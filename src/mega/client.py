from __future__ import annotations

import asyncio
import dataclasses
import functools
import logging
import os
import random
import re
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Self, TypeVar, cast

from Crypto.Cipher import AES
from Crypto.Util import Counter

from mega.api import MegaAPI
from mega.core import MegaCore
from mega.crypto import (
    CHUNK_BLOCK_LEN,
    a32_to_base64,
    a32_to_bytes,
    b64_to_a32,
    b64_url_decode,
    b64_url_encode,
    decrypt_attr,
    encrypt_attr,
    encrypt_key,
    get_chunks,
    pad_bytes,
    random_u32int,
    str_to_a32,
)
from mega.data_structures import (
    AccountData,
    Attributes,
    File,
    FolderSerialized,
    GetNodeResponse,
    Node,
    NodeType,
    UserResponse,
)

from .errors import MegaNzError, RequestError, ValidationError

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine
    from typing import ParamSpec

    from mega.data_structures import (
        AnyDict,
        Array,
        FolderSerialized,
        GetNodesResponse,
        NodeSerialized,
        TupleArray,
    )

    _R = TypeVar("_R")
    _P = ParamSpec("_P")


logger = logging.getLogger(__name__)


def requires_login(func: Callable[_P, Coroutine[None, None, _R]]) -> Callable[_P, Coroutine[None, None, _R]]:
    @functools.wraps(func)
    async def wrapper(*args, **kwargs) -> _R:
        self: Mega = args[0]
        if not self.logged_in:
            raise RuntimeError("You need to log in to use this method")
        return await func(*args, **kwargs)

    return wrapper


@dataclasses.dataclass(slots=True, frozen=True)
class LoginResponse:
    session_id: str
    temp_session_id: str
    private_key: str
    master_key: str


class Mega(MegaCore):
    """Interface with all the public methods of the API"""

    def __init__(self) -> None:
        super().__init__(api=MegaAPI())
        self._cache: dict[str, dict[Any, Any]] = {}

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()

    async def close(self) -> None:
        await self._api.close()

    async def get_filesystem(self) -> dict[PurePosixPath, Node]:
        """Builds a flattened dictionary representing the users' file system"""
        if fs := self._cache.get("fs"):
            return fs.copy()

        nodes = await self.get_nodes()
        fs = self._cache["fs"] = await self.build_file_system(nodes, [self.system_nodes.root.id])
        return fs

    def _is_on_trash_bin(self, node: Node) -> bool:
        return node.parent_id == self.system_nodes.trash_bin.id

    @requires_login
    async def _search(self, query: Path | str, *, exclude_deleted: bool = True) -> list[Node]:
        """
        Return nodes that have "query" as a substring on their path
        """

        query = PurePosixPath(query).as_posix()

        fs = await self.get_filesystem()

        def walk():
            for path, node in fs.items():
                if exclude_deleted and self._is_on_trash_bin(node):
                    continue
                if query in path.as_posix():
                    yield node

        return list(walk())

    async def find_by_handle(self, handle: str, exclude_deleted: bool = True) -> Node | None:
        files = await self.get_nodes()
        file = files.get(handle)
        if not file:
            return
        if exclude_deleted and self._is_on_trash_bin(file):
            return
        return file

    async def get_nodes(self) -> dict[str, Node]:
        if nodes := self._cache.get("nodes"):
            return nodes.copy()

        nodes = self._cache["nodes"] = await self._get_nodes()
        return nodes

    async def get_public_link(self, file: Node) -> str:
        if file.type not in (NodeType.FILE, NodeType.FOLDER):
            raise ValueError
        assert file._crypto
        public_handle: str = await self._get_public_handle(file.id)
        public_key = a32_to_base64(file._crypto.full_key)
        return f"{self._primary_url}/#!{public_handle}!{public_key}"

    async def get_folder_link(self, folder: Node) -> str:
        if folder.type not in (NodeType.FILE, NodeType.FOLDER):
            raise ValueError
        assert folder._crypto and folder._crypto.share_key
        public_handle = await self._get_public_handle(folder.id)
        public_key = a32_to_base64(folder._crypto.share_key)
        return f"{self._primary_url}/#F!{public_handle}!{public_key}"

    async def _get_public_handle(self, file_id: str) -> str:
        try:
            return await self._api.request(
                {
                    "a": "l",
                    "n": file_id,
                }
            )
        except RequestError as e:
            if e.code == -11:
                msg = "Can't get a public link from that file (is this a shared file?) You may need to export it first"
                raise MegaNzError(msg) from e
            raise

    async def get_user(self) -> UserResponse:
        return await self._api.request({"a": "ug"})

    async def get_id_from_public_handle(self, public_handle: str) -> str:
        node_data: GetNodesResponse = await self._api.request(
            {
                "a": "f",
                "f": 1,
                "p": public_handle,
            }
        )

        return node_data["f"][0]["h"]

    async def get_account_data(self) -> AccountData:
        json_resp: dict[str, Any] = await self._api.request(
            {
                "a": "uq",
                "xfer": 1,  # transfer quota
                "strg": 1,  # storage
                "mstrg": 1,  # max storage
                "pro": 1,
                "v": 2,
            }
        )
        return AccountData.parse(json_resp)

    async def delete(self, public_handle: str) -> AnyDict:
        """Delete a file by its public handle."""
        return await self.move(public_handle, NodeType.TRASH)

    async def delete_url(self, url: str) -> AnyDict:
        """Delete a file by its url"""
        public_handle, _ = self._parse_url(url).split("!")
        file_id = await self.get_id_from_public_handle(public_handle)
        return await self.move(file_id, NodeType.TRASH)

    async def destroy(self, file_id: str) -> AnyDict:
        """Destroy a file or folder by its private id (bypass trash bin)"""
        return await self._api.request(
            {
                "a": "d",  # Action: delete
                "n": file_id,  # Node: file Id
                "i": self._api._client_id,  # Request Id
            }
        )

    async def destroy_url(self, url: str) -> AnyDict:
        """Destroy a file by its url (bypass trash bin)"""
        public_handle, *_ = self._parse_url(url).split("!")
        file_id = await self.get_id_from_public_handle(public_handle)
        return await self.destroy(file_id)

    async def empty_trash(self) -> AnyDict | None:
        """Deletes all file in the trash bin. Returns None if the trash was already empty"""
        # get list of files in rubbish out
        files = await self.get_files_in_node(NodeType.TRASH)

        # make a list of json
        if files != {}:
            post_list = []
            for file in files:
                post_list.append(
                    {
                        "a": "d",  # Action: delete
                        "n": file,  # Node: file #Id
                        "i": self._api._client_id,  # Request Id
                    }
                )
            return await self._api.request(post_list)

    async def download(
        self, file: NodeSerialized | None, dest_path: Path | str | None = None, dest_filename: str | None = None
    ) -> Path:
        """Download a file by it's file object."""
        return await self._download_file(
            file_handle=None,
            file_key=None,
            file=file,
            dest_path=dest_path,
            dest_filename=dest_filename,
            is_public=False,
        )

    async def _export_file(self, node: NodeSerialized) -> str:
        _ = await self._api.request(
            {
                "a": "l",  # Action: Export file
                "n": node["h"],  # Node: file Id
                "i": self._api._client_id,  # Request #Id
            }
        )
        return await self.get_public_link(node)

    async def export(self, path: Path | str | None = None, node_id: str | None = None) -> str:
        files = await self.get_nodes()
        if node_id:
            _node_id = node_id
            node: NodeSerialized = files[_node_id]
        elif path:
            found = await self.find(path)
            if not found:
                raise ValueError
            node = found
        else:
            raise ValueError

        if node["t"] == NodeType.FILE:
            folder = node
            return await self._export_file(folder)

        if node["t"] == NodeType.FOLDER:
            try:
                # If already exported
                return await self.get_folder_link(node)
            except (RequestError, KeyError):
                pass

        master_key_cipher = AES.new(a32_to_bytes(self._master_key), AES.MODE_ECB)
        ha = b64_url_encode(master_key_cipher.encrypt(node["h"].encode("utf8") + node["h"].encode("utf8")))

        share_key = random.randbytes(16)
        ok = b64_url_encode(master_key_cipher.encrypt(share_key))

        share_key_cipher = AES.new(share_key, AES.MODE_ECB)
        node_key = node["k_decrypted"]
        encrypted_node_key = b64_url_encode(share_key_cipher.encrypt(a32_to_bytes(node_key)))

        _node_id: str = node["h"]
        await self._api.request(
            {
                "a": "s2",
                "n": _node_id,
                "s": [
                    {
                        "u": "EXP",  # User: export (AKA public)
                        "r": 0,
                    }
                ],
                "i": self._api._client_id,
                "ok": ok,
                "ha": ha,
                "cr": [[_node_id], [_node_id], [0, 0, encrypted_node_key]],
            }
        )
        files = await self.get_nodes()
        folder = cast("FolderSerialized", files[_node_id])
        return await self.get_folder_link(folder)

    async def download_url(self, url: str, dest_path: str | None = None, dest_filename: str | None = None) -> Path:
        """
        Download a file by it's public url
        """
        file_id, file_key = self._parse_url(url).split("!", 1)
        return await self._download_file(
            file_handle=file_id,
            file_key=file_key,
            dest_path=dest_path,
            dest_filename=dest_filename,
            is_public=True,
        )

    async def get_nodes_public_folder(self, url: str) -> dict[str, Node]:
        public_handle, public_key = self._parse_folder_url(url)

        folder: GetNodesResponse = await self._api.request(
            {
                "a": "f",
                "c": 1,
                "ca": 1,
                "r": 1,
            },
            {"n": public_handle},
        )

        return await self._deserialize_nodes(folder["f"], public_key)

    async def download_folder_url(self, url: str, dest_path: str | None = None) -> list[Path]:
        folder_id, _ = self._parse_folder_url(url)
        nodes = await self.get_nodes_public_folder(url)
        download_tasks = []
        root_id = next(iter(nodes))
        fs = await self.build_file_system(nodes, [root_id])

        sem = asyncio.BoundedSemaphore(10)

        async def download_file(file: Node, file_path: Path) -> tuple[Path, bool]:
            download_path = Path(dest_path or ".") / file_path
            try:
                file_data = await self._api.request(
                    {
                        "a": "g",
                        "g": 1,
                        "n": file.id,
                    },
                    {"n": folder_id},
                )

                file_url = file_data["g"]
                file_size = file_data["s"]

                assert file._crypto
                await self._really_download_file(
                    file_url,
                    download_path,
                    file_size,
                    file._crypto.iv,
                    file._crypto.meta_mac,
                    file._crypto.key,
                )
                return download_path, True
            except Exception:
                logger.exception(f"Unable to download {file}")
                return download_path, False

            finally:
                sem.release()

        results = []
        async with asyncio.TaskGroup() as tg:
            self.show_progress = False
            for path, node in fs.items():
                if node.type != NodeType.FILE:
                    continue

                file = node
                await sem.acquire()
                results.append(tg.create_task(download_file(file, Path(path))))

        return await asyncio.gather(*download_tasks)

    async def _download_file(
        self,
        file_handle: str,
        file_key: tuple[int, ...],
        dest_path: Path | str | None = None,
        is_public: bool = False,
    ) -> Path:
        resp = await self._get_file_info(file_handle, is_public=is_public)
        crypto = self._vault.compose_crypto(NodeType.FILE, file_key)
        attrs = decrypt_attr(b64_url_decode(resp["at"]), crypto.key)
        file = File(name=Attributes.parse(attrs).name, size=resp["s"], url=resp.get("g"))

        # Seems to happens sometime... When this occurs, files are
        # inaccessible also in the official web app.
        # Strangely, files can come back later.
        if not file.url:
            raise RequestError("File not accessible anymore")

        output_path = Path(dest_path or Path()) / file.name

        return await self._really_download_file(
            file.url,
            output_path,
            file.size,
            crypto.iv,
            crypto.meta_mac,
            crypto.key,
        )

    async def upload(
        self, file_path: str, dest_node: FolderSerialized | None = None, dest_filename: str | None = None
    ) -> GetNodesResponse:
        # determine storage node
        dest_node_id = dest_node["h"] if dest_node else self.system_nodes.root.id
        # request upload url, call 'u' method
        with open(file_path, "rb") as input_file:
            file_size = os.path.getsize(file_path)
            upload_url: str = (
                await self._api.request(
                    {
                        "a": "u",
                        "s": file_size,
                    }
                )
            )["p"]

            # generate random aes key (128) for file, 192 bits of random data
            ul_key = [random_u32int() for _ in range(6)]
            k_bytes = a32_to_bytes(ul_key[:4])

            # and 64 bits for the IV (which has size 128 bits anyway)
            count = Counter.new(128, initial_value=((ul_key[4] << 32) + ul_key[5]) << 64)
            aes = AES.new(k_bytes, AES.MODE_CTR, counter=count)

            upload_progress = 0
            completion_file_handle = None

            mac_bytes = b"\0" * 16
            mac_encryptor = AES.new(k_bytes, AES.MODE_CBC, mac_bytes)
            iv_bytes = a32_to_bytes([ul_key[4], ul_key[5], ul_key[4], ul_key[5]])
            if file_size > 0:
                for chunk_start, chunk_size in get_chunks(file_size):
                    chunk = input_file.read(chunk_size)
                    actual_size = len(chunk)
                    upload_progress += actual_size
                    encryptor = AES.new(k_bytes, AES.MODE_CBC, iv_bytes)

                    mem_view = memoryview(chunk)
                    for index in range(0, actual_size - CHUNK_BLOCK_LEN, CHUNK_BLOCK_LEN):
                        block = mem_view[index : index + CHUNK_BLOCK_LEN]
                        encryptor.encrypt(block)

                    modchunk = actual_size % CHUNK_BLOCK_LEN
                    if modchunk == 0:
                        # ensure we reserve the last 16 bytes anyway, we have to feed them into mac_encryptor
                        modchunk = CHUNK_BLOCK_LEN

                    # pad last block to 16 bytes
                    last_block = pad_bytes(mem_view[-modchunk:])

                    mac_bytes = mac_encryptor.encrypt(encryptor.encrypt(last_block))

                    # encrypt file and upload
                    chunk = aes.encrypt(chunk)
                    output_file = await self._api.__session.post(upload_url + "/" + str(chunk_start), data=chunk)
                    completion_file_handle = await output_file.text()
                    logger.info("%s of %s uploaded", upload_progress, file_size)
            else:
                # empty file
                output_file = await self._api.__session.post(upload_url + "/0", data="")
                completion_file_handle = await output_file.text()

            logger.info("Chunks uploaded")
            logger.info("Setting attributes to complete upload")
            logger.info("Computing attributes")
            file_mac: TupleArray = str_to_a32(mac_bytes)

            # determine meta mac
            meta_mac = (file_mac[0] ^ file_mac[1], file_mac[2] ^ file_mac[3])

            dest_filename = dest_filename or os.path.basename(file_path)
            attribs = {"n": dest_filename}

            encrypt_attribs = b64_url_encode(encrypt_attr(attribs, ul_key[:4]))
            key: Array = [
                ul_key[0] ^ ul_key[4],
                ul_key[1] ^ ul_key[5],
                ul_key[2] ^ meta_mac[0],
                ul_key[3] ^ meta_mac[1],
                ul_key[4],
                ul_key[5],
                meta_mac[0],
                meta_mac[1],
            ]
            encrypted_key = a32_to_base64(encrypt_key(key, self._master_key))
            logger.info("Sending request to update attributes")
            # update attributes
            data: GetNodesResponse = await self._api.request(
                {
                    "a": "p",
                    "t": dest_node_id,
                    "i": self._api._client_id,
                    "n": [{"h": completion_file_handle, "t": 0, "a": encrypt_attribs, "k": encrypted_key}],
                }
            )
            logger.info("Upload complete")
            return data

    async def _mkdir(self, name: str, parent_node_id: str) -> FolderSerialized:
        # generate random aes key (128) for folder
        ul_key = [random_u32int() for _ in range(6)]

        # encrypt attribs
        attribs = {"n": name}
        encrypt_attribs = b64_url_encode(encrypt_attr(attribs, ul_key[:4]))
        encrypted_key = a32_to_base64(encrypt_key(ul_key[:4], self._master_key))

        # This can return multiple folders if subfolders needed to be created
        folders: dict[str, list[FolderSerialized]] = await self._api.request(
            {
                "a": "p",
                "t": parent_node_id,
                "n": [
                    {
                        "h": "xxxxxxxx",
                        "t": 1,
                        "a": encrypt_attribs,
                        "k": encrypted_key,
                    }
                ],
                "i": self._api._client_id,
            }
        )
        return folders["f"][0]

    async def create_folder(self, path: Path | str) -> FolderSerialized:
        path = Path(path)
        last_parent = await self.find_by_handle(self.system_nodes.inbox.id)
        assert last_parent
        for parent in reversed(path.parents):
            node = await self.find(parent, exclude_deleted=True)
            if node:
                last_parent = node
            else:
                last_parent = await self._mkdir(name=parent.name, parent_node_id=last_parent["h"])

        return await self._mkdir(name=path.name, parent_node_id=last_parent["h"])

    async def rename(self, node: NodeSerialized | FolderSerialized, new_name: str) -> int:
        # create new attribs
        attribs = {"n": new_name}
        # encrypt attribs
        encrypt_attribs = b64_url_encode(encrypt_attr(attribs, node["k_decrypted"]))
        encrypted_key = a32_to_base64(encrypt_key(node["full_key"], self._master_key))
        # update attributes
        return await self._api.request(
            {
                "a": "a",
                "attr": encrypt_attribs,
                "key": encrypted_key,
                "n": node["h"],
                "i": self._api._client_id,
            }
        )

    async def move(self, file_id: str, target: NodeType | int) -> dict[str, Any]:
        target = NodeType(target)

        return await self._api.request(
            {
                "a": "m",
                "n": file_id,
                "t": target,
                "i": self._api._client_id,
            }
        )

    async def add_contact(self, email: str) -> AnyDict:
        """
        Add another user to your mega contact list
        """
        return await self._edit_contact(email, True)

    async def remove_contact(self, email: str) -> AnyDict:
        """
        Remove a user to your mega contact list
        """
        return await self._edit_contact(email, False)

    async def _edit_contact(self, email: str, *, add: bool) -> AnyDict:
        """
        Editing contacts
        """

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            raise ValidationError("add_contact requires a valid email address")

        return await self._api.request(
            {
                "a": "ur",
                "u": email,
                "l": "1" if add else "0",
                "i": self._api._client_id,
            }
        )

    async def get_public_url_info(self, url: str) -> tuple[str, int]:
        """
        Get size and name from a public url, dict returned
        """
        public_handle, public_key = self._parse_url(url).split("!")
        return await self.get_public_file_info(public_handle, public_key)

    async def import_public_url(
        self, url: str, dest_node: FolderSerialized | str | None = None, dest_name: str | None = None
    ) -> GetNodesResponse:
        """
        Import the public url into user account
        """
        public_handle, public_key = self._parse_url(url).split("!")
        return await self.import_public_file(public_handle, public_key, dest_node=dest_node, dest_name=dest_name)

    async def _get_file_info(self, handle: str, is_public: bool = False) -> GetNodeResponse:
        return await self._api.request(
            {
                "a": "g",
                "g": 1,
                "p" if is_public else "n": handle,
            }
        )

    async def get_public_file_info(self, public_handle: str, public_key: str) -> File:
        """
        Get size and name of a public file
        """
        resp = await self._get_file_info(public_handle, is_public=True)
        full_key = b64_to_a32(public_key)
        key = self._vault.compose_crypto(NodeType.FILE, full_key).key
        attrs = decrypt_attr(b64_url_decode(resp["at"]), key)
        return File(name=Attributes.parse(attrs).name, size=resp["s"], url=resp.get("g"))

    @requires_login
    async def import_public_file(
        self,
        public_handle: str,
        public_key: str,
        dest_node_id: str | None = None,
        dest_name: str | None = None,
    ) -> GetNodesResponse:
        """
        Import the public file into user account
        """

        dest_node_id = dest_node_id or self._system_nodes.root

        # Providing dest_name spares an API call to retrieve it.
        if dest_name is None:
            pl_info = await self.get_public_file_info(public_handle, public_key)
            dest_name = pl_info.name

        full_key = b64_to_a32(public_key)
        key: TupleArray = (
            full_key[0] ^ full_key[4],
            full_key[1] ^ full_key[5],
            full_key[2] ^ full_key[6],
            full_key[3] ^ full_key[7],
        )

        encrypted_key = a32_to_base64(encrypt_key(full_key, self._master_key))
        attributes = b64_url_encode(encrypt_attr({"n": dest_name}, key))
        return await self._api.request(
            {
                "a": "p",
                "t": dest_node_id,
                "n": [
                    {
                        "ph": public_handle,
                        "t": 0,
                        "a": attributes,
                        "k": encrypted_key,
                    },
                ],
            }
        )
