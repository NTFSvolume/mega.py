from __future__ import annotations

import asyncio
import dataclasses
import functools
import logging
import os
import random
import re
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Literal, TypeVar, cast

from Crypto.Cipher import AES
from Crypto.Util import Counter

from mega.core import MegaNzCoreClient
from mega.crypto import (
    CHUNK_BLOCK_LEN,
    a32_to_base64,
    a32_to_bytes,
    base64_to_a32,
    base64_url_decode,
    base64_url_encode,
    decrypt_attr,
    decrypt_key,
    encrypt_attr,
    encrypt_key,
    get_chunks,
    pad_bytes,
    random_u32int,
    str_to_a32,
)
from mega.data_structures import NodeType, StorageUsage, TupleArray

from .errors import MegaNzError, RequestError, ValidationError

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine
    from typing import ParamSpec

    from mega.data_structures import (
        AnyArray,
        AnyDict,
        Array,
        Attributes,
        File,
        Folder,
        FolderResponse,
        Node,
        NodesMap,
        TupleArray,
    )

    _R = TypeVar("_R")
    _P = ParamSpec("_P")


logger = logging.getLogger(__name__)


def requires_login(func: Callable[_P, Coroutine[None, None, _R]]) -> Callable[_P, Coroutine[None, None, _R]]:
    @functools.wraps(func)
    async def wrapper(*args, **kwargs) -> _R:
        self: Mega = args[0]
        if not self._logged_in:
            raise RuntimeError("You need to log in to use this method")
        return await func(*args, **kwargs)

    return wrapper


@dataclasses.dataclass(slots=True, frozen=True)
class LoginResponse:
    session_id: str
    temp_session_id: str
    private_key: str
    master_key: str


class Mega(MegaNzCoreClient):
    """Interface with all the public methods of the API"""

    async def find(self, path: Path | str, exclude_deleted: bool = False) -> File | Folder | None:
        """
        Returns file or folder from given path( if exists)
        """
        results = await self._search(path, exclude_deleted, strict=True)
        return results[0] if results else None

    async def search(self, filename_or_path: Path | str, exclude_deleted: bool = False) -> list[File | Folder]:
        """
        Return file object(s) from given filename or path
        """
        return await self._search(filename_or_path, exclude_deleted)

    @requires_login
    async def _search(
        self, filename_or_path: Path | str, exclude_deleted: bool = False, strict=False
    ) -> list[File | Folder]:
        """
        Return file object(s) from given filename or path
        """

        filename_or_path = Path(filename_or_path).as_posix()

        fs = await self.build_file_system()

        found = []
        for path, item in fs.items():
            if filename_or_path in (path_str := path.as_posix()):
                if strict and not path_str.startswith(filename_or_path):
                    continue
                if exclude_deleted and item["p"] == self.trashbin_id:
                    continue
                found.append(item)
        return found

    async def find_by_handle(self, handle: str, exclude_deleted: bool = False) -> File | Folder | None:
        """Return file object(s) from given filename or path"""
        files = await self.get_files()
        file = found if (found := files.get(handle)) else None
        if not file or (file["p"] == self.trashbin_id and exclude_deleted):
            return None
        return cast("File | Folder", file)

    @requires_login
    async def get_files(self) -> NodesMap:
        return await self._get_files()

    @requires_login
    async def get_upload_link(self, folder: FolderResponse) -> str:
        """
        Get a files public link inc. decrypted key
        Requires upload() response as input
        """
        if "f" not in folder:
            raise ValueError("""Upload() response required as input, use get_link() for regular file input""")

        file = cast("File", folder["f"][0])
        public_handle: str = await self._api.request(
            {
                "a": "l",
                "n": file["h"],
            }
        )
        _, file_key = file["k"].split(":", 1)
        decrypted_key = a32_to_base64(decrypt_key(base64_to_a32(file_key), self._master_key))
        return f"{self._primary_url}/#!{public_handle}!{decrypted_key}"

    async def get_link(self, file: File) -> str:
        """
        Get a file public link from given file object
        """

        if not ("h" in file and "full_key" in file):
            raise ValidationError("File id and key must be present")

        public_handle: str = await self._get_public_handle(file)
        decrypted_key = a32_to_base64(file["full_key"])
        return f"{self._primary_url}/#!{public_handle}!{decrypted_key}"

    async def get_folder_link(self, folder: Folder) -> str:
        if not ("h" in folder and "sk_decrypted" in folder):
            raise ValidationError("Folder id and key must be present")

        public_handle: str = await self._get_public_handle(folder)
        decrypted_key = a32_to_base64(folder["sk_decrypted"])
        return f"{self._primary_url}/#F!{public_handle}!{decrypted_key}"

    @requires_login
    async def _get_public_handle(self, file: File | Folder) -> str:
        try:
            public_handle: str = await self._api.request(
                {
                    "a": "l",
                    "n": file["h"],
                }
            )
        except RequestError as e:
            if e.code == -11:
                raise MegaNzError("Can't get a public link from that file (is this a shared file?)") from e
            raise
        else:
            return public_handle

    @requires_login
    async def get_user(self) -> AnyDict:
        user_data: AnyDict = await self._api.request(
            {
                "a": "ug",
            }
        )
        return user_data

    async def get_node_by_type(self, node_type: NodeType | int) -> Node | None:
        """
        Get a node by it's numeric type id, e.g:
        0: file
        1: dir
        2: special: root cloud drive
        3: special: inbox
        4: special trash bin
        """
        nodes = await self.get_files()
        for _, node in nodes.items():
            if node["t"] == node_type:
                return node

    @requires_login
    async def get_files_in_node(
        self, target: Literal[NodeType.INBOX, NodeType.TRASH, NodeType.ROOT_FOLDER]
    ) -> NodesMap:
        """
        Get all files in a given target, e.g. 4=trash
        """
        folder: FolderResponse = await self._api.request(
            {
                "a": "f",
                "c": 1,
            }
        )
        files_dict: NodesMap = {}
        target_id = self.special_nodes_mapping.get(target)
        for index, file in enumerate(folder["f"], 1):
            processed_file = cast("File | Folder", self._process_node(file))
            if processed_file["a"] and processed_file["p"] == target_id:
                files_dict[file["h"]] = processed_file
            if index % 100 == 0:
                await asyncio.sleep(0)
        return files_dict

    async def get_id_from_public_handle(self, public_handle: str) -> str:
        node_data: FolderResponse = await self._api.request(
            {
                "a": "f",
                "f": 1,
                "p": public_handle,
            }
        )

        node_id = self.get_id_from_resp_obj(node_data)
        assert node_id
        return node_id

    @staticmethod
    def get_id_from_resp_obj(resp: FolderResponse) -> str | None:
        """
        Get node id from a file object
        """

        for i in resp["f"]:
            if i["h"] != "":
                return i["h"]

    async def get_quota(self) -> int:
        """Get current remaining disk quota."""
        json_resp: AnyDict = await self._api.request(
            {
                "a": "uq",  # Action: user quota
                "xfer": 1,
                "strg": 1,
                "v": 1,
            }
        )
        return json_resp["mstrg"]

    async def get_storage_space(self) -> StorageUsage:
        """
        Get the current storage space.
        Return a dict containing at least:
          'used' : the used space on the account
          'total' : the maximum space allowed with current plan
        All storage space are in bytes unless asked differently.
        """
        json_resp: AnyDict = await self._api.request(
            {
                "a": "uq",
                "xfer": 1,
                "strg": 1,
            }
        )
        return StorageUsage(json_resp["cstrg"], json_resp["mstrg"])

    async def get_balance(self) -> int | None:
        """Get account monetary balance, Pro accounts only."""
        user_data: AnyDict = await self._api.request(
            {
                "a": "uq",
                "pro": 1,
            }
        )
        return user_data.get("balance")

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
        self, file: File | None, dest_path: Path | str | None = None, dest_filename: str | None = None
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

    async def _export_file(self, node: File) -> str:
        await self._api.request(
            [
                {
                    "a": "l",  # Action: Export file
                    "n": node["h"],  # Node: file Id
                    "i": self._api._client_id,  # Request #Id
                }
            ]
        )
        return await self.get_link(node)

    async def export(self, path: Path | str | None = None, node_id: str | None = None) -> str:
        files = await self.get_files()
        if node_id:
            _node_id = node_id
            node: Node = files[_node_id]
        elif path:
            found = await self.find(path)
            if not found:
                raise ValueError
            node = found
        else:
            raise ValueError

        if node["t"] == NodeType.FILE:
            folder = cast("File", node)
            return await self._export_file(folder)

        node = cast("File | Folder", node)
        if node["t"] == NodeType.FOLDER:
            try:
                # If already exported
                return await self.get_folder_link(node)
            except (RequestError, KeyError):
                pass

        master_key_cipher = AES.new(a32_to_bytes(self._master_key), AES.MODE_ECB)
        ha = base64_url_encode(master_key_cipher.encrypt(node["h"].encode("utf8") + node["h"].encode("utf8")))

        share_key = random.randbytes(16)
        ok = base64_url_encode(master_key_cipher.encrypt(share_key))

        share_key_cipher = AES.new(share_key, AES.MODE_ECB)
        node_key = node["k_decrypted"]
        encrypted_node_key = base64_url_encode(share_key_cipher.encrypt(a32_to_bytes(node_key)))

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
        files = await self.get_files()
        folder = cast("Folder", files[_node_id])
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

    async def get_nodes_public_folder(self, url: str) -> dict[str, File | Folder]:
        folder_id, b64_share_key = self._parse_folder_url(url)

        folder: FolderResponse = await self._api.request(
            {"a": "f", "c": 1, "ca": 1, "r": 1},
            {"n": folder_id},
        )

        return cast("dict[str, File | Folder]", await self._process_nodes(folder["f"], b64_share_key))

    async def download_folder_url(self, url: str, dest_path: str | None = None) -> list[Path]:
        folder_id, _ = self._parse_folder_url(url)
        nodes = await self.get_nodes_public_folder(url)
        download_tasks = []
        root_id = next(iter(nodes))
        fs = await self._build_file_system(nodes, [root_id])  # type: ignore
        for path, node in fs.items():
            if node["t"] != NodeType.FILE:
                continue

            async def download_file(file: File, file_path: Path) -> None:
                file_data = await self._api.request(
                    {
                        "a": "g",
                        "g": 1,
                        "n": file["h"],
                    },
                    {"n": folder_id},
                )

                file_url = file_data["g"]
                file_size = file_data["s"]

                if dest_path:
                    download_path = Path(dest_path) / file_path
                else:
                    download_path = file_path

                await self._really_download_file(
                    file_url,
                    download_path,
                    file_size,
                    file["iv"],
                    file["meta_mac"],
                    file["k_decrypted"],
                )

            file = cast("File", node)
            download_tasks.append(download_file(file, Path(path)))

        with self._new_progress():
            results = await asyncio.gather(*download_tasks)
        return results

    async def _download_file(
        self,
        file_handle: str | None = None,
        file_key: TupleArray | str | None = None,
        dest_path: Path | str | None = None,
        dest_filename: str | None = None,
        is_public: bool = False,
        file: File | None = None,
    ) -> Path:
        if file is None:
            assert file_key
            if isinstance(file_key, str):
                _file_key = base64_to_a32(file_key)
            else:
                _file_key = file_key

            file_data: File = await self._api.request(
                {
                    "a": "g",
                    "g": 1,
                    "p" if is_public else "n": file_handle,
                },
            )

            k: AnyArray = (
                _file_key[0] ^ _file_key[4],
                _file_key[1] ^ _file_key[5],
                _file_key[2] ^ _file_key[6],
                _file_key[3] ^ _file_key[7],
            )
            iv: AnyArray = (*_file_key[4:6], 0, 0)
            meta_mac: TupleArray = _file_key[6:8]
        else:
            file_handle = file["h"]
            file_data = await self._api.request(
                {
                    "a": "g",
                    "g": 1,
                    "p" if is_public else "n": file_handle,
                }
            )
            k = file["k_decrypted"]
            iv = file["iv"]
            meta_mac = file["meta_mac"]

        # Seems to happens sometime... When this occurs, files are
        # inaccessible also in the official web app.
        # Strangely, files can come back later.
        if "g" not in file_data:
            raise RequestError("File not accessible anymore")

        file_url = file_data["g"]
        file_size = file_data["s"]
        attribs_bytes = base64_url_decode(file_data["at"])
        attribs = decrypt_attr(attribs_bytes, k)
        attribs = cast("Attributes", attribs)

        if dest_filename is not None:
            file_name = dest_filename
        else:
            file_name: str = attribs["n"]

        if dest_path is None:
            dest_path = Path()
        elif isinstance(dest_path, str):
            dest_path = Path(dest_path)

        output_path = dest_path / file_name

        with self._new_progress():
            return await self._really_download_file(file_url, output_path, file_size, iv, meta_mac, k)

    async def upload(
        self, filename: str, dest_node: Folder | None = None, dest_filename: str | None = None
    ) -> FolderResponse:
        # determine storage node
        dest_node_id = dest_node["h"] if dest_node else self.root_id
        # request upload url, call 'u' method
        with open(filename, "rb") as input_file:
            file_size = os.path.getsize(filename)
            ul_url: str = (
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
                    output_file = await self._api.__session.post(ul_url + "/" + str(chunk_start), data=chunk)
                    completion_file_handle = await output_file.text()
                    logger.info("%s of %s uploaded", upload_progress, file_size)
            else:
                # empty file
                output_file = await self._api.__session.post(ul_url + "/0", data="")
                completion_file_handle = await output_file.text()

            logger.info("Chunks uploaded")
            logger.info("Setting attributes to complete upload")
            logger.info("Computing attributes")
            file_mac: TupleArray = str_to_a32(mac_bytes)

            # determine meta mac
            meta_mac = (file_mac[0] ^ file_mac[1], file_mac[2] ^ file_mac[3])

            dest_filename = dest_filename or os.path.basename(filename)
            attribs = {"n": dest_filename}

            encrypt_attribs = base64_url_encode(encrypt_attr(attribs, ul_key[:4]))
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
            data: FolderResponse = await self._api.request(
                {
                    "a": "p",
                    "t": dest_node_id,
                    "i": self._api._client_id,
                    "n": [{"h": completion_file_handle, "t": 0, "a": encrypt_attribs, "k": encrypted_key}],
                }
            )
            logger.info("Upload complete")
            return data

    async def _mkdir(self, name: str, parent_node_id: str) -> Folder:
        # generate random aes key (128) for folder
        ul_key = [random_u32int() for _ in range(6)]

        # encrypt attribs
        attribs = {"n": name}
        encrypt_attribs = base64_url_encode(encrypt_attr(attribs, ul_key[:4]))
        encrypted_key = a32_to_base64(encrypt_key(ul_key[:4], self._master_key))

        # This can return multiple folders if subfolders needed to be created
        folders: dict[str, list[Folder]] = await self._api.request(
            {
                "a": "p",
                "t": parent_node_id,
                "n": [{"h": "xxxxxxxx", "t": 1, "a": encrypt_attribs, "k": encrypted_key}],
                "i": self._api._client_id,
            }
        )
        return folders["f"][0]

    async def create_folder(self, path: Path | str) -> Folder:
        path = Path(path)
        last_parent = await self.find_by_handle(self.root_id)
        assert last_parent
        for parent in reversed(path.parents):
            node = await self.find(parent, exclude_deleted=True)
            if node:
                last_parent = node
            else:
                last_parent = await self._mkdir(name=parent.name, parent_node_id=last_parent["h"])

        return await self._mkdir(name=path.name, parent_node_id=last_parent["h"])

    async def rename(self, node: File | Folder, new_name: str) -> int:
        # create new attribs
        attribs = {"n": new_name}
        # encrypt attribs
        encrypt_attribs = base64_url_encode(encrypt_attr(attribs, node["k_decrypted"]))
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

    async def move(self, file_id: str, target: FolderResponse | NodeType | str) -> AnyDict:
        """
        Move a file to another parent node
        params:
        a : command
        n : node we're moving
        t : id of target parent node, moving to
        i : request id

        targets
        2 : root
        3 : inbox
        4 : trash

        or...
        target's id
        or...
        target's structure returned by find()
        """

        if isinstance(target, int):
            result = await self.get_node_by_type(target)
            if not result:
                raise MegaNzError(f"Node type {target} does not exists")
            target_node_id = result["h"]
        else:
            target_node_id = target
        return await self._api.request(
            {
                "a": "m",
                "n": file_id,
                "t": target_node_id,
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

    async def _edit_contact(self, email: str, add: bool) -> AnyDict:
        """
        Editing contacts
        """
        if add is True:
            add_or_remove = "1"  # add command
        elif add is False:
            add_or_remove = "0"  # remove command
        else:
            raise ValidationError("add parameter must be of type bool")

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            raise ValidationError("add_contact requires a valid email address")
        else:
            return await self._api.request(
                {
                    "a": "ur",
                    "u": email,
                    "l": add_or_remove,
                    "i": self._api._client_id,
                }
            )

    async def get_public_url_info(self, url: str) -> AnyDict | None:
        """
        Get size and name from a public url, dict returned
        """
        file_handle, file_key = self._parse_url(url).split("!")
        return await self.get_public_file_info(file_handle, file_key)

    async def import_public_url(
        self, url: str, dest_node: Folder | str | None = None, dest_name: str | None = None
    ) -> FolderResponse:
        """
        Import the public url into user account
        """
        file_handle, file_key = self._parse_url(url).split("!")
        return await self.import_public_file(file_handle, file_key, dest_node=dest_node, dest_name=dest_name)

    async def get_public_file_info(self, file_handle: str, file_key: str) -> AnyDict | None:
        """
        Get size and name of a public file
        """
        data: FolderResponse = await self._api.request(
            {
                "a": "g",
                "p": file_handle,
                "ssm": 1,
            }
        )
        if "at" not in data or "s" not in data:
            raise ValueError("Unexpected result", data)

        key = base64_to_a32(file_key)
        k: TupleArray = (key[0] ^ key[4], key[1] ^ key[5], key[2] ^ key[6], key[3] ^ key[7])

        size = data["s"]
        unencrypted_attrs = decrypt_attr(base64_url_decode(data["at"]), k)
        if not unencrypted_attrs:
            return None
        result = {"size": size, "name": unencrypted_attrs["n"]}
        return result

    async def import_public_file(
        self,
        file_handle: str,
        file_key: str,
        dest_node: Folder | str | None = None,
        dest_name: str | None = None,
    ) -> FolderResponse:
        """
        Import the public file into user account
        """
        # Providing dest_node spare an API call to retrieve it.
        if not self._logged_in:
            raise MegaNzError("You have to log in to import files")

        if dest_node is None:
            # Get '/Cloud Drive' folder no dest node specified
            dest_node_id: str = self.root_id
        elif isinstance(dest_node, str):
            dest_node_id = dest_node
        else:
            dest_node_id = dest_node["h"]

        # Providing dest_name spares an API call to retrieve it.
        if dest_name is None:
            pl_info = await self.get_public_file_info(file_handle, file_key)
            assert pl_info
            dest_name = pl_info["name"]

        key = base64_to_a32(file_key)
        k: TupleArray = (key[0] ^ key[4], key[1] ^ key[5], key[2] ^ key[6], key[3] ^ key[7])

        encrypted_key: str = a32_to_base64(encrypt_key(key, self._master_key))
        encrypted_name: str = base64_url_encode(encrypt_attr({"n": dest_name}, k))
        return await self._api.request(
            {
                "a": "p",
                "t": dest_node_id,
                "n": [
                    {
                        "ph": file_handle,
                        "t": 0,
                        "a": encrypted_name,
                        "k": encrypted_key,
                    },
                ],
            }
        )

    async def build_file_system(self) -> dict[PurePosixPath, Node]:
        nodes_map = await self._get_nodes()
        return await self._build_file_system(nodes_map, list(self.special_nodes_mapping.values()))
