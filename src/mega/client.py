from __future__ import annotations

import asyncio
import dataclasses
import logging
import os
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Self

from Crypto.Cipher import AES
from Crypto.Util import Counter

from mega.api import MegaAPI
from mega.core import MegaCore
from mega.crypto import (
    CHUNK_BLOCK_LEN,
    a32_to_base64,
    a32_to_bytes,
    b64_decrypt_attr,
    b64_to_a32,
    b64_url_encode,
    encrypt_attr,
    encrypt_key,
    get_chunks,
    pad_bytes,
    random_u32int,
    str_to_a32,
)
from mega.data_structures import (
    AccountStats,
    Attributes,
    Crypto,
    FileInfo,
    FileInfoSerialized,
    Node,
    NodeType,
    UserResponse,
)
from mega.filesystem import FileSystem, UserFileSystem

from .errors import MegaNzError, RequestError, ValidationError

if TYPE_CHECKING:
    import aiohttp

    from mega.data_structures import GetNodesResponse


logger = logging.getLogger(__name__)


class Mega(MegaCore):
    """Interface with all the public methods of the API"""

    def __init__(self, session: aiohttp.ClientSession | None = None) -> None:
        super().__init__(api=MegaAPI(session))

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()

    async def close(self) -> None:
        await self._api.close()

    async def search(self, query: Path | str, *, exclude_deleted: bool = True) -> dict[Node, PurePosixPath]:
        """
        Return nodes that have "query" as a substring on their path
        """
        fs = await self.get_filesystem()
        return dict(fs.search(query, exclude_deleted=exclude_deleted))

    async def find(self, query: Path | str) -> Node | None:
        res = await self.search(query)
        query = PurePosixPath(query).as_posix()
        for node, path in res.items():
            if path.as_posix().startswith(query):
                return node

    async def get_filesystem(self, *, force: bool = False) -> UserFileSystem:
        if self._filesystem is None or force:
            async with self._lock:
                if self._filesystem is None or force:
                    self._filesystem = await self._prepare_filesystem()

        return self._filesystem

    async def get_public_link(self, file: Node) -> str:
        if file.type not in (NodeType.FILE, NodeType.FOLDER):
            raise ValueError

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
        resp: GetNodesResponse = await self._api.request(
            {
                "a": "f",
                "f": 1,
                "p": public_handle,
            }
        )

        return resp["f"][0]["h"]

    async def get_account_stats(self) -> AccountStats:
        resp: dict[str, Any] = await self._api.request(
            {
                "a": "uq",
                "xfer": 1,  # transfer quota
                "strg": 1,  # storage
                "mstrg": 1,  # max storage
                "pro": 1,
                "v": 2,
            }
        )
        return AccountStats.parse(resp)

    async def delete(self, node_id: str) -> dict[str, Any]:
        """Delete a file or folder by its private id (move it to the trash bin)"""
        return await self.move(node_id, NodeType.TRASH)

    async def destroy(self, node_id: str) -> bool:
        """Destroy a file or folder by its private id (bypass trash bin)"""
        resp = await self._destroy(node_id)
        return resp == 0

    async def empty_trash(self) -> int | None:
        """Deletes all file in the trash bin. Returns None if the trash was already empty"""

        fs = await self.get_filesystem()
        trashed_files = [f.id for f in fs.deleted]
        if not trashed_files:
            return

        return await self._destroy(*trashed_files)

    async def export(self, node: Node) -> str:
        if node.type is NodeType.FILE:
            await self._export_file(node)
            return await self.get_public_link(node)

        elif node.type is not NodeType.FOLDER:
            msg = f"Can only export files or folders, not {node.type}"
            raise ValidationError(msg)

        try:
            # If already exported
            return await self.get_folder_link(node)
        except (RequestError, KeyError):
            await self._export_folder(node)
            fs = await self.get_filesystem(force=True)
            return await self.get_folder_link(fs[node.id])

    async def get_nodes_in_public_folder(self, public_handle: str, public_key: str) -> FileSystem:
        folder: GetNodesResponse = await self._api.request(
            {
                "a": "f",
                "c": 1,
                "ca": 1,
                "r": 1,
            },
            {"n": public_handle},
        )

        nodes = await self._deserialize_nodes(folder["f"], public_key)
        return await FileSystem.built(nodes)

    async def _request_file_info(
        self,
        handle: str,
        parent_id: str | None = None,
        is_public: bool = False,
    ) -> FileInfo:
        resp: FileInfoSerialized = await self._api.request(
            {
                "a": "g",
                "g": 1,
                "p" if is_public else "n": handle,
            },
            params={"n": parent_id} if parent_id else None,
        )

        return FileInfo.parse(resp)

    async def download(self, node: Node, output_dir: Path | str | None = None) -> Path:
        """Download a file by it's file object."""
        file_info = await self._request_file_info(node.id)
        return await self._download_file(
            file_info,
            node._crypto,
            output_folder=output_dir,
        )

    async def download_public_file(
        self, public_handle: str, public_key: str, output_dir: Path | str | None = None
    ) -> Path:
        """
        Download a public file
        """
        full_key = b64_to_a32(public_key)
        crypto = self._vault.compose_crypto(NodeType.FILE, full_key)
        file_info = await self._request_file_info(public_handle, is_public=True)
        return await self._download_file(
            file_info,
            crypto,
            output_dir,
        )

    async def download_public_folder(
        self, public_handle: str, public_key: str, output_dir: Path | str | None = None
    ) -> list[Path | BaseException]:
        fs = await self.get_nodes_in_public_folder(public_handle, public_key)
        sem = asyncio.BoundedSemaphore(10)
        base_path = Path(output_dir or ".")

        async def download_file(file: Node, file_path: PurePosixPath) -> Path | BaseException:
            try:
                file_info = await self._request_file_info(file.id, public_handle)
                return await self._download_file(
                    file_info,
                    file._crypto,
                    base_path / file_path.parent,
                    file_path.name,
                )
            except BaseException as e:
                logger.exception(f"Unable to download {file}")
                return e
            finally:
                sem.release()

        results: list[asyncio.Task[Path | BaseException]] = []
        async with asyncio.TaskGroup() as tg:
            for file in fs.files:
                path = fs.resolve(file.id)
                await sem.acquire()
                results.append(tg.create_task(download_file(file, path)))

        return await asyncio.gather(*results)

    async def _download_file(
        self,
        dl: FileInfo,
        crypto: Crypto,
        output_folder: Path | str | None = None,
        output_name: str | None = None,
    ) -> Path:
        # Seems to happens sometime... When this occurs, files are
        # inaccessible also in the official web app.
        # Strangely, files can come back later.
        if not dl.url:
            raise RequestError("File not accessible anymore")

        name = output_name or Attributes.parse(b64_decrypt_attr(dl._at, crypto.key)).name
        output_path = Path(output_folder or Path()) / name

        return await self._really_download_file(
            dl.url,
            output_path,
            dl.size,
            crypto.iv,
            crypto.meta_mac,
            crypto.key,
        )

    async def upload(self, file_path: Path | str, dest_node: Node | None = None) -> GetNodesResponse:
        dest_node_id = dest_node or self.filesystem.root.id

        file_path = Path(file_path)
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
            new_key = [random_u32int() for _ in range(6)]
            k_bytes = a32_to_bytes(new_key[:4])

            # and 64 bits for the IV (which has size 128 bits anyway)
            count = Counter.new(128, initial_value=((new_key[4] << 32) + new_key[5]) << 64)
            aes = AES.new(k_bytes, AES.MODE_CTR, counter=count)

            upload_progress = 0
            completion_file_handle = None

            mac_bytes = b"\0" * CHUNK_BLOCK_LEN
            mac_encryptor = AES.new(k_bytes, AES.MODE_CBC, mac_bytes)
            iv_bytes = a32_to_bytes([new_key[4], new_key[5], new_key[4], new_key[5]])
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

                    modchunk = (actual_size % CHUNK_BLOCK_LEN) or CHUNK_BLOCK_LEN
                    # pad last block to 16 bytes
                    last_block = pad_bytes(mem_view[-modchunk:])
                    mac_bytes = mac_encryptor.encrypt(encryptor.encrypt(last_block))

                    # encrypt file and upload
                    chunk = aes.encrypt(chunk)
                    output_file = await self._api._lazy_session().post(upload_url + "/" + str(chunk_start), data=chunk)
                    completion_file_handle = await output_file.text()
                    logger.info("%s of %s uploaded", upload_progress, file_size)
            else:
                # empty file
                output_file = await self._api._lazy_session().post(upload_url + "/0", data="")
                completion_file_handle = await output_file.text()

            logger.info("Chunks uploaded")
            logger.info("Setting attributes to complete upload")
            logger.info("Computing attributes")
            file_mac: tuple[int, ...] = str_to_a32(mac_bytes)

            # determine meta mac
            meta_mac = (file_mac[0] ^ file_mac[1], file_mac[2] ^ file_mac[3])
            attribs = {"n": file_path.name}

            encrypt_attribs = b64_url_encode(encrypt_attr(attribs, new_key[:4]))
            key: tuple[int, ...] = (
                new_key[0] ^ new_key[4],
                new_key[1] ^ new_key[5],
                new_key[2] ^ meta_mac[0],
                new_key[3] ^ meta_mac[1],
                new_key[4],
                new_key[5],
                meta_mac[0],
                meta_mac[1],
            )
            encrypted_key = a32_to_base64(encrypt_key(key, self._vault.master_key))
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

    async def create_folder(self, path: Path | str) -> Node:
        path = PurePosixPath(path).as_posix()
        fs = await self.get_filesystem()
        return await self._mkdir(name=path, parent_node_id=fs.root.id)

    async def rename(self, node: Node, new_name: str) -> bool:
        if not new_name:
            raise ValidationError

        new_attrs = dataclasses.replace(node.attributes, n=new_name)

        attribs = b64_url_encode(encrypt_attr(new_attrs.serialize(), node._crypto.key))
        encrypted_key = a32_to_base64(encrypt_key(node._crypto.key, self._vault.master_key))

        resp = await self._api.request(
            {
                "a": "a",
                "attr": attribs,
                "key": encrypted_key,
                "n": node.id,
                "i": self._api._client_id,
            }
        )
        success = resp == 0
        if success:
            self._filesystem = None
        return success

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

    async def add_contact(self, email: str) -> dict[str, Any]:
        """
        Add another user to your mega contact list
        """
        return await self._edit_contact(email, add=True)

    async def remove_contact(self, email: str) -> dict[str, Any]:
        """
        Remove a user to your mega contact list
        """
        return await self._edit_contact(email, add=False)

    async def get_public_file_info(self, public_handle: str, public_key: str) -> FileInfo:
        """
        Get size and name of a public file
        """
        full_key = b64_to_a32(public_key)
        key = self._vault.compose_crypto(NodeType.FILE, full_key).key
        file_info = await self._request_file_info(public_handle, is_public=True)
        name = Attributes.parse(b64_decrypt_attr(file_info._at, key)).name
        return dataclasses.replace(file_info, name=name)

    async def import_public_file(self, public_handle: str, public_key: str, dest_node_id: str | None = None) -> Node:
        """
        Import the public file into user account
        """

        dest_node_id = dest_node_id or self.filesystem.root.id
        pl_info = await self.get_public_file_info(public_handle, public_key)
        dest_name = pl_info.name

        full_key = b64_to_a32(public_key)
        key = self._vault.compose_crypto(NodeType.FILE, full_key).key
        encrypted_key = a32_to_base64(encrypt_key(full_key, self._vault.master_key))
        attributes = b64_url_encode(encrypt_attr({"n": dest_name}, key))

        resp = await self._api.request(
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
        if resp:
            self._filesystem = None
        return self._deserialize_node(resp["f"][0])
