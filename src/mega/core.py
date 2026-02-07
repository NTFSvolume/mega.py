from __future__ import annotations

import asyncio
import logging
import random
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

from Crypto.Cipher import AES

from mega import auth, download, upload, utils
from mega.api import MegaAPI
from mega.crypto import (
    a32_to_base64,
    a32_to_bytes,
    b64_url_decode,
    b64_url_encode,
    decrypt_attr,
    encrypt_attr,
    encrypt_key,
)
from mega.data_structures import Attributes, Crypto, FileInfo, FileInfoSerialized, Node, NodeID
from mega.filesystem import UserFileSystem
from mega.progress import ProgressManager
from mega.vault import MegaVault

from .errors import MegaNzError, RequestError, ValidationError

if TYPE_CHECKING:
    from os import PathLike

    import aiohttp

    from mega.data_structures import GetNodesResponse


logger = logging.getLogger(__name__)


class MegaCore:
    def __init__(self, session: aiohttp.ClientSession | None = None) -> None:
        self._api = MegaAPI(session)
        self._primary_url = "https://mega.nz"
        self._vault = MegaVault(())
        self._filesystem: UserFileSystem | None = None
        self._lock = asyncio.Lock()
        self._progress = ProgressManager()

    async def get_filesystem(self, *, force: bool = False) -> UserFileSystem:
        if self._filesystem is None or force:
            async with self._lock:
                if self._filesystem is None or force:
                    self._filesystem = await self._prepare_filesystem()

        return self._filesystem

    def __repr__(self) -> str:
        return f"<{type(self).__name__}>(fs={self._filesystem!r}, vault={self._vault!r})"

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()

    async def close(self) -> None:
        await self._api.close()

    @property
    def logged_in(self) -> bool:
        return bool(self._vault.master_key)

    async def login(
        self,
        email: str | None = None,
        password: str | None = None,
    ) -> None:
        if email and password:
            master_key, self._api.session_id = await auth.login(self._api, email, password)
        else:
            master_key, self._api.session_id = await auth.login_anonymous(self._api)

        self._vault = MegaVault(master_key)
        logger.info("Getting all nodes and decryption keys of the account...")
        self._filesystem = await self._prepare_filesystem()
        logger.info(f"File system: {self._filesystem}")
        logger.info("Login complete")

    parse_file_url = staticmethod(utils.parse_file_url)
    parse_folder_url = staticmethod(utils.parse_folder_url)

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

    async def _prepare_filesystem(self) -> UserFileSystem:
        nodes_resp: GetNodesResponse = await self._api.request(
            {
                "a": "f",
                "c": 1,
                "r": 1,  # recursive
            }
        )

        self._vault.init_shared_keys(nodes_resp)
        nodes = await self._vault.deserialize_nodes(nodes_resp["f"])
        return await asyncio.to_thread(UserFileSystem.build, nodes)

    async def _request_upload(self, file_size: int) -> str:
        resp = await self._api.request({"a": "u", "s": file_size})
        return resp["p"]

    async def _upload(self, file_path: str | PathLike[str], dest_node_id: NodeID) -> GetNodesResponse:
        file_path = Path(file_path)
        file_size = file_path.stat().st_size

        with self._progress.new_task(file_path.name, file_size) as progress_hook:
            file_id, crypto = await upload.upload(self._api, file_path, file_size, progress_hook)
            return await upload.finish_upload(
                self._api,
                self._vault.master_key,
                file_id,
                file_path,
                dest_node_id,
                crypto.full_key,
                crypto.key,
            )

    async def _download_file(
        self,
        file_info: FileInfo,
        crypto: Crypto,
        output_folder: str | PathLike[str] | None = None,
        output_name: str | None = None,
    ) -> Path:
        # Seems to happens sometime... When this occurs, files are
        # inaccessible also in the official web app.
        # Strangely, files can come back later.
        if not file_info.url:
            raise RequestError("File not accessible anymore")

        name = output_name or Attributes.parse(decrypt_attr(b64_url_decode(file_info._at), crypto.key)).name
        output_path = Path(output_folder or Path()) / name

        with self._progress.new_task(output_path.name, file_info.size) as progress_hook:
            async with self._api.download(file_info.url) as response:
                return await download.stream_download(
                    response.content,
                    output_path,
                    file_info.size,
                    crypto.iv,
                    crypto.meta_mac,
                    crypto.key,
                    progress_hook,
                )

    async def _export_file(self, node: Node) -> None:
        _ = await self._api.request(
            {
                "a": "l",
                "n": node.id,
                "i": self._api._client_id,
            }
        )

    async def _export_folder(self, node: Node) -> dict[str, Any]:
        master_key_cipher = AES.new(a32_to_bytes(self._vault.master_key), AES.MODE_ECB)
        ha = b64_url_encode(master_key_cipher.encrypt(node.id.encode("utf8") * 2))
        share_key = random.randbytes(16)
        ok = b64_url_encode(master_key_cipher.encrypt(share_key))
        share_key_cipher = AES.new(share_key, AES.MODE_ECB)
        encrypted_node_key = b64_url_encode(share_key_cipher.encrypt(a32_to_bytes(node._crypto.key)))
        resp = await self._api.request(
            {
                "a": "s2",
                "cr": [
                    [node.id],
                    [node.id],
                    [0, 0, encrypted_node_key],
                ],
                "ha": ha,
                "i": self._api._client_id,
                "n": node.id,
                "ok": ok,
                "s": [
                    {
                        "r": 0,
                        "u": "EXP",  # User: export (AKA public)
                    }
                ],
            }
        )
        return resp

    def _success(self, resp: int, clear_cache: bool = True) -> bool:
        success = resp == 0
        if success and clear_cache:
            self._filesystem = None
        return success

    async def _mkdir(self, path: str, parent_node_id: str) -> Node:
        # generate random aes key (128) for folder
        new_key = utils.random_u32int_array(4)
        encrypt_attribs = b64_url_encode(encrypt_attr({"n": path}, new_key))
        encrypted_key = a32_to_base64(encrypt_key(new_key, self._vault.master_key))

        # This can return multiple folders if subfolders needed to be created
        folders: GetNodesResponse = await self._api.request(
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
        self._filesystem = None
        return self._vault.deserialize_node(folders["f"][0])

    async def _edit_contact(self, email: str, *, add: bool) -> int:
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

    async def _destroy(self, *node_ids: NodeID) -> int:
        """Destroy a file or folder by its private id (bypass trash bin)"""
        self._filesystem = None
        return await self._api.request(
            [
                {
                    "a": "d",
                    "n": node_id,
                    "i": self._api._client_id,
                }
                for node_id in node_ids
            ]
        )

    async def _move(self, node_id: NodeID, target_id: NodeID) -> int:
        self._filesystem = None
        return await self._api.request(
            {
                "a": "m",
                "n": node_id,
                "t": target_id,
                "i": self._api._client_id,
            }
        )
