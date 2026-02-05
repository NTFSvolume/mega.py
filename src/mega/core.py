from __future__ import annotations

import asyncio
import logging
import random
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

from Crypto.Cipher import AES
from rich.logging import RichHandler

from mega.api import MegaAPI
from mega.auth import MegaAuth
from mega.crypto import (
    a32_to_base64,
    a32_to_bytes,
    b64_decrypt_attr,
    b64_encrypt_attr,
    b64_to_a32,
    b64_url_encode,
    encrypt_key,
    random_u32int,
)
from mega.data_structures import Attributes, Crypto, FileInfo, FileInfoSerialized, Node, NodeID
from mega.download import MegaDownloader
from mega.filesystem import UserFileSystem
from mega.vault import MegaKeysVault

from .errors import MegaNzError, RequestError, ValidationError

if TYPE_CHECKING:
    from collections.abc import Iterable
    from os import PathLike

    import aiohttp

    from mega.data_structures import GetNodesResponse, NodeSerialized


logger = logging.getLogger(__name__)


def _setup_logger(name: str = "mega") -> None:
    handler = RichHandler(show_time=False, rich_tracebacks=True)
    logger = logging.getLogger(name)
    logger.setLevel(10)
    logger.addHandler(handler)


class MegaCore:
    def __init__(self, session: aiohttp.ClientSession | None = None) -> None:
        self._api = MegaAPI(session)
        self._primary_url = "https://mega.nz"
        self._auth = MegaAuth(self._api)
        self._vault = MegaKeysVault(())
        self._downloader = MegaDownloader(self._api)
        self._filesystem: UserFileSystem | None = None
        self._lock = asyncio.Lock()

    def __repr__(self) -> str:
        return f"<{type(self).__name__}>(fs={self.filesystem!r}, vault={self._vault!r})"

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()

    async def close(self) -> None:
        await self._api.close()

    @property
    def logged_in(self) -> bool:
        return bool(self._vault.master_key)

    @property
    def filesystem(self) -> UserFileSystem:
        assert self._filesystem is not None
        return self._filesystem

    async def login(self, email: str | None, password: str | None, _mfa: str | None = None) -> None:
        if email and password:
            master_key, self._api.session_id = await self._auth.login(email, password)
        else:
            master_key, self._api.session_id = await self._auth.login_anonymous()

        self._vault = MegaKeysVault(master_key)
        logger.info("Getting all nodes and decryption keys of the account...")
        self._filesystem = await self._prepare_filesystem()
        logger.info(f"File system: {self.filesystem}")
        logger.info("Login complete")

    def _deserialize_node(self, node: NodeSerialized) -> Node:
        return self._vault.decrypt(Node.parse(node))

    @staticmethod
    def parse_file_url(url: str) -> tuple[str, str]:
        """Parse file id and key from url."""
        if "/file/" in url:
            # V2 URL structure
            # ex: https://mega.nz/file/cH51DYDR#qH7QOfRcM-7N9riZWdSjsRq
            url = url.replace(" ", "")
            file_id = re.findall(r"\W\w\w\w\w\w\w\w\w\W", url)[0][1:-1]
            match = re.search(file_id, url)
            assert match
            id_index = match.end()
            key = url[id_index + 1 :]
            return file_id, key
        elif "!" in url:
            # V1 URL structure
            # ex: https://mega.nz/#!Ue5VRSIQ!kC2E4a4JwfWWCWYNJovGFHlbz8F
            match = re.findall(r"/#!(.*)", url)
            path = match[0]
            return tuple(path.split("!"))
        else:
            raise ValueError(f"URL key missing from {url}")

    @staticmethod
    def parse_folder_url(url: str) -> tuple[str, str]:
        if "/folder/" in url:
            _, parts = url.split("/folder/", 1)
        elif "#F!" in url:
            _, parts = url.split("#F!", 1)
        else:
            raise ValidationError("Not a valid folder URL")
        root_folder_id, shared_key = parts.split("#")
        return root_folder_id, shared_key

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
        nodes = await self._deserialize_nodes(nodes_resp["f"])
        return await asyncio.to_thread(UserFileSystem.build, nodes)

    async def _deserialize_nodes(self, nodes: Iterable[NodeSerialized], public_key: str | None = None) -> list[Node]:
        """
        Processes multiple nodes at once, decrypting their keys and attributes.
        """

        share_key = b64_to_a32(public_key) if public_key else None
        resolved_nodes: list[Node] = []

        for idx, node in enumerate(nodes):
            node_id = node["h"]
            if share_key:
                self._vault.shared_keys["EXP"][node_id] = share_key

            resolved_nodes.append(self._deserialize_node(node))

            if idx % 500 == 0:
                await asyncio.sleep(0)

        return resolved_nodes

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

        name = output_name or Attributes.parse(b64_decrypt_attr(file_info._at, crypto.key)).name
        output_path = Path(output_folder or Path()) / name

        return await self._downloader.run(
            file_info.url,
            output_path,
            file_info.size,
            crypto.iv,
            crypto.meta_mac,
            crypto.key,
        )

    async def _export_file(self, node: Node) -> dict[str, Any]:
        return await self._api.request(
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
        return await self._api.request(
            {
                "a": "s2",
                "n": node.id,
                "s": [
                    {
                        "u": "EXP",  # User: export (AKA public)
                        "r": 0,
                    }
                ],
                "i": self._api._client_id,
                "ok": ok,
                "ha": ha,
                "cr": [[node.id], [node.id], [0, 0, encrypted_node_key]],
            }
        )

    def _success(self, resp: int, clear_cache: bool = True) -> bool:
        success = resp == 0
        if success and clear_cache:
            self._filesystem = None
        return success

    async def _mkdir(self, name: str, parent_node_id: str) -> Node:
        # generate random aes key (128) for folder
        new_key = [random_u32int() for _ in range(4)]
        encrypt_attribs = b64_encrypt_attr({"n": name}, new_key)
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
        return self._deserialize_node(folders["f"][0])

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
