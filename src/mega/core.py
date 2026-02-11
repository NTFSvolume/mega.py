from __future__ import annotations

import asyncio
import dataclasses
import logging
import random
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple

import yarl
from Crypto.Cipher import AES

from mega import auth, download, progress, upload
from mega.crypto import (
    a32_to_base64,
    a32_to_bytes,
    b64_to_a32,
    b64_url_decode,
    b64_url_encode,
    decrypt_attr,
    encrypt_attr,
    encrypt_key,
)
from mega.data_structures import (
    Attributes,
    Crypto,
    FileInfo,
    FileInfoSerialized,
    Node,
    NodeID,
    NodeSerialized,
    NodeType,
    UserResponse,
)
from mega.errors import MegaNzError, RequestError, ValidationError
from mega.filesystem import FileSystem, UserFileSystem
from mega.utils import Site, get_file_size, random_u32int_array, transform_v1_url
from mega.vault import MegaVault

if TYPE_CHECKING:
    from collections.abc import Iterable
    from os import PathLike

    from mega.api import MegaAPI
    from mega.data_structures import GetNodesResponse


logger = logging.getLogger(__name__)


class PublicURLInfo(NamedTuple):
    is_folder: bool
    public_handle: NodeID
    public_key: str
    selected_folder: NodeID | None = None
    selected_file: NodeID | None = None

    @property
    def selected_node(self) -> NodeID | None:
        return self.selected_folder or self.selected_file


@dataclasses.dataclass(slots=True)
class MegaCore:
    api: MegaAPI
    filesystem: UserFileSystem | None = None
    vault: MegaVault = dataclasses.field(default_factory=MegaVault)
    _lock: asyncio.Lock = dataclasses.field(default_factory=asyncio.Lock, repr=False)

    async def get_filesystem(self, *, force: bool = False) -> UserFileSystem:
        if self.filesystem is None or force:
            async with self._lock:
                if self.filesystem is None or force:
                    self.filesystem = await self._prepare_filesystem()

        return self.filesystem

    async def login(self, email: str | None = None, password: str | None = None) -> None:
        if email and password:
            master_key, self.api.session_id = await auth.login(self.api, email, password)
        else:
            master_key, self.api.session_id = await auth.login_anonymous(self.api)

        self.vault = MegaVault(master_key)
        logger.info("Getting all nodes and decryption keys of the account...")
        self.filesystem = await self._prepare_filesystem()
        logger.debug(f"File system: {self.filesystem}")
        logger.info("Login complete!")

    @classmethod
    def parse_file_url(cls, url: str | yarl.URL) -> tuple[NodeID, str]:
        result = cls.parse_url(url)
        if result.is_folder:
            raise ValidationError(f"This is a folder URL: {url}")
        return result.public_handle, result.public_key

    @classmethod
    def parse_folder_url(cls, url: str | yarl.URL) -> tuple[NodeID, str, NodeID | None]:
        result = cls.parse_url(url)
        if not result.is_folder:
            raise ValidationError(f"This is a file URL: {url}")
        return result.public_handle, result.public_key, result.selected_node

    @staticmethod
    def parse_url(url: str | yarl.URL) -> PublicURLInfo:
        """Parse a public URL"""
        url = yarl.URL(url)
        Site.MEGA.check_host(url)
        new_url = transform_v1_url(url)
        if new_url != url:
            logger.info(f"Transformed v1 URL from {url} to {new_url}")

        url = new_url
        if not url.fragment:
            raise ValidationError(f"Public key missing from {url}")

        match url.parts[1:]:
            case ["file", public_handle]:
                return PublicURLInfo(False, public_handle, url.fragment)
            case ["folder", public_handle]:
                selected_folder = selected_file = None
                public_key, *rest = url.fragment.split("/")
                match rest:
                    case ["folder", id_]:
                        selected_folder = id_
                    case ["file", id_]:
                        selected_file = id_
                    case []:
                        pass
                    case _:
                        raise ValidationError(f"Unknown URL format {url}")

                return PublicURLInfo(True, public_handle, public_key, selected_folder, selected_file)

            case _:
                raise ValidationError(f"Unknown URL format {url}")

    async def get_user(self) -> UserResponse:
        return await self.api.post({"a": "ug"})

    async def public_handle_from_id(self, node_id: NodeID) -> str:
        try:
            return await self.api.post(
                {
                    "a": "l",
                    "n": node_id,
                },
            )
        except RequestError as e:
            if e.code == -11:
                msg = "Can't get a public link from that file"
                error = MegaNzError(msg)
                error.add_note("Is this a shared file? You may need to export it first")
                raise error from e
            raise

    async def id_from_public_handle(self, public_handle: NodeID) -> str:
        resp: GetNodesResponse = await self.api.post(
            {
                "a": "f",
                "f": 1,
                "p": public_handle,
            },
        )
        return resp["f"][0]["h"]

    async def request_file_info(
        self,
        handle: str,
        parent_id: str | None = None,
        is_public: bool = False,
    ) -> FileInfo:
        resp: FileInfoSerialized = await self.api.post(
            {
                "a": "g",
                "g": 1,
                "p" if is_public else "n": handle,
            },
            params={"n": parent_id} if parent_id else None,
        )

        return FileInfo.parse(resp)

    async def _prepare_filesystem(self) -> UserFileSystem:
        logger.info("Fetching users's filesystem information...")
        nodes_resp: GetNodesResponse = await self.api.post(
            {
                "a": "f",
                "c": 1,
                "r": 1,  # recursive
            },
        )

        nodes = nodes_resp["f"]
        logger.info(f"Decrypting and building users's filesystem ({len(nodes)} nodes)...")
        self.vault.init_shared_keys(nodes_resp)
        nodes = await self.deserialize_nodes(nodes)
        return await asyncio.to_thread(UserFileSystem.build, nodes)

    async def deserialize_nodes(self, nodes: Iterable[NodeSerialized], public_key: str | None = None) -> list[Node]:
        """Processes multiple nodes at once, decrypting their keys and attributes"""
        # We can't run this loop in another thread because we modify the vault in place

        share_key = b64_to_a32(public_key) if public_key else None
        resolved_nodes: list[Node] = []

        for idx, node in enumerate(nodes):
            node_id = node["h"]
            if share_key:
                self.vault.save_public_key(node_id, share_key)

            resolved_nodes.append(self._deserialize_node(node))

            if idx % 500 == 0:
                await asyncio.sleep(0)

        return resolved_nodes

    def _deserialize_node(self, node: NodeSerialized) -> Node:
        return self.decrypt(Node.parse(node))

    def decrypt(self, node: Node) -> Node:
        crypto = attributes = None
        if node.type in (NodeType.FILE, NodeType.FOLDER):
            full_key, share_key = self.vault[node]
            crypto = Crypto.decompose(full_key, node.type, share_key)
            attributes = self.decrypt_attrs(node._a, crypto.key)

        else:
            name = {
                NodeType.ROOT_FOLDER: "Cloud Drive",
                NodeType.INBOX: "Inbox",
                NodeType.TRASH: "Trash Bin",
            }[node.type]
            attributes = Attributes(name)

        return dataclasses.replace(node, _crypto=crypto, attributes=attributes)

    def clear_cache(self) -> None:
        self.filesystem = None

    async def upload(self, file_path: str | PathLike[str], dest_node_id: NodeID) -> GetNodesResponse:
        file_path = Path(file_path)
        file_size = await asyncio.to_thread(get_file_size, file_path)

        with progress.new_task(file_path.name, file_size, "UP"):
            file_id, crypto = await upload.upload(self.api, file_path, file_size)
            self.clear_cache()
            return await upload.finish_upload(
                self.api,
                self.vault.master_key,
                file_id,
                file_path,
                dest_node_id,
                crypto.full_key,
                crypto.key,
            )

    async def download_file(
        self,
        file_info: FileInfo,
        crypto: Crypto,
        output_folder: str | PathLike[str],
    ) -> Path:
        # Seems to happens sometime... When this occurs, files are
        # inaccessible also in the official web app.
        # Strangely, files can come back later.
        if not file_info.url:
            raise RequestError("File not accessible anymore")

        output_path = Path(output_folder)
        async with self.api.get(file_info.url) as response:
            with progress.new_task(output_path.name, file_info.size, "DOWN"):
                return await download.encrypted_stream(
                    response.content,
                    output_path,
                    file_info.size,
                    crypto.key,
                    crypto.iv,
                    crypto.meta_mac,
                )

    async def export_file(self, node: Node) -> None:
        _ = await self.api.post(
            {
                "a": "l",
                "n": node.id,
                "i": self.api.client_id,
            },
        )

    async def export_folder(self, node: Node) -> dict[str, Any]:
        master_key_cipher = AES.new(a32_to_bytes(self.vault.master_key), AES.MODE_ECB)
        ha = b64_url_encode(master_key_cipher.encrypt(node.id.encode("utf8") * 2))
        share_key = random.randbytes(16)
        ok = b64_url_encode(master_key_cipher.encrypt(share_key))
        share_key_cipher = AES.new(share_key, AES.MODE_ECB)
        encrypted_node_key = b64_url_encode(share_key_cipher.encrypt(a32_to_bytes(node._crypto.key)))
        resp = await self.api.post(
            {
                "a": "s2",
                "cr": [
                    [node.id],
                    [node.id],
                    [0, 0, encrypted_node_key],
                ],
                "ha": ha,
                "i": self.api.client_id,
                "n": node.id,
                "ok": ok,
                "s": [
                    {
                        "r": 0,
                        "u": "EXP",  # User: export (AKA public)
                    },
                ],
            },
        )
        return resp

    async def get_public_filesystem(self, public_handle: NodeID, public_key: str) -> FileSystem:
        logger.info(f"Fetching filesystem information for {public_handle = }...")
        folder: GetNodesResponse = await self.api.post(
            {
                "a": "f",
                "c": 1,
                "ca": 1,
                "r": 1,
            },
            {"n": public_handle},
        )
        nodes = folder["f"]
        logger.info(f"Decrypting and building filesystem for {public_handle = } ({len(nodes)} nodes)...")
        nodes = await self.deserialize_nodes(nodes, public_key)
        return await asyncio.to_thread(FileSystem.build, nodes)

    async def mkdir(self, path: str, parent_node_id: str) -> Node:
        # generate random aes key (128) for folder
        new_key = random_u32int_array(4)
        encrypt_attribs = b64_url_encode(encrypt_attr({"n": path}, new_key))
        encrypted_key = a32_to_base64(encrypt_key(new_key, self.vault.master_key))

        # This can return multiple folders if subfolders needed to be created
        folders: GetNodesResponse = await self.api.post(
            {
                "a": "p",
                "t": parent_node_id,
                "n": [
                    {
                        "h": "xxxxxxxx",
                        "t": 1,
                        "a": encrypt_attribs,
                        "k": encrypted_key,
                    },
                ],
                "i": self.api.client_id,
            },
        )
        self.clear_cache()
        return self._deserialize_node(folders["f"][0])

    async def edit_contact(self, email: str, *, add: bool) -> None:
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            raise ValidationError("add_contact requires a valid email address")

        _ = await self.api.post(
            {
                "a": "ur",
                "u": email,
                "l": "1" if add else "0",
                "i": self.api.client_id,
            },
        )

    async def destroy(self, *node_ids: NodeID) -> None:
        """Destroy a file or folder by its private id (bypass trash bin)"""
        _ = await self.api.post(
            [
                {
                    "a": "d",
                    "n": node_id,
                    "i": self.api.client_id,
                }
                for node_id in node_ids
            ],
        )
        self.clear_cache()

    async def move(self, node_id: NodeID, target_id: NodeID) -> None:
        _ = await self.api.post(
            {
                "a": "m",
                "n": node_id,
                "t": target_id,
                "i": self.api.client_id,
            },
        )
        self.clear_cache()

    @staticmethod
    def decrypt_attrs(attrs: str, key: tuple[int, ...]) -> Attributes:
        return Attributes.parse(decrypt_attr(b64_url_decode(attrs), key))

    async def import_file(
        self,
        public_handle: NodeID,
        public_key: str,
        dest_node_id: NodeID,
    ) -> Node:
        """Import the public file into user account"""
        full_key = b64_to_a32(public_key)
        key = Crypto.decompose(full_key).key
        file_info = await self.request_file_info(public_handle, is_public=True)
        name = self.decrypt_attrs(file_info._at, key).name
        encrypted_key = a32_to_base64(encrypt_key(full_key, self.vault.master_key))
        attributes = b64_url_encode(encrypt_attr({"n": name}, key))

        resp: GetNodesResponse = await self.api.post(
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
            },
        )

        self.clear_cache()
        return self._deserialize_node(resp["f"][0])
