from __future__ import annotations

import asyncio
import dataclasses
import logging
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from mega.core import MegaCore
from mega.crypto import a32_to_base64, b64_decrypt_attr, b64_to_a32, b64_url_encode, encrypt_attr, encrypt_key
from mega.data_structures import AccountStats, Attributes, FileInfo, Node, NodeID, NodeType, UserResponse
from mega.filesystem import FileSystem, UserFileSystem
from mega.utils import throttled_gather

from .errors import RequestError, ValidationError

if TYPE_CHECKING:
    from os import PathLike

    from mega.data_structures import GetNodesResponse


logger = logging.getLogger(__name__)


class Mega(MegaCore):
    """Interface with all the public methods of the API"""

    async def search(self, query: str | PathLike[str], *, exclude_deleted: bool = True) -> dict[NodeID, PurePosixPath]:
        """Return nodes that have "query" as a substring on their path"""
        fs = await self.get_filesystem()
        return dict(fs.search(query, exclude_deleted=exclude_deleted))

    async def find(self, query: str | PathLike[str]) -> Node | None:
        """Return the first node that which path starts with `query`"""
        fs = await self.get_filesystem()
        return fs.find(query)

    async def get_filesystem(self, *, force: bool = False) -> UserFileSystem:
        if self._filesystem is None or force:
            async with self._lock:
                if self._filesystem is None or force:
                    self._filesystem = await self._prepare_filesystem()

        return self._filesystem

    async def get_public_link(self, file: Node) -> str:
        if file.type not in (NodeType.FILE, NodeType.FOLDER):
            raise ValueError

        public_handle: NodeID = await self._get_public_handle(file.id)
        public_key = a32_to_base64(file._crypto.full_key)
        return f"{self._primary_url}/#!{public_handle}!{public_key}"

    async def get_folder_link(self, folder: Node) -> str:
        if folder.type not in (NodeType.FILE, NodeType.FOLDER):
            raise ValueError

        assert folder._crypto and folder._crypto.share_key
        public_handle = await self._get_public_handle(folder.id)
        public_key = a32_to_base64(folder._crypto.share_key)
        return f"{self._primary_url}/#F!{public_handle}!{public_key}"

    async def get_user(self) -> UserResponse:
        return await self._api.request({"a": "ug"})

    async def get_id_from_public_handle(self, public_handle: NodeID) -> str:
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

    async def delete(self, node_id: NodeID) -> bool:
        """Delete a file or folder by its private id (moves it to the trash bin)"""
        fs = await self.get_filesystem()
        return await self.move(node_id, fs.trash_bin.id)

    async def destroy(self, node_id: NodeID) -> bool:
        """Destroy a file or folder by its private id (bypasses trash bin)"""
        resp = await self._destroy(node_id)
        return self._success(resp)

    async def empty_trash(self) -> bool | None:
        """Deletes all file in the trash bin. Returns `None` if the trash was already empty"""

        fs = await self.get_filesystem()
        trashed_files = [f.id for f in fs.deleted]
        if not trashed_files:
            return

        resp = await self._destroy(*trashed_files)
        return self._success(resp)

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

    async def get_nodes_in_public_folder(self, public_handle: NodeID, public_key: str) -> FileSystem:
        folder: GetNodesResponse = await self._api.request(
            {
                "a": "f",
                "c": 1,
                "ca": 1,
                "r": 1,
            },
            {"n": public_handle},
        )

        nodes = await self._vault.deserialize_nodes(folder["f"], public_key)
        return await asyncio.to_thread(FileSystem.build, nodes)

    async def download(self, node: Node, output_dir: str | PathLike[str] | None = None) -> Path:
        """Download a file by it's file object."""
        file_info = await self._request_file_info(node.id)
        return await self._download_file(
            file_info,
            node._crypto,
            output_folder=output_dir,
        )

    async def download_public_file(
        self, public_handle: NodeID, public_key: str, output_dir: str | PathLike[str] | None = None
    ) -> Path:
        full_key = b64_to_a32(public_key)
        crypto = self._vault.compose_crypto(NodeType.FILE, full_key)
        file_info = await self._request_file_info(public_handle, is_public=True)
        return await self._download_file(
            file_info,
            crypto,
            output_dir,
        )

    async def download_public_folder(
        self, public_handle: NodeID, public_key: str, output_dir: str | PathLike[str] | None = None
    ) -> list[Path | Exception]:
        """
        Recursively download all files from a public folder, preserving its internal directory structure.

        Returns:
            A list where each element is either a `Path` (a successful download)
            or an `Exception` (a failed download).
        """
        fs = await self.get_nodes_in_public_folder(public_handle, public_key)

        base_path = Path(output_dir or ".")
        folder_url = f"{self._primary_url}/folder/{public_handle}#{public_key}"

        async def worker(file: Node, path: PurePosixPath) -> Path:
            web_url = folder_url + f"/file/{file.id}"
            output_folder = base_path / path.parent
            try:
                file_info = await self._request_file_info(file.id, public_handle)
                return await self._download_file(file_info, file._crypto, output_folder, path.name)
            except Exception:
                logger.exception(f"Unable to download {web_url} to {output_folder}")
                raise

        def make_coros():
            for file in fs.files:
                path = fs.relative_path(file.id)
                yield (worker(file, path))

        return await throttled_gather(make_coros(), return_exceptions=True)

    async def upload(self, file_path: str | PathLike[str], dest_node_id: NodeID | None = None) -> GetNodesResponse:
        if not dest_node_id:
            dest_node_id = (await self.get_filesystem()).root.id

        return await self._upload(file_path, dest_node_id)

    async def create_folder(self, path: str | PathLike[str]) -> Node:
        path = PurePosixPath(path).as_posix()
        fs = await self.get_filesystem()
        return await self._mkdir(name=path, parent_node_id=fs.root.id)

    async def rename(self, node: Node, new_name: str) -> bool:
        new_attrs = dataclasses.replace(node.attributes, name=new_name)
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
        return self._success(resp)

    async def move(self, node_id: NodeID, target_id: NodeID) -> bool:
        resp = await self._move(node_id, target_id)
        return self._success(resp)

    async def add_contact(self, email: str) -> bool:
        resp = await self._edit_contact(email, add=True)
        return self._success(resp, clear_cache=False)

    async def remove_contact(self, email: str) -> bool:
        resp = await self._edit_contact(email, add=False)
        return self._success(resp, clear_cache=False)

    async def get_public_file_info(self, public_handle: NodeID, public_key: str) -> FileInfo:
        """Get size and name of a public file"""
        full_key = b64_to_a32(public_key)
        key = self._vault.compose_crypto(NodeType.FILE, full_key).key
        file_info = await self._request_file_info(public_handle, is_public=True)
        name = Attributes.parse(b64_decrypt_attr(file_info._at, key)).name
        return dataclasses.replace(file_info, name=name)

    async def import_public_file(
        self, public_handle: NodeID, public_key: str, dest_node_id: NodeID | None = None
    ) -> Node:
        """Import the public file into user account"""
        if not dest_node_id:
            dest_node_id = (await self.get_filesystem()).root.id

        file_info = await self.get_public_file_info(public_handle, public_key)
        full_key = b64_to_a32(public_key)
        key = self._vault.compose_crypto(NodeType.FILE, full_key).key
        encrypted_key = a32_to_base64(encrypt_key(full_key, self._vault.master_key))
        attributes = b64_url_encode(encrypt_attr({"n": file_info.name}, key))

        resp: GetNodesResponse = await self._api.request(
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

        self._filesystem = None
        return self._vault.deserialize_node(resp["f"][0])
