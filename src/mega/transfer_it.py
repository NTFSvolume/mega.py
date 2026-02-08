from __future__ import annotations

import asyncio
import dataclasses
import logging
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, ClassVar, TypeAlias

import yarl

from mega import download, progress
from mega.api import MegaAPI
from mega.crypto import b64_to_a32, b64_url_decode, decrypt_attr
from mega.data_structures import Attributes, Crypto, Node, NodeType
from mega.filesystem import FileSystem
from mega.utils import throttled_gather

if TYPE_CHECKING:
    from collections.abc import Iterable
    from os import PathLike

    from mega.data_structures import GetNodesResponse, NodeSerialized


TransferID: TypeAlias = str

logger = logging.getLogger(__name__)


class TransferItAPI(MegaAPI):
    entrypoint: ClassVar[yarl.URL] = yarl.URL("https://bt7.api.mega.co.nz/cs")

    async def request(self, data: dict[str, Any] | list[dict[str, Any]], params: dict[str, Any] | None = None) -> Any:
        params = {
            "v": 3,
            "domain": "transferit",
            "lang": "en",
            "bc": 1,
        } | (params or {})
        return await super().request(data, params)


class TransferItClient:
    def __init__(self) -> None:
        self._api: TransferItAPI = TransferItAPI()

    async def get_filesystem(self, transfer_id: TransferID) -> FileSystem:
        folder: GetNodesResponse = await self._api.request(
            {
                "a": "f",
                "c": 1,
                "r": 1,
                "xnc": 1,
            },
            {"x": transfer_id},
        )
        nodes = await asyncio.to_thread(self._deserialize_nodes, folder["f"])
        return await asyncio.to_thread(FileSystem.build, nodes)

    @staticmethod
    def parse_url(url: str) -> TransferID:
        if not url.startswith("https://transfer.it/"):
            raise ValueError

        match yarl.URL(url).parts[1:]:
            case ["t", transfer_id]:
                return transfer_id
            case _:
                raise ValueError

    def get_download_link(self, transfer_id: TransferID, file: Node, password: str | None = None) -> str:
        """Get a direct download URL to the node

        NOTE: Download requests need `https://transfer.it` as referer in the headers
        """
        url = (self._api.entrypoint / "g").with_query(x=transfer_id, n=file.id, fn=file.attributes.name)
        if password:
            url = url.update_query(pw=password)
        return str(url)

    def _deserialize_nodes(self, nodes: Iterable[NodeSerialized]) -> list[Node]:
        return [self._decrypt(Node.parse(node)) for node in nodes]

    def _decrypt(self, node: Node) -> Node:
        crypto = attributes = None
        assert node.type in (NodeType.FILE, NodeType.FOLDER)
        full_key = b64_to_a32(next(iter(node.keys.values())))
        crypto = Crypto.decompose(full_key, node.type)
        attributes = Attributes.parse(decrypt_attr(b64_url_decode(node._a), crypto.key))
        return dataclasses.replace(node, _crypto=crypto, attributes=attributes)

    async def download_transfer(
        self,
        transfer_id: TransferID,
        output_dir: str | PathLike[str] | None = None,
    ) -> tuple[list[Path], list[Exception]]:
        """Recursively download all files from a transfer, preserving its internal directory structure.

        Returns:
            A list where each element is either a `Path` (a successful download)
            or an `Exception` (a failed download).
        """
        fs = await self.get_filesystem(transfer_id)

        base_path = Path(output_dir or ".")
        folder_url = f"https://transfer.it/t/{transfer_id}"

        async def worker(file: Node, path: PurePosixPath) -> Path:
            web_url = folder_url + f"#{file.id}"
            output_folder = base_path / path.parent
            dl_link = self.get_download_link(transfer_id, file)
            try:
                return await self._download_file(dl_link, output_folder, path.name)
            except Exception:
                logger.exception(f"Unable to download {web_url} to {output_folder}")
                raise

        def make_coros():
            for file in fs.files:
                path = fs.relative_path(file.id)
                yield (worker(file, path))

        results = await throttled_gather(make_coros(), return_exceptions=True)
        success: list[Path] = []
        fails: list[Exception] = [
            result for result in results if isinstance(result, Exception) or (success.append(result) and False)
        ]

        return success, fails

    async def _download_file(
        self,
        dl_link: str,
        output_folder: str | PathLike[str] | None = None,
        output_name: str | None = None,
    ) -> Path:
        name = output_name or yarl.URL(dl_link).query["fn"]
        output_path = Path(output_folder or Path()) / name

        async with self._api.download(dl_link) as response:
            size = int(response.headers["Content-Length"])
            with progress.new_task(name, size, "DOWN"):
                return await download.stream(response.content, output_path)
