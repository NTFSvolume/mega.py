from __future__ import annotations

import asyncio
import dataclasses
import logging
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, ClassVar, TypeAlias

import yarl

from mega import download, progress
from mega.api import AbstractApiClient, MegaAPI
from mega.crypto import b64_to_a32, b64_url_decode, decrypt_attr
from mega.data_structures import Attributes, Crypto, Node, NodeID, NodeType
from mega.filesystem import FileSystem
from mega.utils import Site, throttled_gather

if TYPE_CHECKING:
    from collections.abc import Iterable
    from os import PathLike

    import aiohttp

    from mega.data_structures import GetNodesResponse, NodeSerialized


TransferID: TypeAlias = str

logger = logging.getLogger(__name__)


class TransferItAPI(MegaAPI):
    _entrypoint: ClassVar[yarl.URL] = yarl.URL("https://bt7.api.mega.co.nz/cs")

    async def post(self, json: dict[str, Any] | list[dict[str, Any]], params: dict[str, Any] | None = None) -> Any:
        params = {
            "v": 3,
            "domain": "transferit",
            "lang": "en",
            "bc": 1,
        } | (params or {})
        return await super().post(json, params)


class TransferItClient(AbstractApiClient):
    def __init__(self, session: aiohttp.ClientSession | None = None) -> None:  # pyright: ignore[reportMissingSuperCall]
        self._api = TransferItAPI(session)

    async def get_filesystem(self, transfer_id: TransferID) -> FileSystem:
        folder: GetNodesResponse = await self._api.post(
            {
                "a": "f",
                "c": 1,
                "r": 1,
                "xnc": 1,
            },
            {"x": transfer_id},
        )
        return await asyncio.to_thread(self._deserialize_nodes, folder["f"])

    @staticmethod
    def parse_url(url: str | yarl.URL) -> TransferID:
        url = yarl.URL(url)
        Site.TRANSFER_IT.check_host(url)

        match url.parts[1:]:
            case ["t", transfer_id]:
                return transfer_id
            case _:
                raise ValueError(f"Unknown URL format {url}")

    def create_download_url(self, transfer_id: TransferID, file: Node, password: str | None = None) -> str:
        """Get a direct download URL to the node

        NOTE: Download requests need `https://transfer.it` as referer in the headers
        """
        url = (self._api.entrypoint / "g").with_query(x=transfer_id, n=file.id, fn=file.attributes.name)
        if password:
            url = url.update_query(pw=password)
        return str(url)

    def _deserialize_nodes(self, nodes: Iterable[NodeSerialized]) -> FileSystem:
        return FileSystem.build([self._decrypt(Node.parse(node)) for node in nodes])

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
        root_id: NodeID | None = None,
    ) -> tuple[list[Path], list[Exception]]:
        """Recursively download all files from a transfer, preserving its internal directory structure.

        Returns:
            A list where each element is either a `Path` (a successful download)
            or an `Exception` (a failed download).
        """
        fs = await self.get_filesystem(transfer_id)

        base_path = Path(output_dir or ".") / f"transfer.it ({transfer_id})"
        folder_url = f"https://transfer.it/t/{transfer_id}"

        async def worker(file: Node, path: PurePosixPath) -> Path:
            web_url = folder_url + f"#{file.id}"
            output_folder = base_path / path.parent
            dl_link = self.create_download_url(transfer_id, file)
            try:
                return await self._download_file(dl_link, output_folder, path.name)
            except Exception as exc:
                logger.error(f'Unable to download {web_url} to "{output_folder}" ({type(exc).__name__})')
                raise

        def make_coros():
            for file in fs.files_from(root_id):
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

        async with self._api.get(dl_link, headers={"Referer": "https://transfer.it/"}) as response:
            size = int(response.headers["Content-Length"])
            with progress.new_task(name, size, "DOWN"):
                return await download.stream(response.content, output_path)
