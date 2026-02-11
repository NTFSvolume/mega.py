from __future__ import annotations

import asyncio
import dataclasses
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, TypeAlias

import yarl

from mega import download, progress
from mega.api import APIContextManager, MegaAPI
from mega.crypto import b64_to_a32, b64_url_decode, decrypt_attr
from mega.data_structures import Attributes, Crypto, Node, NodeID, NodeType
from mega.download import DownloadResults
from mega.errors import ValidationError
from mega.filesystem import FileSystem
from mega.utils import Site, async_map, format_error

if TYPE_CHECKING:
    from collections.abc import Iterable
    from contextlib import _GeneratorContextManager  # pyright: ignore[reportPrivateUsage]
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


class TransferItClient(APIContextManager):
    def __init__(self, session: aiohttp.ClientSession | None = None) -> None:  # pyright: ignore[reportMissingSuperCall]
        self._api = TransferItAPI(session)

    @property
    def progress_bar(self) -> _GeneratorContextManager[None, None, None]:
        return progress.new_progress()

    async def get_filesystem(self, transfer_id: TransferID) -> FileSystem:
        logger.info(f"Fetching filesystem information for {transfer_id = }...")
        folder: GetNodesResponse = await self._api.post(
            {
                "a": "f",
                "c": 1,
                "r": 1,
                "xnc": 1,
            },
            {"x": transfer_id},
        )
        nodes = folder["f"]
        logger.info(f"Decrypting and building filesystem for {transfer_id = } ({len(nodes)} nodes)...")
        return await asyncio.to_thread(self._deserialize_nodes, nodes)

    @staticmethod
    def parse_url(url: str | yarl.URL) -> TransferID:
        url = yarl.URL(url)
        Site.TRANSFER_IT.check_host(url)

        match url.parts[1:]:
            case ["t", transfer_id]:
                return transfer_id
            case _:
                raise ValidationError(f"Unknown URL format {url}")

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
    ) -> DownloadResults:
        """Recursively download all files from a transfer, preserving its internal directory structure.

        Returns:
            A list where each element is either a `Path` (a successful download)
            or an `Exception` (a failed download).
        """
        fs = await self.get_filesystem(transfer_id)

        base_path = Path(output_dir or ".") / f"transfer.it ({transfer_id})"
        folder_url = f"https://transfer.it/t/{transfer_id}"

        async def download(file: Node) -> tuple[NodeID, Path | Exception]:
            web_url = folder_url + f"#{file.id}"
            output_path = base_path / fs.relative_path(file.id)
            dl_link = self.create_download_url(transfer_id, file)
            try:
                result = await self._download_file(dl_link, output_path)
            except Exception as exc:
                msg = format_error(exc)
                logger.error(f'Unable to download {web_url} to "{output_path}" {msg}')
                result = exc

            return file.id, result

        results = await async_map(download, fs.files_from(root_id))
        return DownloadResults.split(dict(results))

    async def _download_file(self, dl_link: str, output_path: str | PathLike[str]) -> Path:
        output_path = Path(output_path)
        async with self._api.get(dl_link, headers={"Referer": "https://transfer.it/"}) as response:
            size = int(response.headers["Content-Length"])
            with progress.new_task(output_path.name, size, "DOWN"):
                return await download.stream(response.content, output_path, size)
