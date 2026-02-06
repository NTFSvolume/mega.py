from __future__ import annotations

import asyncio
import dataclasses
from typing import TYPE_CHECKING, Any, ClassVar, TypeAlias

import yarl

from mega.api import MegaAPI
from mega.crypto import b64_to_a32, b64_url_decode, compose_crypto, decrypt_attr
from mega.data_structures import Attributes, Node, NodeType
from mega.filesystem import FileSystem

if TYPE_CHECKING:
    from collections.abc import Iterable

    from mega.data_structures import GetNodesResponse, NodeSerialized


TransferID: TypeAlias = str


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

        NOTE: Download requests need `https://transfer.it` as referer in the headers"""
        url = (self._api.entrypoint / "g").with_query(x=transfer_id, n=file.id, fn=file.attributes.name)
        if password:
            url = url.update_query(pw=password)
        return str(url)

    def _deserialize_nodes(self, nodes: Iterable[NodeSerialized]) -> list[Node]:
        return [self._decrypt(Node.parse(node)) for node in nodes]

    def _decrypt(self, node: Node) -> Node:
        crypto = attributes = None
        assert node.type in (NodeType.FILE, NodeType.FOLDER)
        full_key, share_key = b64_to_a32(next(iter(node.keys.values()))), None
        crypto = compose_crypto(full_key, node.type, share_key)
        attributes = Attributes.parse(decrypt_attr(b64_url_decode(node._a), crypto.key))
        return dataclasses.replace(node, _crypto=crypto, attributes=attributes)
