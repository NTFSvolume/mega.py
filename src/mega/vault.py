from __future__ import annotations

import dataclasses
import logging
from typing import TYPE_CHECKING, Final, NamedTuple

from mega.crypto import b64_to_a32, decrypt_key
from src.mega.data_structures import Crypto

if TYPE_CHECKING:
    from collections.abc import Generator

    from mega.data_structures import ComposedFileKey, GetNodesResponse, Node, NodeID, NodeKey, SharedKeys, UserID

logger = logging.getLogger(__name__)
_EXPORTED: Final = "EXP"
# An special owner used for exported (AKA public) file/folders


class KeyLookup(NamedTuple):
    full_key: ComposedFileKey | NodeKey
    share_key: NodeKey | None


@dataclasses.dataclass(slots=True, frozen=True)
class MegaVault:
    master_key: tuple[int, ...] = ()

    _shared_keys: dict[UserID, SharedKeys] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        _ = self._shared_keys.setdefault(_EXPORTED, {})

    def update(self, api_resp: GetNodesResponse) -> None:
        """Parse and update keys not associated with an user"""

        new_keys: SharedKeys = {}
        for share_key in api_resp["ok"]:
            node_id, key = share_key["h"], share_key["k"]
            new_keys[node_id] = decrypt_key(b64_to_a32(key), self.master_key)

        for share_target in api_resp["s"]:
            node_id, owner = share_target["h"], share_target["u"]
            if key := new_keys.get(node_id):
                self._shared_keys.setdefault(owner, {})[node_id] = key

    def __getitem__(self, node: Node) -> KeyLookup:
        keys = self.get_keys(node)
        if len(keys) > 1:
            logger.warning("Found multiple keys for node %s, using latest one", node.id)
        crypto = keys[-1]
        return KeyLookup(crypto.full_key, crypto.share_key)

    def _get_keys(self, node: Node) -> Generator[Crypto]:
        def cast_key(full_key: tuple[int, ...], share_key: tuple[int, ...] | None):
            if len(full_key) not in (4, 8):
                raise RuntimeError(f"Invalid key len found for node {node.id} ({len(full_key)})")

            return Crypto.decompose(full_key, node.type, share_key)  # pyright: ignore[reportArgumentType]

        # my files/folders
        if node.owner in node.keys:
            full_key = decrypt_key(b64_to_a32(node.keys[node.owner]), self.master_key)
            yield cast_key(full_key, None)
            return

        # folders shared with me
        if node.share_owner and node.share_key and node.id in node.keys:
            share_key = decrypt_key(b64_to_a32(node.share_key), self.master_key)
            full_key = decrypt_key(b64_to_a32(node.keys[node.id]), share_key)
            self._shared_keys.setdefault(node.share_owner, {})[node.id] = share_key
            yield cast_key(full_key, share_key)
            return

        # files shared with me
        if node.owner in self._shared_keys:
            shared_keys = self._shared_keys[node.owner]
            for node_id, encrypted_key in node.keys.items():
                try:
                    share_key = shared_keys[node_id]
                except KeyError:
                    continue

                full_key = decrypt_key(b64_to_a32(encrypted_key), share_key)
                yield cast_key(full_key, share_key)
            return

        # public files/folders
        if share_key := self._shared_keys[_EXPORTED].get(node.id):
            exported_nodes = self._shared_keys[_EXPORTED].keys()
            for node_id, encrypted_key in node.keys.items():
                if node_id not in exported_nodes:
                    continue

                full_key = decrypt_key(b64_to_a32(encrypted_key), share_key)
                yield cast_key(full_key, share_key)

    def get_keys(self, node: Node) -> list[Crypto]:
        keys = list(self._get_keys(node))
        if len(keys) == 0:
            raise RuntimeError(f"We do not have keys for {node = }")
        return keys

    def save_public_key(self, node_id: NodeID, share_key: tuple[int, ...]) -> None:
        self._shared_keys[_EXPORTED][node_id] = share_key
