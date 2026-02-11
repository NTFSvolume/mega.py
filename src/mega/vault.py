from __future__ import annotations

import dataclasses
import logging
from typing import TYPE_CHECKING

from mega.crypto import b64_to_a32, decrypt_key

if TYPE_CHECKING:
    from mega.data_structures import GetNodesResponse, Node, NodeID, SharedKeys, UserID


logger = logging.getLogger(__name__)


@dataclasses.dataclass(slots=True, frozen=True)
class MegaVault:
    master_key: tuple[int, ...] = ()

    shared_keys: dict[UserID, SharedKeys] = dataclasses.field(default_factory=dict, repr=False)
    # An special owner "EXP" is used for exported (AKA public) file/folders

    def __getitem__(self, node: Node) -> tuple[tuple[int, ...], tuple[int, ...] | None]:
        return self.get_keys(node)

    def init_shared_keys(self, nodes_response: GetNodesResponse) -> None:
        """Init shared key not associated with a user.
        Seems to happen when a folder is shared,
        some files are exchanged and then the
        folder is un-shared.
        Keys are stored in files['s'] and files['ok']
        """
        self.shared_keys["EXP"] = {}
        new_keys: SharedKeys = {}
        for share_key in nodes_response["ok"]:
            node_id, key = share_key["h"], share_key["k"]
            new_keys[node_id] = decrypt_key(b64_to_a32(key), self.master_key)

        for share_key in nodes_response["s"]:
            node_id, owner = share_key["h"], share_key["u"]
            if key := new_keys.get(node_id):
                self.shared_keys.setdefault(owner, {})[node_id] = key

    def get_keys(self, node: Node) -> tuple[tuple[int, ...], tuple[int, ...] | None]:
        share_key: tuple[int, ...] | None = None

        # my files/folders
        if node.owner in node.keys:
            full_key = decrypt_key(b64_to_a32(node.keys[node.owner]), self.master_key)

        # folders shared with me
        elif node.share_owner and node.share_key and node.id in node.keys:
            share_key = decrypt_key(b64_to_a32(node.share_key), self.master_key)
            full_key = decrypt_key(b64_to_a32(node.keys[node.id]), share_key)
            self.shared_keys.setdefault(node.share_owner, {})[node.id] = share_key

        # files shared with me
        elif node.owner in self.shared_keys:
            real_node_id, share_key = next(p for p in self.shared_keys[node.owner].items() if p[0] in node.keys)
            full_key = decrypt_key(b64_to_a32(node.keys[real_node_id]), share_key)

        # public files/folders
        elif share_key := self.shared_keys.get("EXP", {}).get(node.id):
            encrypted_key = b64_to_a32(next(iter(node.keys.values())))
            full_key = decrypt_key(encrypted_key, share_key)

        else:
            raise RuntimeError(f"We do not have keys for {node = }")

        return full_key, share_key

    def save_public_key(self, node_id: NodeID, share_key: tuple[int, ...]) -> None:
        self.shared_keys["EXP"][node_id] = share_key
