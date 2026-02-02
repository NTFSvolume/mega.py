from __future__ import annotations

import dataclasses
import logging
from typing import TYPE_CHECKING

from mega.crypto import (
    b64_to_a32,
    b64_url_decode,
    decrypt_attr,
    decrypt_key,
    str_to_a32,
)
from mega.data_structures import Attributes, Crypto, Node, NodeType

if TYPE_CHECKING:
    from mega.data_structures import GetNodesResponse, SharedKeys


logger = logging.getLogger(__name__)


@dataclasses.dataclass(slots=True, frozen=True)
class MegaKeysVault:
    master_key: tuple[int, ...]
    shared_keys: dict[str, SharedKeys] = dataclasses.field(default_factory=dict, repr=False)
    # This is a mapping of owner (user_id) to shared keys. An special owner "EXP" is used for exported (AKA public) file/folders

    def init_shared_keys(self, nodes_response: GetNodesResponse) -> None:
        """
        Init shared key not associated with a user.
        Seems to happen when a folder is shared,
        some files are exchanged and then the
        folder is un-shared.
        Keys are stored in files['s'] and files['ok']
        """
        if self.shared_keys:
            return

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
        elif node.share_id and node.share_key and node.id in node.keys:
            share_key = decrypt_key(b64_to_a32(node.share_key), self.master_key)
            full_key = decrypt_key(b64_to_a32(node.keys[node.id]), share_key)
            self.shared_keys.setdefault(node.share_id, {})[node.id] = share_key

        # files shared with me
        elif node.owner in self.shared_keys:
            real_node_id, share_key = next(p for p in self.shared_keys[node.owner].items() if p[0] in node.keys)
            full_key = decrypt_key(b64_to_a32(node.keys[real_node_id]), share_key)

        # public files/folders
        elif share_key := self.shared_keys.get("EXP", {}).get(node.id):
            encrypted_key = str_to_a32(b64_url_decode(next(iter(node.keys.values()))))
            full_key = decrypt_key(encrypted_key, share_key)

        else:
            raise RuntimeError(f"We do not have keys for {node = }")

        return full_key, share_key

    @staticmethod
    def compose_crypto(
        node_type: NodeType, full_key: tuple[int, ...], share_key: tuple[int, ...] | None = None
    ) -> Crypto:
        if node_type is NodeType.FILE:
            key = (
                full_key[0] ^ full_key[4],
                full_key[1] ^ full_key[5],
                full_key[2] ^ full_key[6],
                full_key[3] ^ full_key[7],
            )

        else:
            key = full_key

        iv = *full_key[4:6], 0, 0
        meta_mac = full_key[6:8]
        return Crypto(key, iv, meta_mac, full_key, share_key)  # pyright: ignore[reportArgumentType]

    def decrypt(self, node: Node) -> Node:
        if node.type in (NodeType.FILE, NodeType.FOLDER):
            full_key, share_key = self.get_keys(node)
            node._crypto = self.compose_crypto(node.type, full_key, share_key)
            attributes = decrypt_attr(b64_url_decode(node._a), node._crypto.key)
            node.attributes = Attributes.parse(attributes)

        else:
            name = {
                NodeType.ROOT_FOLDER: "Cloud Drive",
                NodeType.INBOX: "Inbox",
                NodeType.TRASH: "Trash Bin",
            }[node.type]
            node.attributes = Attributes(name)

        return node
