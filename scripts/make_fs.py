from __future__ import annotations

import dataclasses
import itertools
import json
import random
import time
from pathlib import Path, PurePosixPath
from pprint import pprint
from types import MappingProxyType
from typing import TYPE_CHECKING

from mega.crypto import a32_to_base64, b64_url_encode, encrypt_attr, encrypt_key
from mega.data_structures import _LABELS, Attributes, Crypto, Node, NodeType
from mega.filesystem import UserFileSystem
from mega.utils import random_id, random_u32int_array, str_utc_now

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable

_FOLDERS = (
    "assets",
    "bin",
    "config",
    "data",
    "docs",
    "images",
    "local",
    "logs",
    "scripts",
    "src",
    "temp",
    "tests",
    "user",
    "vendor",
)

_FILENAMES = (
    ".gitignore",
    "backup.sql",
    "config.yaml",
    "data.json",
    "docker-compose.yml",
    "index.html",
    "logo.png",
    "main.py",
    "notes.txt",
    "README.md",
    "script.js",
    "setup.sh",
    "styles.css",
    "utils.py",
)


master_key = random_u32int_array(4)

_POSIX_ROOT = PurePosixPath("/")
_E_NODE_PATHS = {
    NodeType.ROOT_FOLDER: _POSIX_ROOT / "Cloud Drive",
    NodeType.INBOX: _POSIX_ROOT / "Inbox",
    NodeType.TRASH: _POSIX_ROOT / "Trash Bin",
}


def generate_paths(
    root_name: PurePosixPath | str = "",
    *,
    max_depth: int = 3,
    min_items_per_dir: int = 1,
    max_items_per_dir: int = 5,
) -> Generator[PurePosixPath]:
    root_path = _POSIX_ROOT / root_name

    def built_tree(current_path: PurePosixPath, depth: int) -> Generator[PurePosixPath]:
        num_children = random.randint(min_items_per_dir, max_items_per_dir)
        here: set[str] = set()
        threshold = random.random()
        while len(here) < num_children:
            is_file = random.random() < threshold
            name = random.choice(_FILENAMES if is_file else _FOLDERS)

            if name not in here:
                new_path = current_path / name
                yield new_path
                here.add(name)

                if not is_file and depth < max_depth:
                    yield from built_tree(new_path, depth + 1)

    yield from built_tree(root_path, 0)


def create_node(name: str, parent_id: str) -> Node:
    owner = "me"
    random_key = random_u32int_array(6)
    key, iv = random_key[:4], random_key[4:]
    meta_mac = (0, 0)
    type_ = NodeType.FOLDER if name in _FOLDERS else NodeType.FILE
    crypto = Crypto.compose(key, iv, meta_mac, type_)
    attris = Attributes(name, random.choice(_LABELS), random.choice((True, False)))
    encrypted_key = a32_to_base64(encrypt_key(key, master_key))

    return Node(
        id=random_id(8),
        parent_id=parent_id,
        owner="me",
        type=type_,
        attributes=attris,
        created_at=int(time.time()),
        keys=MappingProxyType({owner: encrypted_key}),
        share_owner=None,
        share_key=None,
        _a=b64_url_encode(encrypt_attr(attris.serialize(), key)),
        _crypto=crypto,
    )


def s_node(node_type: NodeType) -> tuple[PurePosixPath, Node]:
    name = _E_NODE_PATHS[node_type].name
    attributes = Attributes(name)

    path = _POSIX_ROOT if node_type is NodeType.ROOT_FOLDER else _E_NODE_PATHS[node_type]

    return path, dataclasses.replace(
        create_node("", ""),
        attributes=attributes,
        _a="",
        keys=MappingProxyType({}),
        type=node_type,
        _crypto=None,
    )


def generate_nodes(paths: Iterable[PurePosixPath]) -> list[Node]:
    map = dict(s_node(t) for t in _E_NODE_PATHS)

    for path in sorted(paths, key=lambda x: str(x).casefold()):
        if path in map:
            continue
        parent_id = map[path.parent].id
        map[path] = create_node(path.name, parent_id)

    return list(map.values())


def generate_random_fs() -> UserFileSystem:
    paths = generate_paths()
    deleted = generate_paths("Trash Bin", max_depth=2, max_items_per_dir=3)

    return fs_from_paths(itertools.chain(paths, deleted))


def fs_from_paths(nodes_map: Iterable[PurePosixPath | str]) -> UserFileSystem:
    return UserFileSystem.build(generate_nodes(_POSIX_ROOT / v for v in nodes_map))


if __name__ == "__main__":
    fs = generate_random_fs()
    pprint(fs)  # noqa: T203
    out = Path(__file__).parent.parent / "tests" / f"fake_fs_{str_utc_now()}.json"
    print(f"Writing filesystem to '{out!s}'")  # noqa: T201
    dump = fs.dump()

    del dump["inv_paths"]
    del dump["children"]

    out.write_text(json.dumps(dump, indent=2, ensure_ascii=False))
