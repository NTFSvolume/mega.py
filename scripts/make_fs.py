from __future__ import annotations

import dataclasses
import json
import random
import time
from pathlib import Path, PurePosixPath
from pprint import pprint
from types import MappingProxyType

from mega.crypto import a32_to_base64, b64_url_encode, encrypt_attr, encrypt_key
from mega.data_structures import _LABELS, Attributes, Crypto, Node, NodeType
from mega.filesystem import FileSystem
from mega.utils import random_id, random_u32int, random_u32int_array

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


def generate_paths(root_name: str = "", max_depth: int = 3, max_items_per_dir: int = 10) -> list[PurePosixPath]:
    root_path = PurePosixPath("/") / root_name
    paths = {root_path}

    def built_tree(current_path: PurePosixPath, depth: int) -> None:
        if depth > max_depth:
            return

        num_items = random.randint(1, max_items_per_dir)

        here: set[str] = set()

        for _ in range(num_items):
            is_file = random.random() < 0.75

            name = random.choice(_FILENAMES if is_file else _FOLDERS)

            if name not in here:
                new_path = current_path / name
                paths.add(new_path)
                here.add(name)

                if not is_file:
                    built_tree(new_path, depth + 1)

    built_tree(root_path, 0)
    return sorted(paths, key=lambda x: str(x).casefold())


def create_node(name: str, parent_id: str) -> Node:
    owner = "me"
    random_key = tuple(random_u32int() for _ in range(6))
    key, iv = random_key[:4], random_key[4:]
    meta_mac = (0, 0)
    crypto = Crypto.compose(key, iv, meta_mac)
    attris = Attributes(name, random.choice(_LABELS), random.choice((True, False)))
    encrypted_key = a32_to_base64(encrypt_key(key, master_key))

    return Node(
        id=random_id(8),
        parent_id=parent_id,
        owner="me",
        type=NodeType.FOLDER if name in _FOLDERS else NodeType.FILE,
        attributes=attris,
        created_at=int(time.time()),
        keys=MappingProxyType({owner: encrypted_key}),
        share_owner=None,
        share_key=None,
        _a=b64_url_encode(encrypt_attr(attris.serialize(), key)),
        _crypto=crypto,
    )


def generate_nodes(paths: list[PurePosixPath]) -> list[Node]:
    root = dataclasses.replace(
        create_node("", ""),
        attributes=Attributes("Cloud Drive"),
        _a="",
        keys=MappingProxyType({}),
        type=NodeType.ROOT_FOLDER,
        _crypto=None,
    )
    map = {paths[0]: root}

    for path in paths[1:]:
        parent_id = map[path.parent].id
        node = create_node(path.name, parent_id)
        map[path] = node

    return list(map.values())


if __name__ == "__main__":
    paths = generate_paths()
    fs = FileSystem.build(generate_nodes(paths))
    pprint(fs)  # noqa: T203
    out = Path(__file__).parent.parent / "tests" / "fake_fs.json"
    print(f"Writing filesystem to '{out!s}'")  # noqa: T201
    out.write_text(json.dumps(fs.dump(), indent=2, ensure_ascii=False))
