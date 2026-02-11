from __future__ import annotations

import json
from pathlib import Path, PurePosixPath

import pytest

from mega.data_structures import Node
from mega.errors import MultipleNodesFoundError
from mega.filesystem import _POSIX_ROOT, UserFileSystem

NODE_ID = "0fPFklV3"
FIND_NODE_ID = "0fPFklV3"
DELETED_NODE_IDS = "t8HkzBH2", "8EwHVJna"
TEST_FS = Path(__file__).parent / "fake_fs.json"


@pytest.fixture(name="fs")
async def filesystem() -> UserFileSystem:
    path = Path(__file__).parent / "fake_fs.json"
    return UserFileSystem.from_dump(json.loads(path.read_text()))


def test_filesystem_has_root(fs: UserFileSystem) -> None:
    assert isinstance(fs, UserFileSystem)
    assert fs.root
    assert fs.inbox
    assert fs.trash_bin


def test_magic_methods(fs: UserFileSystem) -> None:
    assert len(fs) == 20
    assert len(fs) == fs.file_count + fs.folder_count + 3
    assert isinstance(next(iter(fs)), Node)
    node = fs[NODE_ID]
    assert isinstance(node, Node)
    assert node.id == NODE_ID
    assert node.id in fs
    assert node not in fs


def test_deleted(fs: UserFileSystem) -> None:
    deleted = set(fs.deleted)
    assert deleted == {fs[DELETED_NODE_IDS[0]]}
    all_deleted = set(fs.iterdir(fs.trash_bin.id, recursive=True))
    assert all_deleted == {
        fs[DELETED_NODE_IDS[0]],
        fs[DELETED_NODE_IDS[1]],
    }


def test_path_resolve(fs: UserFileSystem) -> None:
    path = "tests/scripts/script.js"
    rel_path = PurePosixPath(path)
    node = fs.find(path)
    assert node is fs.find(rel_path)
    assert fs.relative_path(node.id) == rel_path
    assert fs.absolute_path(node.id) == _POSIX_ROOT / rel_path


def test_search(fs: UserFileSystem) -> None:
    query = "tests/script"
    results = dict(fs.search(query))
    expected = (
        "/tests/script.js",
        "/tests/scripts",
        "/tests/scripts/notes.txt",
        "/tests/scripts/script.js",
        "/tests/scripts/styles.css",
    )

    assert sorted(results.values()) == sorted(PurePosixPath(v) for v in expected)


def test_search_exclude_deleted(fs: UserFileSystem) -> None:
    results = dict(fs.search("/"))
    assert len(results) == 18
    results = dict(fs.search("/", exclude_deleted=False))
    assert len(results) == 20


def test_find(fs: UserFileSystem) -> None:
    node = fs.find("/tests/scripts/notes.txt")
    assert node is fs[FIND_NODE_ID]

    with pytest.raises(FileNotFoundError):
        fs.find("/this/path/does/not/exists")

    with pytest.raises(FileNotFoundError):
        fs.find("/tests/script")

    with pytest.raises(MultipleNodesFoundError):
        fs.find("/tests/logo.png")


def test_iter_dir(fs: UserFileSystem) -> None:
    children = (
        "/tests/logo.png",
        "/tests/logo.png",
        "/tests/script.js",
        "/tests/scripts",
        "/tests/setup.sh",
        "/tests/utils.py",
    )

    recursive_children = (
        *children,
        "/tests/scripts/notes.txt",
        "/tests/scripts/script.js",
        "/tests/scripts/styles.css",
    )

    node = fs.find("/tests")

    def get_path(recursive: bool) -> list[str]:
        return sorted(str(fs.absolute_path(n.id)) for n in fs.iterdir(node.id, recursive=recursive))

    assert get_path(recursive=False) == sorted(children)
    assert get_path(recursive=True) == sorted(recursive_children)


def test_unsafe_filesystem_build() -> None:
    dump = json.loads(TEST_FS.read_text())
    nodes = (Node.from_dump(node) for node in dump["nodes"].values())
    UserFileSystem.build_unsafe(nodes)


def test_safe_filesystem_build() -> None:
    dump = json.loads(TEST_FS.read_text())
    nodes = (Node.from_dump(node) for node in dump["nodes"].values())
    fs = UserFileSystem.build(nodes)
    TEST_FS.write_text(json.dumps(fs.dump(), indent=2, ensure_ascii=False) + "\n")
