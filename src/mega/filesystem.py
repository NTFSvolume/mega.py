"""A read-only representation of the Mega.nz's filesystem

NOTE: Mega's filesystem is **not POSIX-compliant**: multiple nodes may have the same path"""

from __future__ import annotations

import dataclasses
import errno
from collections.abc import Generator
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, NamedTuple, Self

from mega.data_structures import Node, NodeID, NodeType, _DictDumper
from mega.errors import MultipleNodesFoundError

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable, Iterator, Sequence
    from os import PathLike

_POSIX_ROOT = PurePosixPath("/")


class NodeLookup(NamedTuple):
    node_id: NodeID
    path: PurePosixPath
    was_deleted: bool


def _resolve_paths(walker: NodeWalker, *roots: Node) -> Generator[NodeLookup]:
    def walk(node_id: str, current_path: PurePosixPath) -> Generator[tuple[NodeID, PurePosixPath]]:
        for node in walker.iterdir(node_id):
            node_path = current_path / node.attributes.name
            yield node.id, node_path

            if node.type is not NodeType.FILE:
                yield from walk(node.id, node_path)

    for root in roots:
        name = root.attributes.name
        path = _POSIX_ROOT if root.type is NodeType.ROOT_FOLDER else _POSIX_ROOT / name

        yield NodeLookup(root.id, path, False)
        deleted = root.type is NodeType.TRASH
        for child_id, child_path in walk(root.id, path):
            yield NodeLookup(child_id, child_path, deleted)


@dataclasses.dataclass(slots=True, frozen=True, kw_only=True, weakref_slot=True)
class NodeWalker:
    _nodes: MappingProxyType[NodeID, Node] = dataclasses.field(repr=False)
    _children: MappingProxyType[NodeID, tuple[NodeID, ...]] = dataclasses.field(repr=False)

    def _ls(self, node_id: NodeID, *, recursive: bool) -> Iterable[NodeID]:
        """Get ID of every child of this node"""
        for child_id in self._children.get(node_id, ()):
            yield child_id
            if recursive:
                yield from self._ls(child_id, recursive=recursive)

    def iterdir(self, node_id: NodeID, *, recursive: bool = False) -> Iterable[Node]:
        """Iterate over the children in this node"""
        for child_id in self._ls(node_id, recursive=recursive):
            yield self._nodes[child_id]

    def listdir(self, node_id: NodeID) -> list[Node]:
        """Get a list of children of this node (non recursive)"""
        return list(self.iterdir(node_id))


@dataclasses.dataclass(slots=True, frozen=True, kw_only=True, weakref_slot=True)
class SimpleFileSystem(NodeWalker, _DictDumper):
    """A simple representation of Mega.nz's file system.

    Supports lookups and traversal of nodes by node ID.
    """

    root: Node | None
    inbox: Node | None
    trash_bin: Node | None

    file_count: int
    folder_count: int

    def __len__(self) -> int:
        return len(self.nodes)

    def __iter__(self) -> Iterator[Node]:
        return iter(self.nodes.values())

    def __contains__(self, item: object) -> bool:
        return item in self.nodes

    def __getitem__(self, node_id: NodeID) -> Node:
        """Get the node with this ID"""
        return self.nodes[node_id]

    @property
    def nodes(self) -> MappingProxyType[NodeID, Node]:
        """A mapping of every node"""
        return self._nodes

    @property
    def children(self) -> MappingProxyType[NodeID, tuple[NodeID, ...]]:
        """A mapping of nodes to their inmediate children"""
        return self._children

    @classmethod
    def build(cls, nodes: Sequence[Node]) -> Self:
        root = inbox = trash_bin = None
        file_count = folder_count = 0

        nodes_map: dict[NodeID, Node] = {}
        children: dict[NodeID, list[NodeID]] = {}

        for node in nodes:
            nodes_map[node.id] = node
            children.setdefault(node.parent_id, []).append(node.id)
            match node.type:
                case NodeType.FILE:
                    file_count += 1
                case NodeType.FOLDER:
                    folder_count += 1
                case NodeType.ROOT_FOLDER:
                    root = node
                case NodeType.INBOX:
                    inbox = node
                case NodeType.TRASH:
                    trash_bin = node
                case _:
                    raise RuntimeError

        return cls(
            root=root,
            inbox=inbox,
            trash_bin=trash_bin,
            file_count=file_count,
            folder_count=folder_count,
            _nodes=MappingProxyType(nodes_map),
            _children=MappingProxyType({node_id: tuple(nodes) for node_id, nodes in children.items()}),
        )

    def dump(self) -> dict[str, Any]:
        """Get a JSONable dict representation of this object"""
        return dict(  # noqa: C408
            file_count=self.file_count,
            folder_count=self.folder_count,
            root=self.root.dump() if self.root else None,
            inbox=self.inbox.dump() if self.inbox else None,
            trash_bin=self.trash_bin.dump() if self.trash_bin else None,
            nodes={node_id: node.dump() for node_id, node in self.nodes.items()},
        )


@dataclasses.dataclass(slots=True, frozen=True, kw_only=True, weakref_slot=True)
class FileSystem(SimpleFileSystem):
    """Mega.nz's file system.

    - Supports lookups and traversal of nodes by node ID.
    - Supports lookups and traversal of nodes by their paths.

    NOTE: Mega's filesystem is **not POSIX-compliant**: multiple nodes may have the same path
    """

    _paths: MappingProxyType[NodeID, PurePosixPath] = dataclasses.field(repr=False)
    _inv_paths: MappingProxyType[PurePosixPath, tuple[NodeID, ...]] = dataclasses.field(repr=False)
    _deleted: frozenset[NodeID] = dataclasses.field(repr=False)

    @classmethod
    def build(cls, nodes: Sequence[Node]) -> Self:
        # This is really expensive
        # We do 5 loops over all nodes:
        # SimpleFileSystem:
        # - 1. Create a map to all nodes
        # - 2. Freeze children (list -> tuple)
        #
        # FileSystem:
        # - 3. Resolve their paths
        # - 4. Sort their paths
        # - 5. Freeze inv paths (list -> tuple)

        self = SimpleFileSystem.build(nodes)

        roots = list(filter(None, (self.root, self.inbox, self.trash_bin))) or [nodes[0]]
        paths: dict[NodeID, PurePosixPath] = {}
        inv_paths: dict[PurePosixPath, list[NodeID]] = {}
        deleted_ids: set[NodeID] = set()

        for node_id, path, was_deleted in sorted(_resolve_paths(self, *roots), key=lambda x: str(x[1]).casefold()):
            paths[node_id] = path
            inv_paths.setdefault(path, []).append(node_id)
            if was_deleted:
                deleted_ids.add(node_id)

        return cls(
            root=self.root,
            inbox=self.inbox,
            trash_bin=self.trash_bin,
            file_count=self.file_count,
            folder_count=self.folder_count,
            _nodes=self.nodes,
            _children=self.children,
            _paths=MappingProxyType(paths),
            _inv_paths=MappingProxyType({path: tuple(nodes) for path, nodes in inv_paths.items()}),
            _deleted=frozenset(deleted_ids),
        )

    @property
    def paths(self) -> MappingProxyType[NodeID, PurePosixPath]:
        """A mapping of every node to its absolute path within the filesystem"""
        return self._paths

    @property
    def inv_paths(self) -> MappingProxyType[PurePosixPath, tuple[NodeID, ...]]:
        """A mapping of paths to every node located at that path

        Mega's filesystem is **not POSIX-compliant**: multiple nodes may have the same path"""
        return self._inv_paths

    @property
    def files(self) -> Iterable[Node]:
        """All files that are NOT deleted (recursive)"""

        for node in self:
            if node.type is NodeType.FILE and not self._deleted:
                yield node

    @property
    def folders(self) -> Iterable[Node]:
        """All folders that are NOT deleted (recursive)"""

        for node in self:
            if node.type is NodeType.FOLDER and node.id not in self._deleted:
                yield node

    @property
    def deleted(self) -> Iterable[Node]:
        """All files or folders currently on the trash bin (Non recursive)"""
        if self.trash_bin:
            yield from self.iterdir(self.trash_bin.id)

    def dirmap(self, node_id: str, *, recursive: bool = False) -> dict[NodeID, PurePosixPath]:
        """Creates a mapping from `node id` -> `Path` only including children of this node"""

        pairs = (
            (child_id, self.resolve(child_id))
            for child_id in self._ls(
                node_id,
                recursive=recursive,
            )
        )
        return dict(sorted(pairs, key=lambda x: str(x[1]).casefold()))

    def relative_path(self, node_id: NodeID) -> PurePosixPath:
        """Get the path of this node relative to the root folder"""
        return self._paths[node_id].relative_to(_POSIX_ROOT)

    def resolve(self, node_id: NodeID) -> PurePosixPath:
        """Get the absolute path of this node"""
        return self._paths[node_id]

    def search(
        self, query: str | PathLike[str], *, exclude_deleted: bool = True
    ) -> Iterable[tuple[NodeID, PurePosixPath]]:
        """Returns nodes that have "query" as a substring on their path"""

        query = PurePosixPath(query).as_posix()

        for node_id, path in self._paths.items():
            if query not in path.as_posix():
                continue

            if exclude_deleted and node_id in self._deleted:
                continue

            yield node_id, path

    def find(self, path: str | PathLike[str]) -> Node:
        """Return the single node located at *path*.

        NOTE: Mega's filesystem is **not POSIX-compliant**: multiple nodes may have the same path

        Raises `MultipleNodesFoundError` if more that one node has this path

        Raises `FileNotFoundError` if this path does not exists on the filesystem

        """
        path = _POSIX_ROOT / PurePosixPath(path)
        try:
            nodes = self._inv_paths[path]
        except LookupError:
            msg = f"A node with '{path = !s}' does not exists"
            raise FileNotFoundError(errno.ENOENT, msg) from None
        else:
            if len(nodes) > 1:
                msg = f"There is more that one node with '{path = !s}'"
                raise MultipleNodesFoundError(msg, nodes)

            assert nodes
            return self[nodes[0]]

    def dump(self, *, simple: bool = False) -> dict[str, Any]:
        """Get a JSONable dict representation of this object"""
        dump = super(FileSystem, self).dump()
        if simple:
            return dump

        return dump | dict(  # noqa: C408
            deleted=sorted(self._deleted),
            paths={node_id: str(path) for node_id, path in self._paths.items()},
            inv_paths={str(path): node_id for path, node_id in self._inv_paths.items()},
            children=dict(self.children),
        )

    @classmethod
    def from_dump(cls, dump: dict[str, Any], /) -> Self:
        return cls.build([Node.from_dump(node) for node in dump["nodes"].values()])


@dataclasses.dataclass(slots=True, frozen=True, weakref_slot=True)
class UserFileSystem(FileSystem):
    root: Node
    inbox: Node
    trash_bin: Node
