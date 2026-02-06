import dataclasses
import errno
from collections.abc import Generator, Iterable, Iterator, Sequence
from os import PathLike
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any, Self

from mega.data_structures import Node, NodeID, NodeType, _DictDumper
from mega.errors import MultipleNodesFoundError

_POSIX_ROOT = PurePosixPath("/")


@dataclasses.dataclass(slots=True, frozen=True, weakref_slot=True)
class FileSystem(_DictDumper):
    """A read-only representation of the Mega.nz's filesystem

    NOTE: Mega's filesystem is **not POSIX-compliant**: multiple nodes may have the same path"""

    root: Node | None
    inbox: Node | None
    trash_bin: Node | None

    file_count: int
    folder_count: int

    _nodes: MappingProxyType[NodeID, Node] = dataclasses.field(repr=False)
    _children: MappingProxyType[NodeID, tuple[NodeID, ...]] = dataclasses.field(repr=False)
    _paths: MappingProxyType[NodeID, PurePosixPath] = dataclasses.field(repr=False)
    _inv_paths: MappingProxyType[PurePosixPath, tuple[NodeID, ...]] = dataclasses.field(repr=False)

    @classmethod
    def build(cls, nodes: Sequence[Node]) -> Self:
        # This is really expensive
        # We do 5 loops over all nodes:
        # - 1. Create a map to all of them
        # - 2. Resolve their paths
        # - 3. Sort their paths
        # - 4. Freeze children (list -> tuple)
        # - 5. Freeze inv paths (list -> tuple)

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

        paths: dict[NodeID, PurePosixPath] = {}
        inv_paths: dict[PurePosixPath, tuple[NodeID, ...]] = {}
        inv_paths_temp: dict[PurePosixPath, list[NodeID]] = {}

        self = cls(
            root,
            inbox,
            trash_bin,
            file_count,
            folder_count,
            MappingProxyType(nodes_map),
            MappingProxyType({node_id: tuple(nodes) for node_id, nodes in children.items()}),
            MappingProxyType(paths),
            MappingProxyType(inv_paths),
        )

        roots = list(filter(None, (root, inbox, trash_bin))) or [nodes[0]]

        for node_id, path in sorted(self._resolve_paths(*roots), key=lambda x: str(x[1]).casefold()):
            paths[node_id] = path
            inv_paths_temp.setdefault(path, []).append(node_id)

        inv_paths.update((path, tuple(nodes)) for path, nodes in inv_paths_temp.items())

        return self

    def __len__(self) -> int:
        return len(self._nodes)

    def __iter__(self) -> Iterator[Node]:
        return iter(self._nodes.values())

    def __contains__(self, item: object) -> bool:
        return item in self._nodes

    def __getitem__(self, node_id: NodeID) -> Node:
        """Get the node with this ID"""
        return self._nodes[node_id]

    def _was_deleted(self, node: Node) -> bool:
        return node.parent_id == self.trash_bin.id if self.trash_bin else False

    @property
    def nodes(self) -> MappingProxyType[NodeID, Node]:
        """A mapping of every node"""
        return self._nodes

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
    def children(self) -> MappingProxyType[NodeID, tuple[NodeID, ...]]:
        """A mapping of nodes to their inmediate children"""

        return self._children

    @property
    def files(self) -> Iterable[Node]:
        """All files that are NOT deleted"""
        for node in self:
            if node.type is NodeType.FILE and not self._was_deleted(node):
                yield node

    @property
    def folders(self) -> Iterable[Node]:
        """All folders that are NOT deleted"""
        for node in self:
            if node.type is NodeType.FOLDER and not self._was_deleted(node):
                yield node

    @property
    def deleted(self) -> Iterable[Node]:
        """All files or folders currently on the trash bin"""
        if self.trash_bin:
            yield from self.iterdir(self.trash_bin.id)

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

            if exclude_deleted and self._was_deleted(self[node_id]):
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
            msg = f"A node with '{path =}' does not exists"
            raise FileNotFoundError(errno.ENOENT, msg) from None
        else:
            if len(nodes) > 1:
                msg = f"There is more that one node with '{path =}'"
                raise MultipleNodesFoundError(msg, nodes)

            assert nodes
            return self[nodes[0]]

    def iterdir(self, node_id: NodeID, *, recursive: bool = False) -> Iterable[Node]:
        """Iterate over the children in this node"""
        for child_id in self._ls(node_id, recursive=recursive):
            yield self[child_id]

    def listdir(self, node_id: NodeID) -> list[Node]:
        """Get a list of children of this node (non recursive)"""
        return list(self.iterdir(node_id))

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

    def dump(self) -> dict[str, Any]:
        """Get a JSONable dict representation of this object"""
        return dict(  # noqa: C408
            root=self.root.dump() if self.root else None,
            inbox=self.inbox.dump() if self.inbox else None,
            trash_bin=self.trash_bin.dump() if self.trash_bin else None,
            file_count=self.file_count,
            folder_count=self.folder_count,
            nodes={node_id: node.dump() for node_id, node in self._nodes.items()},
            paths={node_id: str(path) for node_id, path in self._paths.items()},
            inv_paths={str(path): node_id for path, node_id in self._inv_paths.items()},
            children=dict(self._children),
        )

    @classmethod
    def from_dump(cls, dump: dict[str, Any], /) -> Self:
        return cls.build([Node.from_dump(node) for node in dump["nodes"].values()])

    def _ls(self, node_id: NodeID, *, recursive: bool) -> Iterable[NodeID]:
        """Get ID of every child of this node"""
        for child_id in self._children.get(node_id, ()):
            yield child_id
            if recursive:
                yield from self._ls(child_id, recursive=recursive)

    def _resolve_paths(self, *roots: Node) -> Generator[tuple[NodeID, PurePosixPath]]:
        def walk(parent_id: str, current_path: PurePosixPath):
            for node in self.iterdir(parent_id):
                node_path = current_path / node.attributes.name
                yield node.id, node_path

                if node.type is not NodeType.FILE:
                    yield from walk(node.id, node_path)

        for node in roots:
            name = node.attributes.name
            path = _POSIX_ROOT if node.type is NodeType.ROOT_FOLDER else _POSIX_ROOT / name
            yield node.id, path
            yield from walk(node.id, path)


@dataclasses.dataclass(slots=True, frozen=True, weakref_slot=True)
class UserFileSystem(FileSystem):
    root: Node
    inbox: Node
    trash_bin: Node
