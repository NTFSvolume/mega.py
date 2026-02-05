import asyncio
import dataclasses
from collections.abc import Iterable, Iterator, Sequence
from os import PathLike
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any, Self

from mega.data_structures import Node, NodeID, NodeType, _DictDumper


@dataclasses.dataclass(slots=True, frozen=True, weakref_slot=True)
class FileSystem(_DictDumper):
    """An read-only representation of the Mega.nz's filesystem

    NOTE: Folders can have multiple nodes with the same name"""

    root: Node | None
    inbox: Node | None
    trash_bin: Node | None

    _nodes: MappingProxyType[NodeID, Node]
    _children: MappingProxyType[NodeID, tuple[NodeID, ...]]
    _paths: MappingProxyType[NodeID, PurePosixPath]

    def __repr__(self) -> str:
        fields = ", ".join(
            f"{name}={value!r}"
            for name, value in (
                ("root", self.root),
                ("inbox", self.inbox),
                ("trash_bin", self.trash_bin),
                ("files", self.file_count),
                ("folders", self.folder_count),
                ("deleted", self.deleted_count),
            )
        )
        return f"<{type(self).__name__}>({fields})"

    @classmethod
    async def built(cls, nodes: Sequence[Node]) -> Self:
        return await asyncio.to_thread(cls._built, nodes)

    @classmethod
    def _built(cls, nodes: Sequence[Node]) -> Self:
        root = inbox = trash_bin = None

        nodes_map: dict[NodeID, Node] = {}
        children: dict[NodeID, list[NodeID]] = {}
        paths: dict[NodeID, PurePosixPath] = {}

        for node in nodes:
            nodes_map[node.id] = node
            children.setdefault(node.parent_id, []).append(node.id)
            if node.type is NodeType.ROOT_FOLDER:
                root = node
            elif node.type is NodeType.INBOX:
                inbox = node
            elif node.type is NodeType.TRASH:
                trash_bin = node

        self = cls(
            root,
            inbox,
            trash_bin,
            MappingProxyType(nodes_map),
            MappingProxyType({k: tuple(v) for k, v in children.items()}),
            MappingProxyType(paths),
        )

        roots = list(filter(None, (root, inbox, trash_bin))) or [nodes[0]]
        paths.update(self._resolve_paths(*[root.id for root in roots]))
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

    def get(self, node_id: NodeID) -> Node | None:
        """Get the node with this ID (If it exists)"""
        return self._nodes.get(node_id)

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
    def files(self) -> Iterable[Node]:
        """All files that are NOT deleted"""
        for node in self:
            if node.type is NodeType.FILE and not self._was_deleted(node):
                yield node

    @property
    def folders(self) -> Iterable[Node]:
        """All folders that are NOT deleted"""
        for node in self:
            if node.type is NodeType.FOLDER and self._was_deleted(node):
                yield node

    @property
    def deleted(self) -> Iterable[Node]:
        """All files or folders currently on the trash bin"""
        if self.trash_bin:
            yield from self.iterdir(self.trash_bin.id)

    @property
    def file_count(self) -> int:
        return sum(1 for _ in self.files)

    @property
    def folder_count(self) -> int:
        return sum(1 for _ in self.folders)

    @property
    def deleted_count(self) -> int:
        return sum(1 for _ in self.deleted)

    def resolve(self, node_id: NodeID) -> PurePosixPath:
        """Get the path of this node"""
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

    def dump(self) -> dict[str, Any]:
        """Get a JSONable dict representation of this object"""
        return dict(  # noqa: C408
            root=self.root.dump() if self.root else None,
            inbox=self.inbox.dump() if self.inbox else None,
            trash_bin=self.trash_bin.dump() if self.trash_bin else None,
            nodes={k: v.dump() for k, v in self._nodes.items()},
            paths={k: str(v) for k, v in self._paths.items()},
            children={k: list(v) for k, v in self._children.items()},
        )

    def find(self, query: str | PathLike[str]) -> Node | None:
        """Return the first node which path starts with `query`"""
        query = PurePosixPath(query).as_posix()
        for node_id, path in self.search(query):
            if path.as_posix().startswith(query):
                return self[node_id]

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

    def _ls(self, node_id: NodeID, *, recursive: bool) -> Iterable[NodeID]:
        """Get ID of every child of this node"""
        for child_id in self._children.get(node_id, ()):
            yield child_id
            if recursive:
                yield from self._ls(child_id, recursive=recursive)

    def _resolve_paths(self, *root_ids: str) -> dict[NodeID, PurePosixPath]:
        paths: dict[NodeID, PurePosixPath] = {}

        def walk(parent_id: str, current_path: PurePosixPath) -> None:
            for node in self.iterdir(parent_id):
                node_path = current_path / node.attributes.name
                paths[node.id] = node_path

                if node.type is NodeType.FOLDER:
                    walk(node.id, node_path)

        for root_id in root_ids:
            root_node = self[root_id]
            name = root_node.attributes.name
            path = PurePosixPath("." if root_node.type is NodeType.ROOT_FOLDER else name)
            paths[root_node.id] = path
            walk(root_id, path)

        return dict(sorted(paths.items(), key=lambda x: str(x[1]).casefold()))


@dataclasses.dataclass(slots=True, frozen=True, weakref_slot=True)
class UserFileSystem(FileSystem):
    root: Node
    inbox: Node
    trash_bin: Node
