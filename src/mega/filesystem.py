import asyncio
import dataclasses
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Self

from mega.data_structures import Node, NodeID, NodeType


@dataclasses.dataclass(slots=True, frozen=True, weakref_slot=True)
class FileSystem:
    """An abstract representaion of the MegaNZ's filesystem"""

    root: Node | None
    inbox: Node | None
    trash_bin: Node | None
    _nodes: MappingProxyType[NodeID, Node]
    _children: MappingProxyType[NodeID, list[NodeID]]
    _paths: MappingProxyType[NodeID, PurePosixPath]

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
            MappingProxyType(children),
            MappingProxyType(paths),
        )

        roots = list(filter(None, (root, inbox, trash_bin))) or [next(iter(nodes))]
        paths.update(self._build_fs_paths(*[root.id for root in roots]))
        return self

    @classmethod
    async def built(cls, nodes: Sequence[Node]) -> Self:
        return await asyncio.to_thread(cls._built, nodes)

    def __repr__(self) -> str:
        text = ",".join(
            f"{name}={value!r}"
            for (name, value) in (
                ("root", self.root),
                ("inbox", self.inbox),
                ("trash_bin", self.trash_bin),
                ("files", self.file_count),
                ("folders", self.folder_count),
                ("deleted", self.deleted_count),
            )
        )
        return f"<{type(self).__name__}>({text})"

    def __len__(self) -> int:
        return len(self._nodes)

    def __iter__(self) -> Iterator[Node]:
        return iter(self._nodes.values())

    def __getitem__(self, node_id: NodeID) -> Node:
        return self._nodes[node_id]

    def get(self, node_id: NodeID) -> Node | None:
        return self._nodes.get(node_id)

    def _was_deleted(self, node: Node) -> bool:
        return node.parent_id == self.trash_bin.id if self.trash_bin else False

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
            yield from self.ls_dir(self.trash_bin.id)

    @property
    def file_count(self) -> int:
        return len(tuple(self.files))

    @property
    def folder_count(self) -> int:
        return len(tuple(self.folders))

    @property
    def deleted_count(self) -> int:
        return len(tuple(self.deleted))

    def ls_dir(self, node_id: NodeID) -> Iterable[Node]:
        """Get childs of this node (non resursive)"""
        for child_id in self._children.get(node_id, []):
            yield self[child_id]

    def resolve(self, node_id: NodeID) -> PurePosixPath:
        """Get the path of this node"""
        return self._paths[node_id]

    def search(self, query: Path | str, *, exclude_deleted: bool = True) -> Iterable[tuple[Node, PurePosixPath]]:
        """
        Returns nodes that have "query" as a substring on their path
        """

        query = PurePosixPath(query).as_posix()

        for node_id, path in self._paths.items():
            if query not in path.as_posix():
                continue
            node = self[node_id]
            if exclude_deleted and self._was_deleted(node):
                continue
            yield node, path

    def _build_fs_paths(self, *root_ids: str) -> dict[NodeID, PurePosixPath]:
        paths: dict[NodeID, PurePosixPath] = {}

        def walk(parent_id: str, current_path: PurePosixPath) -> None:
            for node in self.ls_dir(parent_id):
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


class UserFileSystem(FileSystem):
    root: Node
    inbox: Node
    trash_bin: Node
