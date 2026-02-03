from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path, PurePosixPath
from typing import TypeAlias

from mega.data_structures import Node, NodeType

NodeID: TypeAlias = str


class FileSystem:
    """An abstract representaion of the MegaNZ's filesystem"""

    root: Node
    inbox: Node
    trash_bin: Node

    def __init__(self, nodes: Sequence[Node]) -> None:
        self.root, self.inbox, self.trash_bin, *nodes = nodes

        nodes_map: dict[NodeID, Node] = {}
        children: dict[NodeID, list[NodeID]] = {}

        for node in nodes:
            nodes_map[node.id] = node
            children.setdefault(node.parent_id, []).append(node.id)

        self._nodes: dict[NodeID, Node] = nodes_map
        self._children: dict[NodeID, list[NodeID]] = children
        self._paths: dict[NodeID, PurePosixPath] = self._build_fs_paths(self.root.id, self.inbox.id, self.trash_bin.id)

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

    def _was_deleted(self, node: Node) -> bool:
        return node.parent_id == self.trash_bin.id

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
        return self.ls_dir(self.trash_bin.id)

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

    def search(self, query: Path | str, *, exclude_deleted: bool = True) -> Iterable[Node]:
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
            yield node

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
