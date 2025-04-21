from collections.abc import Sequence
from enum import IntEnum
from typing import Any, NamedTuple, TypedDict, Union

from typing_extensions import NotRequired, TypeAlias

U32Int: TypeAlias = int
TupleArray: TypeAlias = tuple[U32Int, ...]
ListArray: TypeAlias = list[U32Int]
Array: TypeAlias = Union[TupleArray, ListArray]
AnyArray: TypeAlias = Sequence[U32Int]
AnyDict: TypeAlias = dict[str, Any]


class Chunk(NamedTuple):
    offset: int
    size: int


class Attributes(TypedDict):
    n: str  # Name


class NodeType(IntEnum):
    DUMMY = -1
    FILE = 0
    FOLDER = 1
    ROOT_FOLDER = 2
    INBOX = 3
    TRASH = 4


class Node(TypedDict):
    t: NodeType
    h: str  # Id
    p: str  # Parent Id
    a: str  # Encrypted attributes (within this: 'n' Name)
    k: str  # Node key
    u: str  # User Id
    s: int  # Size
    ts: int  # Timestamp
    g: str  # Access URL

    #  Non standard properties, only used internally by mega.py
    attributes: Attributes  # Decrypted attributes


class FileOrFolder(Node):
    k: str  # Public access key (parent folder + file)
    su: NotRequired[str]  # Shared key, only present present in shared files / folder
    sk: NotRequired[str]  # Shared user Id, only present present in shared files / folder

    #  Non standard properties, only used internally by mega.py
    iv: TupleArray
    meta_mac: TupleArray
    decrypted_k: TupleArray
    decrypted_sk: TupleArray
    key: TupleArray  # Decrypted access key (unique per file)


class File(FileOrFolder):
    at: str  # File specific attributes (encrypted)


class Folder(FileOrFolder):
    f: list[FileOrFolder]  # Children (files or folders)


SharedKey = dict[str, TupleArray]  # Mapping: (recipient) User Id ('u') -> decrypted value of shared key ('sk')
SharedkeysDict = dict[str, SharedKey]  # Mapping: (owner) Shared User Id ('su') -> SharedKey


class StorageUsage(TypedDict):
    used: int
    total: int


FileOrFolderDict = dict[str, FileOrFolder]  # key is parent_id ('p')
FileOrFolderTuple = tuple[str, FileOrFolder]  # first element is parent_id ('p')
