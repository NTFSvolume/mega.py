"""
Mega API information
=====================

- This file contains definitions for some of the properties within the API.
- Some definitions are not used by mega.py
- The aim of the file is that more people will contribute through understanding.

"""

from __future__ import annotations

from collections.abc import Sequence
from enum import IntEnum
from typing import TYPE_CHECKING, Any, Generic, Literal, NamedTuple, TypeAlias, TypedDict, TypeVar

if TYPE_CHECKING:
    from typing_extensions import NotRequired

U32Int: TypeAlias = int
TupleArray: TypeAlias = tuple[U32Int, ...]
ListArray: TypeAlias = list[U32Int]
Array: TypeAlias = TupleArray | ListArray
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


if TYPE_CHECKING:
    _N = TypeVar("_N", bound=NodeType)

    class Node(TypedDict, Generic[_N]):
        h: str  # Id
        p: str  # Parent Id
        u: str  # User Id
        t: _N
        a: str  # Encrypted attributes (within this: 'n' Name)
        ts: int  # Timestamp

        #  Non standard properties, only used internally by mega.py
        attributes: Attributes  # Decrypted attributes

    class _FileOrFolder(Node, Generic[_N]):
        k: str  # Node key
        su: NotRequired[str]  # Shared user Id, only present present in shared files / folder
        sk: NotRequired[str]  # Shared key, only present present in shared (public) files / folder

        #  Non standard properties, only used internally by mega.py
        iv: TupleArray
        meta_mac: TupleArray
        k_decrypted: TupleArray
        sk_decrypted: TupleArray
        full_key: TupleArray  # Decrypted access key (for folders, its values if the same as 'k_decrypted')

    class File(_FileOrFolder[Literal[NodeType.FILE]]):
        s: int  # size
        fa: str  # file attributes

    class Folder(_FileOrFolder[Literal[NodeType.FOLDER]]): ...

    class PublicFile(File):
        g: str  # direct download URL

    class FolderResponse(_FileOrFolder):
        f: list[Node]
        ok: list[File | Folder]
        s: list[File | Folder]

    NodesMap = dict[str, Node]  # key is parent_id ('p')
    SharedKeys = dict[str, TupleArray]  # Mapping: (recipient) User Id ('u') -> decrypted value of shared key ('sk')
    SharedKeysMap = dict[str, SharedKeys]  # Mapping: (owner) Shared User Id ('su') -> SharedKey


class StorageUsage(NamedTuple):
    used: int
    total: int


class User(TypedDict):
    user: str  # User handle
    uh: str  # Password hash
    mfa: str  # Multi-Factor Authentication key
    csid: str  # Session Id
    privk: str  # Private Key
    k: str  # Master key
    tsid: str  # Temp session Id
    u: str  # User Id
    ach: int  # <UNKNOWN>


class Upload(TypedDict):
    s: int  # Size
    p: str  # URL


class StorageMetrics(NamedTuple):
    bytes_used: int
    files_count: int
    folders_count: int


class AccountInformation(TypedDict):
    mstrg: int  # Total Quota
    cstrg: int  # Used Quota
    cstrgn: dict[str, StorageMetrics]  # Metrics Serialized, Mapping of node_id > Storage metrics(tuple)
