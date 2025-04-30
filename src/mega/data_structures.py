"""
Mega API information
=====================

- This file contains definitions for some of the properties within the API.
- Some definitions are not used by mega.py
- The aim of the file is that more people will contribute through understanding.

"""

from collections.abc import Sequence
from enum import IntEnum
from typing import Any, Literal, NamedTuple, TypedDict, Union

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
    k: str  # Public access key (parent folder + file)

    #  Non standard properties, only used internally by mega.py
    attributes: Attributes  # Decrypted attributes
    k_decrypted: TupleArray
    key_decrypted: TupleArray  # Decrypted access key (for folders, its values if the same as 'k_decrypted')


class FileOrFolder(Node):
    su: NotRequired[str]  # Shared user Id, only present present in shared files / folder
    sk: NotRequired[str]  # Shared key, only present present in shared (public) files / folder

    #  Non standard properties, only used internally by mega.py
    iv: TupleArray
    meta_mac: TupleArray
    sk_decrypted: TupleArray


class File(FileOrFolder):
    at: str  # File specific attributes (encrypted)


class Folder(FileOrFolder):
    f: list[FileOrFolder]  # Children (files or folders)
    ok: list[FileOrFolder]
    s: list[FileOrFolder]


SharedKey = dict[str, TupleArray]  # Mapping: (recipient) User Id ('u') -> decrypted value of shared key ('sk')
SharedkeysDict = dict[str, SharedKey]  # Mapping: (owner) Shared User Id ('su') -> SharedKey


class StorageUsage(NamedTuple):
    used: int
    total: int


FilesMapping = dict[str, FileOrFolder]  # key is parent_id ('p')


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


# ~~~~~~~~~~~~~~~~~~~ REQUEST PARAMATERS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


class MegaRequest(TypedDict):
    a: str  # Action, AKA what the request intends to do


class MoveRequest(MegaRequest):
    n: str  # node Id
    t: str  # destination node Id


class PreLoginRequest(MegaRequest):
    a: Literal["us0"]
    user: str  # user handle (AKA email)


class PreLoginResponse(TypedDict):
    s: str  # salt
    v: int  # version
