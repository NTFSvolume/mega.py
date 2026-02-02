"""
Mega API information
=====================

- This file contains definitions for some of the properties within the API.
- Some definitions are not used by mega.py
- The aim of the file is that more people will contribute through understanding.

"""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence
from enum import IntEnum
from typing import TYPE_CHECKING, Any, Literal, NamedTuple, TypeAlias, TypedDict

from typing_extensions import ReadOnly

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


class NodeType(IntEnum):
    DUMMY = -1
    FILE = 0
    FOLDER = 1
    ROOT_FOLDER = 2
    INBOX = 3
    TRASH = 4


class NodeSerialized(TypedDict):
    h: str  # ID
    p: str  # Parent ID
    u: str  # Wwner
    t: ReadOnly[NodeType]
    a: str  # Serialized  attributes
    ts: int  # Timestamp (creation date)

    k: NotRequired[str]  # Node keys
    su: NotRequired[str]  # Shared user Id, only present present in shared (public) files / folder
    sk: NotRequired[str]  # Shared key, only present present in shared (public) files / folder


class FileSerialized(NodeSerialized):
    t: ReadOnly[Literal[NodeType.FILE]]
    s: int  # Size
    fa: str  # Serialized file attributes
    g: NotRequired[str]  # Direct download URL


class FolderSerialized(NodeSerialized):
    t: ReadOnly[Literal[NodeType.FOLDER]]


class ShareKeySerialized(TypedDict):
    h: str
    k: str
    ha: str  # ???


class ShareKeySerialized2(TypedDict):
    h: str
    u: str
    r: int
    ts: int


class GetNodesResponse(TypedDict):
    f: list[NodeSerialized]
    ok: list[ShareKeySerialized]
    s: list[ShareKeySerialized2]


@dataclasses.dataclass(slots=True, order=True)
class Node:
    id: str
    parent_id: str
    owner: str
    type: NodeType
    attributes: Attributes
    creation_date: int
    keys: dict[str, str]
    share_id: str | None
    share_key: str | None

    _a: str
    _crypto: Crypto | None = None


@dataclasses.dataclass(slots=True, order=True, frozen=True)
class Attributes:
    name: str
    size: int | None = None


@dataclasses.dataclass(slots=True, order=True, frozen=True)
class Crypto:
    key: tuple[int, int, int, int, int, int, int, int]
    iv: tuple[int, int, int, int]
    meta_mac: tuple[int, int]

    full_key: tuple[int, int, int, int]
    share_key: TupleArray | None


SharedKeys = dict[str, TupleArray]  # Mapping: (recipient) User Id ('u') -> decrypted value of shared key ('sk')


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
