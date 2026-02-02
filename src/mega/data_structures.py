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
from typing import TYPE_CHECKING, Any, ClassVar, Literal, NamedTuple, Self, TypeAlias, TypedDict

if TYPE_CHECKING:
    from typing import NotRequired

    from typing_extensions import ReadOnly

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
    u: str  # Owner (user ID)
    t: ReadOnly[NodeType]
    a: str  # Serialized attributes
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
    h: str  # ID of node for this key
    k: str  # key
    ha: str  # ???


class ShareKeySerialized2(TypedDict):
    h: str  # ID of node for this key
    u: str  # Owner (user ID)
    r: int
    ts: int  # timestamp


class GetNodesResponse(TypedDict):
    f: list[NodeSerialized]
    ok: list[ShareKeySerialized]
    s: list[ShareKeySerialized2]


class GetNodeResponse(TypedDict):
    s: int
    at: str
    fa: str  # file attributes (thumb, audio or video)
    g: NotRequired[str]  # direct download URL


@dataclasses.dataclass(slots=True, order=True, frozen=True, weakref_slot=True)
class File:
    name: str
    size: int
    url: str | None


@dataclasses.dataclass(slots=True, order=True, frozen=True, weakref_slot=True)
class Node:
    id: str
    parent_id: str
    owner: str
    type: NodeType
    attributes: Attributes
    creation_date: int
    keys: dict[str, str]
    share_owner: str | None
    share_key: str | None

    _a: str
    _crypto: Crypto | None = None


@dataclasses.dataclass(slots=True, order=True, frozen=True, weakref_slot=True)
class Attributes:
    name: str
    label: str = ""
    favorited: bool = False

    @classmethod
    def parse(cls, attrs: dict[str, Any]) -> Self:
        labels = ["", "red", "orange", "yellow", "green", "blue", "purple", "grey"]
        return cls(
            name=attrs["n"],
            label=labels[attrs.get("lbl", 0)],
            favorited=bool(attrs.get("fav")),
        )


@dataclasses.dataclass(slots=True, frozen=True, weakref_slot=True)
class Crypto:
    key: tuple[int, int, int, int, int, int, int, int]
    iv: tuple[int, int, int, int]
    meta_mac: tuple[int, int]

    full_key: tuple[int, int, int, int]
    share_key: TupleArray | None


SharedKeys = dict[str, TupleArray]  # Mapping: (recipient) User Id ('u') -> decrypted value of shared key ('sk')


class Parser:
    __dataclass_fields__: ClassVar[dict[str, dataclasses.Field[Any]]]

    @classmethod
    def filter_dict(cls, data: dict[str, Any]) -> dict[str, Any]:
        fields = [f.name for f in dataclasses.fields(cls)]
        return {k: v for k, v in data.items() if k in fields}

    @classmethod
    def parse(cls, data: dict[str, Any]) -> Self:
        return cls(**cls.filter_dict(data))


@dataclasses.dataclass(slots=True, frozen=True, weakref_slot=True)
class AccountData(Parser):
    balance: tuple[float, str]
    subs: list[str]
    plans: list[str]
    storage: StorageQuota

    @classmethod
    def parse(cls, data: dict[str, Any]) -> Self:
        balance = (data.get("balance") or [[0.0, "EUR"]])[0]
        clean_data = cls.filter_dict(data)
        clean_data.update(
            {
                "storage": StorageQuota.parse(data),
                "balance": (float(balance[0]), str(balance[1])),
            }
        )
        return cls(**clean_data)


@dataclasses.dataclass(slots=True, frozen=True, weakref_slot=True)
class StorageQuota:
    used: int
    total: int

    percent: int
    is_full: bool
    is_almost_full: bool

    @classmethod
    def parse(cls, data: dict[str, Any]) -> Self:
        total, used, threshold = map(int, (data["mstrg"], data["cstrg"], data["uslw"]))
        ratio = used / total
        return cls(
            used=used,
            total=total,
            is_full=ratio >= 1,
            percent=int(ratio * 100),
            is_almost_full=ratio >= (threshold / 10000),
        )


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


class UserResponse(TypedDict, total=False):
    u: str  # user id
    since: int  # timestamp of account creation
    email: str
    emails: list[str]
    pemails: list[str]
    name: str


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
