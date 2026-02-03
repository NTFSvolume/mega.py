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
from typing import TYPE_CHECKING, Any, ClassVar, Final, Literal, Self, TypeAlias, TypedDict

if TYPE_CHECKING:
    from typing import NotRequired

    from typing_extensions import ReadOnly

TupleArray: TypeAlias = tuple[int, ...]
AnyArray: TypeAlias = Sequence[int]
SharedKeys = dict[str, TupleArray]  # owner (User Id) -> share keys


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


@dataclasses.dataclass(slots=True, frozen=True, weakref_slot=True)
class Crypto:
    key: tuple[int, ...]
    iv: tuple[int, int, int, int]
    meta_mac: tuple[int, int]

    full_key: tuple[int, int, int, int]
    share_key: TupleArray | None


# Dummy crypto for root/trash_bin/inbox
_NO_CRYPTO = Crypto((), (), (), (), ())  # pyright: ignore[reportArgumentType]


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
    _crypto: Crypto = _NO_CRYPTO


_LABELS: Final = "", "red", "orange", "yellow", "green", "blue", "purple", "grey"


@dataclasses.dataclass(slots=True, order=True, frozen=True, weakref_slot=True)
class Attributes:
    name: str
    label: str = ""
    favorited: bool = False

    @classmethod
    def parse(cls, attrs: dict[str, Any]) -> Self:
        return cls(
            name=attrs["n"],
            label=_LABELS[attrs.get("lbl", 0)],
            favorited=bool(attrs.get("fav")),
        )

    def dump(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in [
                ("n", self.name),
                ("lbl", _LABELS.index(self.label)),
                ("fav", self.favorited),
            ]
            if value
        }


class Parser:
    __dataclass_fields__: ClassVar[dict[str, dataclasses.Field[Any]]]

    @classmethod
    def _filter_dict(cls, data: dict[str, Any]) -> dict[str, Any]:
        fields = [f.name for f in dataclasses.fields(cls)]
        return {k: v for k, v in data.items() if k in fields}

    @classmethod
    def parse(cls, data: dict[str, Any]) -> Self:
        return cls(**cls._filter_dict(data))


@dataclasses.dataclass(slots=True, frozen=True, weakref_slot=True)
class AccountStats(Parser):
    balance: tuple[float, str]
    subs: list[str]
    plans: list[str]
    storage: StorageQuota
    metrics: dict[str, StorageMetrics]  # Mapping of node_id > Storage metrics

    @classmethod
    def parse(cls, data: dict[str, Any]) -> Self:
        balance = (data.get("balance") or [[0.0, "EUR"]])[0]

        clean_data = cls._filter_dict(data)
        clean_data.update(
            {
                "storage": StorageQuota.parse(data),
                "balance": (float(balance[0]), str(balance[1])),
                "metrics": {k: StorageMetrics(*v[0:3]) for k, v in data["cstrgn"].items()},
            }
        )
        return cls(**clean_data)


@dataclasses.dataclass(slots=True, frozen=True, weakref_slot=True)
class StorageMetrics:
    bytes_used: int
    files: int
    folders: int


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
