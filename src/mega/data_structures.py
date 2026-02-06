"""
Mega API information
=====================

- This file contains definitions for some of the properties within the API.
- TypeDict objects are the raw data returned by the http requests to the API itself.
- The dataclasses are the internal representation of thoses objects

"""

from __future__ import annotations

import dataclasses
from collections.abc import Generator, Sequence
from enum import IntEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, ClassVar, Final, Self, TypeAlias, TypedDict

if TYPE_CHECKING:
    from typing import NotRequired

    from typing_extensions import ReadOnly

NodeID: TypeAlias = str
UserID: TypeAlias = str
TimeStamp: TypeAlias = int

TupleArray: TypeAlias = tuple[int, ...]
AnyArray: TypeAlias = Sequence[int]


SharedKeys: TypeAlias = dict[UserID, tuple[int, ...]]


class ByteSize(int):
    def human_readable(self) -> str:
        """(ex: '150.5MB')"""
        scale = 1000
        me = float(self)
        for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
            if abs(me) < scale:
                if unit == "B":
                    return f"{me:0.0f}{unit}"
                return f"{me:0.1f}{unit}"
            me /= scale

        return f"{me:0.1f}EB"

    def __repr__(self) -> str:
        return self.human_readable()


class NodeType(IntEnum):
    DUMMY = -1
    FILE = 0
    FOLDER = 1
    ROOT_FOLDER = 2
    INBOX = 3
    TRASH = 4


class NodeSerialized(TypedDict):
    h: NodeID  # ID
    p: NodeID  # Parent ID
    u: UserID  # Owner (user ID)
    t: ReadOnly[NodeType]
    a: str  # Serialized attributes
    ts: TimeStamp  # creation date

    k: NotRequired[str]  # Node keys
    su: NotRequired[str]  # Share owner (user ID), only present present in shared (public) files / folder
    sk: NotRequired[str]  # Share key, only present present in shared (public) files / folder


class ShareKeySerialized(TypedDict):
    h: NodeID  # ID of node for this key
    k: str  # key
    ha: str  # ???


class ShareKeySerialized2(TypedDict):
    h: NodeID  # ID of node for this key
    u: str  # Owner (user ID)
    r: int
    ts: TimeStamp


class GetNodesResponse(TypedDict):
    f: list[NodeSerialized]
    ok: list[ShareKeySerialized]
    s: list[ShareKeySerialized2]


class AttributesSerialized(TypedDict, total=False):
    n: ReadOnly[str]  # Name
    lbl: int  # label
    fav: bool  # favorited


class FileInfoSerialized(TypedDict):
    s: int  # size
    at: str  # Serialized attributes
    fa: str  # Media file attributes (thumb, audio or video)
    g: NotRequired[str]  # direct download URL


_FIELDS_CACHE: dict[type, tuple[str, ...]] = {}


def _fields(cls: type) -> tuple[str, ...]:
    if fields := _FIELDS_CACHE.get(cls):
        return fields
    fields = _FIELDS_CACHE[cls] = tuple(f.name for f in dataclasses.fields(cls))
    return fields


class _DictDumper:
    __dataclass_fields__: ClassVar[dict[str, dataclasses.Field[Any]]]

    def dump(self) -> dict[str, Any]:
        """Get a JSONable dict representation of this object"""
        return dataclasses.asdict(self)

    def _shallow_dump(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in _fields(type(self))}


class _DictParser:
    __dataclass_fields__: ClassVar[dict[str, dataclasses.Field[Any]]]

    @classmethod
    def _filter_dict(cls, data: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in data.items() if k in _fields(cls)}

    @classmethod
    def parse(cls, data: dict[str, Any], /) -> Self:
        return cls(**cls._filter_dict(data))


@dataclasses.dataclass(slots=True, frozen=True, weakref_slot=True)
class FileInfo(_DictDumper):
    name: str
    size: ByteSize
    url: str | None

    _at: str

    @classmethod
    def parse(cls, resp: FileInfoSerialized) -> FileInfo:
        return FileInfo(
            name="",
            size=ByteSize(resp["s"]),
            url=resp.get("g"),
            _at=resp["at"],
        )


@dataclasses.dataclass(slots=True, frozen=True, weakref_slot=True)
class Crypto(_DictDumper):
    key: tuple[int, ...]
    iv: tuple[int, int]
    meta_mac: tuple[int, int]

    full_key: tuple[int, int, int, int]
    share_key: tuple[int, ...] | None

    def __iter__(self) -> Generator[tuple[int, ...]]:
        yield from dataclasses.astuple(self)

    @classmethod
    def from_dump(cls, dump: dict[str, Any]) -> Self:
        share_key = dump.pop("share_key")
        crypto = {k: tuple(v) for k, v in dump.items()}
        return cls(**crypto, share_key=tuple(share_key) if share_key else None)


# We populate attrs and crypto after instance creation
@dataclasses.dataclass(slots=True, frozen=True, order=True, weakref_slot=True)
class Node(_DictDumper):
    id: NodeID
    parent_id: NodeID
    owner: UserID
    type: NodeType
    attributes: Attributes
    created_at: TimeStamp
    keys: MappingProxyType[UserID, str]
    share_owner: UserID | None
    share_key: str | None

    _a: str
    _crypto: Crypto

    @classmethod
    def parse(cls, node: NodeSerialized) -> Node:
        if k := node.get("k"):
            keys = dict(key_pair.split(":", 1) for key_pair in k.split("/") if ":" in key_pair)
        else:
            keys = {}

        return Node(
            id=node["h"],
            parent_id=node["p"],
            owner=node["u"],
            created_at=node["ts"],
            type=NodeType(node["t"]),
            keys=MappingProxyType(keys),
            share_owner=node.get("su"),
            share_key=node.get("sk"),
            _a=node["a"],
            attributes=None,  # pyright: ignore[reportArgumentType]
            _crypto=None,  # pyright: ignore[reportArgumentType]
        )

    @classmethod
    def from_dump(cls, dump: dict[str, Any], /) -> Self:
        dump = dump | dict(  # noqa: C408
            type=NodeType[str(dump["type"]).upper()],
            attributes=Attributes(**dump["attributes"]) if dump["attributes"] else None,
            _crypto=Crypto.from_dump(dump["_crypto"]),
        )

        return cls(**dump)

    def dump(self) -> dict[str, Any]:
        """Get a JSONable dict representation of this object"""
        me = self._shallow_dump()
        me["_crypto"] = self._crypto.dump() if self._crypto else None
        me["attributes"] = self.attributes.dump() if self.attributes else {}
        me["keys"] = dict(self.keys)
        me["type"] = self.type.name.lower()
        return me


_LABELS: Final = "", "red", "orange", "yellow", "green", "blue", "purple", "grey"


@dataclasses.dataclass(slots=True, frozen=True, weakref_slot=True)
class Attributes(_DictDumper):
    name: str
    label: str = ""
    favorited: bool = False

    @classmethod
    def parse(cls, attrs: AttributesSerialized) -> Self:
        return cls(
            name=attrs.get("n", ""),
            label=_LABELS[attrs.get("lbl", 0)],
            favorited=bool(attrs.get("fav")),
        )

    def serialize(self) -> AttributesSerialized:
        return {  # pyright: ignore[reportReturnType]
            key: value
            for key, value in [
                ("n", self.name),
                ("lbl", _LABELS.index(self.label)),
                ("fav", self.favorited),
            ]
            if value
        }


@dataclasses.dataclass(slots=True, frozen=True, weakref_slot=True)
class AccountBalance(_DictDumper):
    amount: float
    currency: str

    @classmethod
    def parse(cls, balance: list[tuple[float, str]] | None) -> Self:
        amount, currency = balance[0] if balance else (0.0, "EUR")
        return cls(float(amount), str(currency))


@dataclasses.dataclass(slots=True, frozen=True, weakref_slot=True)
class AccountStats(_DictParser, _DictDumper):
    storage: StorageQuota
    balance: AccountBalance
    metrics: dict[NodeID, StorageMetrics]
    subs: list[str]
    plans: list[str]
    features: list[str]

    @classmethod
    def parse(cls, data: dict[str, Any]) -> Self:
        clean_data = cls._filter_dict(data)
        clean_data.update(
            {
                "storage": StorageQuota.parse(data),
                "balance": AccountBalance.parse(data.get("balance")),
                "metrics": {node_id: StorageMetrics.parse(stats) for node_id, stats in data["cstrgn"].items()},
            }
        )
        return cls(**clean_data)


@dataclasses.dataclass(slots=True, frozen=True, weakref_slot=True)
class StorageMetrics(_DictDumper):
    bytes_used: ByteSize
    files: int
    folders: int

    @classmethod
    def parse(cls, metrics: list[int]) -> Self:
        bytes_used, files, folders = metrics[0:3]
        return cls(ByteSize(bytes_used), files, folders)


@dataclasses.dataclass(slots=True, frozen=True, weakref_slot=True)
class StorageQuota(_DictDumper):
    used: ByteSize
    total: ByteSize

    percent: int
    is_full: bool
    is_almost_full: bool

    @classmethod
    def parse(cls, data: dict[str, Any]) -> Self:
        total, used, threshold = map(ByteSize, (data["mstrg"], data["cstrg"], data["uslw"]))
        ratio = used / total
        return cls(
            used=used,
            total=total,
            is_full=ratio >= 1,
            percent=int(ratio * 100),
            is_almost_full=ratio >= (threshold / 10000),
        )


class UserResponse(TypedDict, total=False):
    u: UserID
    since: int  # timestamp of account creation
    email: str
    emails: list[str]
    pemails: list[str]
    name: str


class Upload(TypedDict):
    s: int  # Size
    p: str  # URL
