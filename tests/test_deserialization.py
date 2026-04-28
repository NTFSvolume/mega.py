import pytest

from mega.data_structures import (
    _EMPTY_ATTRS,
    AccountBalance,
    AccountStats,
    Attributes,
    AttributesSerialized,
    Node,
    StorageMetrics,
    StorageQuota,
    StorageStatus,
)


def test_node_deserialization() -> None:
    node = Node.parse(
        {
            "h": "yL4WxYRC",
            "p": "WTRFSLDY",
            "u": "dwjDZ5T_jgA",
            "t": 0,
            "a": "eexhyj90ZGTIIJB9sNzxbtoXtWxSZF-Wx4y-9tCKHetrwkzkU8lRTJbJyWvriph4FkX_A3G-GEUOObx6PBdOuQ",
            "k": "PKhmVYiT:phd4KByD1xLsej-pnfePxFFg5nkaSA8F7ay6avW_dE4/WTRFSLDY:JWYVHvtGKidlMTA7_uKjf23JR_T7myQvDV1iVt9_BjM",
            "s": 294547972,
            "fa": "43:8*K9-7MfX1Ps8/882:0*Yq6v_ndWh6I/882:1*FVHG-E1gbIg",
            "ts": 1770833362,
        }
    )
    assert node.id == "yL4WxYRC"
    assert node.created_at == 1770833362
    assert node.attributes is None
    assert not node.is_folder
    assert dict(node.keys) == {
        "PKhmVYiT": "phd4KByD1xLsej-pnfePxFFg5nkaSA8F7ay6avW_dE4",
        "WTRFSLDY": "JWYVHvtGKidlMTA7_uKjf23JR_T7myQvDV1iVt9_BjM",
    }
    assert node.owner == "dwjDZ5T_jgA"
    assert node.parent_id == "WTRFSLDY"
    assert node.size == 294547972
    assert node._a == "eexhyj90ZGTIIJB9sNzxbtoXtWxSZF-Wx4y-9tCKHetrwkzkU8lRTJbJyWvriph4FkX_A3G-GEUOObx6PBdOuQ"
    assert node._crypto is None
    assert node.share_key is None
    assert node.share_owner is None


def test_attributes_deserialization() -> None:
    assert Attributes.parse({}) is _EMPTY_ATTRS
    attrs = {
        "n": "2239007845.jpg",
        "lbl": 3,
    }
    attributes = Attributes.parse(attrs)  # pyright: ignore[reportArgumentType]
    assert attributes.name == "2239007845.jpg"
    assert attributes.label == "yellow"
    assert not attributes.favorited
    assert attributes.serialize() == attrs


@pytest.mark.parametrize(
    "attrs, extras",
    [
        (
            {
                "n": "2239007845.jpg",
                "lbl": 0,
            },
            ("lbl",),
        ),
        (
            {
                "n": "2239007845.jpg",
                "lbl": 3,
            },
            (),
        ),
        (
            {
                "n": "",
                "lbl": 0,
                "fav": False,
            },
            ("n", "lbl", "fav"),
        ),
    ],
)
def test_attributes_serialization(attrs: AttributesSerialized, extras: tuple[str, ...]) -> None:
    filtered = {k: v for k, v in attrs.items() if k not in extras}
    assert Attributes.parse(attrs).serialize() == filtered


def test_storage_metrics() -> None:
    metrics = StorageMetrics.parse([35342640609, 2088, 33, 0, 0])
    assert metrics.bytes_used == 35342640609
    assert metrics.files == 2088
    assert metrics.folders == 33


def test_storage_quota() -> None:
    storage = StorageQuota.parse(
        {
            "mstrg": 53687091200,
            "usl": 0,
            "cstrg": 35342640609,
            "uslw": 9000,
        }
    )
    assert storage.used == 35342640609
    assert storage.max == 53687091200
    assert storage.threshold == 90
    assert storage.ratio == pytest.approx(0.6583, abs=0.0001)
    assert storage.percent == 66
    assert storage.is_full is False
    assert storage.is_almost_full is False


def test_account_balance() -> None:
    for value in ([], None):
        balance = AccountBalance.parse(value)
        assert balance.amount == 0.0
        assert balance.currency == "EUR"

    balance = AccountBalance.parse([(28, "USD")])
    assert type(balance.amount) is float
    assert balance.amount == 28.0
    assert balance.currency == "USD"


def test_account_stats() -> None:
    stats = AccountStats.parse(
        {
            "mstrg": 53687091200,
            "usl": 0,
            "cstrgn": {
                "5NJU0QYC": [35342640609, 2088, 33, 0, 0],
                "sF4BSZQC": [0, 0, 0, 0, 0],
                "UQY1SapC": [0, 0, 3, 0, 0],
            },
            "cstrg": 35342640609,
            "uslw": 9000,
            "srvratio": 25.000381475547417,
            "balance": [],
            "subs": [],
            "plans": [],
            "features": [],
            "bt": 18012,
            "tah": [0, 0, 0, 0, 0, 0],
            "tar": 0,
            "tuo": 0,
            "tua": 0,
            "ruo": 0,
            "rua": 0,
            "rtt": 1,
        }
    )
    assert stats.storage.used == 35342640609
    assert stats.storage.max == 53687091200
    assert stats.storage.threshold == 90
    assert stats.transfer_quota is None
    assert stats.features == ()
    assert stats.plan_expires is None
    assert stats.plans == ()
    assert stats.storage_status is StorageStatus.GREEN
    assert stats.balance.amount == 0.0
    assert stats.balance.currency == "EUR"
