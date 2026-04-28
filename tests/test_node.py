import pytest

from mega.data_structures import _EMPTY_ATTRS, Attributes, AttributesSerialized, Node


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
