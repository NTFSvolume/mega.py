from typing import Any

import pytest

from mega.crypto import b64_url_decode, decrypt_attr, generate_hashcash, mpi_to_int, str_to_a32
from mega.data_structures import Crypto, NodeType


@pytest.mark.parametrize(
    ("attrs", "key", "expected_output"),
    [
        (
            b'\xb6E[\xe6K\xbd\xf9\t\x95\x1d\xcb\xe9\xa3N\x13 \xbb\xf3\x15\xf9H\xb7\x11\xe8\xec\\\x92"\x1d\xb45ia\xaf\x89v\xa5\xab\xd3\xb1\xa8Y\xbb\xe0\x81g\x8e\x19\x1b\xf5b\xa8\x1f`\x9d\x05b<\x13\x7fM\x07\xe0\xea',
            (1958576006, 489861153, 2106943810, 3660715586),
            {
                "c": "KGUlr2utItBMvUIKW-RuwQSUdM9j",
                "n": "SAM4}.png",
            },
        ),
    ],
)
def test_decrypt_attr(attrs: bytes, key: tuple[int, ...], expected_output: dict[str, Any]) -> None:
    output = decrypt_attr(attrs, key)
    assert output == expected_output


@pytest.mark.parametrize(
    ("attrs", "key", "expected_output"),
    [
        (
            "eexhyj90ZGTIIJB9sNzxbtoXtWxSZF-Wx4y-9tCKHetrwkzkU8lRTJbJyWvriph4FkX_A3G-GEUOObx6PBdOuQ",
            (1236629439, 3286055264, 785908661, 3074713241),
            {
                "c": "isL4enBZjOSl7BzytQws8ARrxYxp",
                "n": "OnlyFans (2).mp4",
            },
        ),
    ],
)
def test_decrypt_attr_str(attrs: str, key: tuple[int, ...], expected_output: dict[str, Any]) -> None:
    output = decrypt_attr(b64_url_decode(attrs), key)
    assert output == expected_output


@pytest.mark.parametrize(
    ("blob", "expected"),
    [
        (b"\x00\x00\x00", 0),
        (b"\x00\x08\xff", 255),
        (b"\x00\x10\x01\x23", 0x0123),
    ],
)
def test_mpi(blob: bytes, expected: int) -> None:
    assert mpi_to_int(blob) == expected


class TestStrToA32:
    def test_basic_string(self) -> None:
        result = str_to_a32("AAAA")
        assert result == (0x41414141,)

    def test_bytes_input(self) -> None:
        input_bytes = b"\x00\x00\x00\x01\x00\x00\x00\x02"
        result = str_to_a32(input_bytes)
        assert result == (1, 2)

    def test_padding(self) -> None:
        result = str_to_a32("ABC")
        assert result == (0x41424300,)

    def test_multiple_blocks(self) -> None:
        result = str_to_a32("ABCDE")
        assert len(result) == 2
        assert result[0] == 0x41424344
        assert result[1] == 0x45000000

    def test_unicode_handling(self) -> None:
        result = str_to_a32("©")
        assert result == (0xC2A90000,)

    def test_empty_input(self) -> None:
        result = str_to_a32("")
        assert isinstance(result, tuple)

    def test_invalid_type(self) -> None:
        with pytest.raises(AssertionError):
            str_to_a32(12345)  # type: ignore  # pyright: ignore[reportUnusedCallResult, reportArgumentType]

    @pytest.mark.parametrize(
        "input_val,expected",
        [
            ("1234", (0x31323334,)),
            (b"\x00\x00\x00\x01", (1,)),
        ],
    )
    def test_parameterized_cases(self, input_val: str | bytes, expected: tuple[int, ...]) -> None:

        assert str_to_a32(input_val) == expected


def test_crypto_decompose() -> None:
    full_key = (1194345153, 1144465475, 2482274722, 3745551294, 1, 2, 3, 4)
    crypto = Crypto.decompose(full_key)
    assert crypto.key == (1194345152, 1144465473, 2482274721, 3745551290)
    assert crypto.full_key == full_key
    assert crypto.iv == (1, 2)
    assert crypto.meta_mac == (3, 4)

    with pytest.raises(RuntimeError):
        _ = Crypto.decompose((1, 2, 3, 4))  # pyright: ignore[reportArgumentType]


def test_crypto_compose_file() -> None:
    key = (1, 2, 3, 4)
    iv = (5, 6)
    meta_mac = (7, 8)
    crypto = Crypto.compose(key, iv, meta_mac, NodeType.FILE)
    assert crypto.key == key
    assert crypto.iv == iv
    assert crypto.meta_mac == meta_mac
    assert crypto.full_key == (4, 4, 4, 12, 5, 6, 7, 8)
    assert crypto.share_key is None


def test_crypto_compose_folder() -> None:
    key = (1, 2, 3, 4)
    iv = (5, 6)
    meta_mac = (7, 8)
    crypto = Crypto.compose(key, iv, meta_mac, NodeType.FOLDER)
    assert crypto.key == key
    assert crypto.iv == iv
    assert crypto.meta_mac == meta_mac
    assert crypto.full_key == (1, 2, 3, 4, 5, 6, 7, 8)
    assert crypto.share_key is None


@pytest.mark.parametrize(
    ("input", "expected"),
    [
        (
            "1:192:1769956228:atNinVpwMnq2sgu6r3UXgd6TSZFJyi2GwOO_OC7hcUJTpKfMMJmKKPrAgxp8F5xj",
            "1:atNinVpwMnq2sgu6r3UXgd6TSZFJyi2GwOO_OC7hcUJTpKfMMJmKKPrAgxp8F5xj:jgEAAA",
        ),
        (
            "1:192:1769956324:n8r22ANvCSdYEqJAw09pFWl2L8dWA8J_VKtFsSlL3532DVsHfX_HgtvXvXuUvv77",
            "1:n8r22ANvCSdYEqJAw09pFWl2L8dWA8J_VKtFsSlL3532DVsHfX_HgtvXvXuUvv77:1wAAAA",
        ),
    ],
)
def test_hashcash(input: str, expected: str) -> None:
    assert generate_hashcash(input) == expected
