from typing import Any

import pytest

from mega import crypto
from mega.data_structures import AnyArray


@pytest.mark.parametrize(
    "file_size, exp_result",
    [
        (10, ((0, 10),)),
        (1000, ((0, 1000),)),
        (1000000, ((0, 131072), (131072, 262144), (393216, 393216), (786432, 213568))),
        (
            10000000,
            (
                (0, 131072),
                (131072, 262144),
                (393216, 393216),
                (786432, 524288),
                (1310720, 655360),
                (1966080, 786432),
                (2752512, 917504),
                (3670016, 1048576),
                (4718592, 1048576),
                (5767168, 1048576),
                (6815744, 1048576),
                (7864320, 1048576),
                (8912896, 1048576),
                (9961472, 38528),
            ),
        ),
    ],
)
def test_get_chunks(file_size: int, exp_result: tuple[int, int]) -> None:
    result = tuple(crypto.get_chunks(file_size))

    assert result == exp_result


@pytest.mark.parametrize(
    "attrs, key, expected_output",
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
def test_decrypt_attr(attrs: bytes, key: AnyArray, expected_output: dict[str, Any]) -> None:
    output = crypto.decrypt_attr(attrs, key)
    assert output == expected_output


@pytest.mark.parametrize(
    "blob,expected",
    [
        (b"\x00\x00\x00", 0),
        (b"\x00\x08\xff", 255),
        (b"\x00\x10\x01\x23", 0x0123),
    ],
)
def test_mpi(blob: bytes, expected: int) -> None:
    assert crypto.mpi_to_int(blob) == expected


@pytest.mark.parametrize(
    "input,expected",
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
    assert crypto.generate_hashcash_token(input) == expected
