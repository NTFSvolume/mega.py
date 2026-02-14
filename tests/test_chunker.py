import os

import pytest

from mega.chunker import MegaChunker, get_chunks
from mega.utils import random_u32int_array


@pytest.mark.parametrize(
    ("file_size", "exp_result"),
    [
        (
            0,
            ((0, 0),),
        ),
        (
            10,
            ((0, 10),),
        ),
        (
            1000,
            ((0, 1000),),
        ),
        (
            1000000,
            (
                (0, 131072),
                (131072, 262144),
                (393216, 393216),
                (786432, 213568),
            ),
        ),
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
    result = tuple(get_chunks(file_size))

    assert result == exp_result


def test_encrypt_decrypt() -> None:
    key = (0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210)
    iv = (0xDEADBEEF, 0xCAFEBABE)
    expected_meta_mac = (915100996, 2671779104)
    data = b"small payload"
    chunker = MegaChunker(key, iv)
    ciphertext = chunker.read(data)
    meta_mac = chunker.compute_meta_mac()
    assert meta_mac == expected_meta_mac

    assert len(ciphertext) == len(data)
    chunker = MegaChunker(key, iv, meta_mac)
    recovered = chunker.read(ciphertext)
    final_mac = chunker.compute_meta_mac()
    assert recovered == data
    assert final_mac == meta_mac


def test_encrypt_decrypt_large() -> None:
    key = random_u32int_array(4)
    iv = random_u32int_array(2)
    data = os.urandom(1_000_000)

    chunker = MegaChunker(key, iv)  # pyright: ignore[reportArgumentType]
    ciphertext = chunker.read(data)
    meta_mac = chunker.compute_meta_mac()

    chunker = MegaChunker(key, iv, meta_mac)  # pyright: ignore[reportArgumentType]
    recovered = chunker.read(ciphertext)
    final_mac = chunker.compute_meta_mac()
    assert recovered == data
    assert final_mac == meta_mac
