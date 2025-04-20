from __future__ import annotations

import base64
import binascii
import codecs
import json
import random
import struct
from collections.abc import Generator, Sequence
from typing import Any, TypeAlias

from Crypto.Cipher import AES

U32Int: TypeAlias = int
TupleArray: TypeAlias = tuple[U32Int, ...]
ListArray: TypeAlias = list[U32Int]
Array: TypeAlias = TupleArray | ListArray
AnyArray: TypeAlias = Sequence[U32Int]
AnyDict: TypeAlias = dict[str, Any]
Chunk: TypeAlias = tuple[int, int]  # index, size

CHUNK_BLOCK_LEN = 16
EMPTY_IV = b"\0" * CHUNK_BLOCK_LEN


def pad_bytes(data: bytes, length: int = CHUNK_BLOCK_LEN) -> bytes:
    """
    Pads a bytes-like object with null bytes to a multiple of the specified length.

    Args:
        data: The bytes-like object to pad (bytes or memoryview).
        lenght: The block size to pad to. Defaults to 16.

    Returns:
        A new bytes object that is padded with null bytes such that its length is a multiple of 'length'.
    """

    if len(data) % length:
        padding = b"\0" * (length - len(data) % length)
        if isinstance(data, memoryview):
            return data.tobytes() + padding
        return data + padding
    return data


def random_u32int() -> U32Int:
    return random.randint(0, 0xFFFFFFFF)


def _make_byte(x: str) -> bytes:
    return codecs.latin_1_encode(x)[0]


def _make_string(x: bytes) -> str:
    return codecs.latin_1_decode(x)[0]


def _aes_cbc_encrypt(data: bytes, key: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, EMPTY_IV).encrypt(data)


def _aes_cbc_decrypt(data: bytes, key: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, EMPTY_IV).decrypt(data)


def _aes_cbc_encrypt_a32(data: AnyArray, key: AnyArray) -> TupleArray:
    return str_to_a32(_aes_cbc_encrypt(a32_to_bytes(data), a32_to_bytes(key)))


def _aes_cbc_decrypt_a32(data: AnyArray, key: AnyArray) -> TupleArray:
    return str_to_a32(_aes_cbc_decrypt(a32_to_bytes(data), a32_to_bytes(key)))


def make_hash(string: str, aeskey: AnyArray) -> str:
    s32 = str_to_a32(string)
    h32 = [0, 0, 0, 0]
    for i in range(len(s32)):
        h32[i % 4] ^= s32[i]
    for _ in range(0x4000):
        h32 = _aes_cbc_encrypt_a32(h32, aeskey)
    return a32_to_base64((h32[0], h32[2]))


def prepare_key(arr: Array) -> Array:
    pkey: Array = [0x93C467E3, 0x7DB0C7A4, 0xD1BE3F81, 0x0152CB56]
    for _ in range(0x10000):
        for j in range(0, len(arr), 4):
            key: Array = [0, 0, 0, 0]
            for i in range(4):
                if i + j < len(arr):
                    key[i] = arr[i + j]
            pkey = _aes_cbc_encrypt_a32(pkey, key)
    return pkey


def encrypt_key(array: AnyArray, key: AnyArray) -> TupleArray:
    # this sum, which is applied to a generator of tuples, actually flattens the output list of lists of that generator
    # i.e. it's equivalent to tuple([item for t in generatorOfLists for item in t])

    return sum((_aes_cbc_encrypt_a32(array[index : index + 4], key) for index in range(0, len(array), 4)), ())


def decrypt_key(array: AnyArray, key: AnyArray) -> TupleArray:
    return sum((_aes_cbc_decrypt_a32(array[index : index + 4], key) for index in range(0, len(array), 4)), ())


def encrypt_attr(attr_dict: dict, key: AnyArray) -> bytes:
    attr: bytes = _make_byte("MEGA" + json.dumps(attr_dict))
    attr = pad_bytes(attr)
    return _aes_cbc_encrypt(attr, a32_to_bytes(key))


def decrypt_attr(attr: bytes, key: AnyArray) -> AnyDict:
    attr_bytes = _aes_cbc_decrypt(attr, a32_to_bytes(key))
    attr_str = _make_string(attr_bytes).rstrip("\0")
    if attr_str.startswith('MEGA{"'):
        start = 4
        end = attr_str.find("}") + 1
        if end >= 1:
            return json.loads(attr_str[start:end])
        else:
            raise RuntimeError(f"Unable to properly decode filename, raw content is: {attr_str}")
    else:
        return {}


def a32_to_bytes(array: AnyArray) -> bytes:
    return struct.pack(f">{len(array):.0f}I", *array)


def str_to_a32(bytes_or_str: str | bytes) -> TupleArray:
    if isinstance(bytes_or_str, str):
        bytes_ = _make_byte(bytes_or_str)
    else:
        assert isinstance(bytes_or_str, bytes)
        bytes_ = bytes_or_str

    # pad to multiple of 4
    bytes_ = pad_bytes(bytes_, length=4)
    return struct.unpack(f">{(len(bytes_) / 4):.0f}I", bytes_)


def map_bytes_to_int(data: bytes) -> int:
    """
    A Multi-precision integer is encoded as a series of bytes in big-endian
    order. The first two bytes are a header which tell the number of bits in
    the integer. The rest of the bytes are the integer.
    """
    return int(binascii.hexlify(data[2:]), CHUNK_BLOCK_LEN)


def _extended_gcd(num1: int, num2: int) -> tuple[int, int, int]:
    """
    Computes the extended greatest common divisor (GCD) of two integers.

    Args:
        num1: The first integer.
        num2: The second integer.

    Returns:
        A tuple (gcd, x, y) such that gcd is the greatest common divisor
        of num1 and num2, and num1*x + num2*y == gcd.
    """
    if num1 == 0:
        return (num2, 0, 1)  # GCD, x, y
    else:
        gcd, x_coeff, y_coeff = _extended_gcd(num2 % num1, num1)
        x = y_coeff
        y = x_coeff - (num2 // num1) * y_coeff
        return (gcd, x, y)


def modular_inverse(num: int, module: int) -> int:
    """
    Calculate the modular inverse of num with respect to the given module.

    The modular inverse of 'a' modulo 'module' is an integer 'x' such that
    (a * x) % module == 1.

    Args:
        num: The integer for which to find the modular inverse.
        module: The modulus.

    Returns:
        The modular inverse of 'num' modulo 'module'.

    Raises:
        ValueError: If the modular inverse does not exist (i.e., 'num' and 'module'
            are not coprime).
    """

    gcd, inverse, _ = _extended_gcd(num, module)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    else:
        return inverse % module


def base64_url_decode(data: str) -> bytes:
    data += "=="[(2 - len(data) * 3) % 4 :]
    for search, replace in (("-", "+"), ("_", "/"), (",", "")):
        data = data.replace(search, replace)
    return base64.b64decode(data)


def base64_to_a32(string: str) -> TupleArray:
    return str_to_a32(base64_url_decode(string))


def base64_url_encode(data: bytes) -> str:
    data_bytes = base64.b64encode(data)
    data_str = _make_string(data_bytes)
    for search, replace in (("+", "-"), ("/", "_"), ("=", "")):
        data_str = data_str.replace(search, replace)
    return data_str


def a32_to_base64(array: AnyArray) -> str:
    return base64_url_encode(a32_to_bytes(array))


def get_chunks(size: int) -> Generator[Chunk]:
    # generates a list of chunks (offset, chunk_size), where offset refers to the file initial position
    position = 0
    current_size = init_size = 0x20000
    while position + current_size < size:
        yield (position, current_size)
        position += current_size
        if current_size < 0x100000:
            current_size += init_size
    yield (position, size - position)
