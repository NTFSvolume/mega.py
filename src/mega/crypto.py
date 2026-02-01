from __future__ import annotations

import base64
import json
import math
import random
import struct
from typing import TYPE_CHECKING, Any, NamedTuple

from Crypto.Cipher import AES
from Crypto.Math.Numbers import Integer
from Crypto.PublicKey import RSA

if TYPE_CHECKING:
    from collections.abc import Generator

    from .data_structures import AnyArray, AnyDict, Array, TupleArray, U32Int

CHUNK_BLOCK_LEN = 16  # Hexadecimal
EMPTY_IV = b"\0" * CHUNK_BLOCK_LEN


class Chunk(NamedTuple):
    offset: int
    size: int


def pad_bytes(data: bytes, length: int = CHUNK_BLOCK_LEN) -> bytes:
    if len(data) % length:
        padding = b"\0" * (length - len(data) % length)
        if isinstance(data, memoryview):
            return data.tobytes() + padding
        return data + padding
    return data


def random_u32int() -> U32Int:
    return random.randint(0, 0xFFFFFFFF)


def _aes_cbc_encrypt(data: bytes, key: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, EMPTY_IV).encrypt(data)


def _aes_cbc_decrypt(data: bytes, key: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, EMPTY_IV).decrypt(data)


def _aes_cbc_encrypt_a32(data: AnyArray, key: AnyArray) -> TupleArray:
    return str_to_a32(_aes_cbc_encrypt(a32_to_bytes(data), a32_to_bytes(key)))


def _aes_cbc_decrypt_a32(data: AnyArray, key: AnyArray) -> TupleArray:
    return str_to_a32(_aes_cbc_decrypt(a32_to_bytes(data), a32_to_bytes(key)))


def generate_v1_hash(string: str, aeskey: AnyArray) -> str:
    s32 = str_to_a32(string)
    h32 = [0, 0, 0, 0]
    for i in range(len(s32)):
        h32[i % 4] ^= s32[i]
    for _ in range(0x4000):
        h32 = _aes_cbc_encrypt_a32(h32, aeskey)
    return a32_to_base64((h32[0], h32[2]))


def prepare_v1_key(password: str) -> Array:
    arr = str_to_a32(password)
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
    return sum((_aes_cbc_encrypt_a32(array[index : index + 4], key) for index in range(0, len(array), 4)), ())


def decrypt_key(array: AnyArray, key: AnyArray) -> TupleArray:
    return sum((_aes_cbc_decrypt_a32(array[index : index + 4], key) for index in range(0, len(array), 4)), ())


def encrypt_attr(attrs: dict[str, Any], key: AnyArray) -> bytes:
    attr_bytes: bytes = f"MEGA{json.dumps(attrs)}".encode()
    return _aes_cbc_encrypt(pad_bytes(attr_bytes), a32_to_bytes(key))


def decrypt_attr(attr: bytes, key: AnyArray) -> AnyDict:
    attr_bytes = _aes_cbc_decrypt(attr, a32_to_bytes(key))
    try:
        attr_str = attr_bytes.decode("utf-8").rstrip("\0")
    except UnicodeDecodeError:
        attr_str = attr_bytes.decode("latin-1").rstrip("\0")

    if attr_str.startswith('MEGA{"'):
        content = attr_str[4 : attr_str.rfind("}") + 1]
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Unable to decode file attributes, raw content is: {attr_str}") from e

    return {}


def a32_to_bytes(array: AnyArray) -> bytes:
    return struct.pack(f">{len(array):.0f}I", *array)


def str_to_a32(bytes_or_str: str | bytes) -> TupleArray:
    if isinstance(bytes_or_str, str):
        bytes_ = bytes_or_str.encode()
    else:
        assert isinstance(bytes_or_str, bytes)
        bytes_ = bytes_or_str

    # pad to multiple of 4
    bytes_ = pad_bytes(bytes_, length=4)
    return struct.unpack(f">{(len(bytes_) / 4):.0f}I", bytes_)


def mpi_to_int(data: bytes) -> int:
    """
    A Multi-precision integer (mpi) is encoded as a series of bytes in big-endian
    order. The first two bytes are a header which tell the number of bits in
    the integer. The rest of the bytes are the integer.
    """

    return int(data[2:].hex(), CHUNK_BLOCK_LEN)


def base64_url_decode(data: str) -> bytes:
    data += "=="[(2 - len(data) * 3) % 4 :]
    for search, replace in (("-", "+"), ("_", "/"), (",", "")):
        data = data.replace(search, replace)
    return base64.b64decode(data)


def base64_to_a32(string: str) -> TupleArray:
    return str_to_a32(base64_url_decode(string))


def base64_url_encode(data: bytes) -> str:
    data_bytes = base64.b64encode(data)
    data_str = data_bytes.decode()
    for old, replace in (("+", "-"), ("/", "_"), ("=", "")):
        data_str = data_str.replace(old, replace)
    return data_str


def a32_to_base64(array: AnyArray) -> str:
    return base64_url_encode(a32_to_bytes(array))


def get_chunks(size: int) -> Generator[Chunk]:
    # generates a list of chunks (offset, chunk_size), where offset refers to the file initial position
    offset = 0
    current_size = init_size = 0x20000
    while offset + current_size < size:
        yield Chunk(offset, current_size)
        offset += current_size
        if current_size < 0x100000:
            current_size += init_size
    yield Chunk(offset, size - offset)


def decrypt_rsa_key(private_key: bytes) -> RSA.RsaKey:
    # The private_key contains 4 MPI integers concatenated together.
    rsa_private_key = [0, 0, 0, 0]
    for idx in range(4):
        key_len = (private_key[0] * 256) + private_key[1]
        key_len_bytes = math.ceil(key_len / 8) + 2  # +2 for MPI header
        rsa_private_key[idx] = mpi_to_int(private_key[:key_len_bytes])
        private_key = private_key[key_len_bytes:]

    first_factor_p, second_factor_q, private_exponent_d, crt_coeficient_u = rsa_private_key[:4]
    rsa_modulus_n = first_factor_p * second_factor_q
    phi = (first_factor_p - 1) * (second_factor_q - 1)
    public_exponent_e = int(Integer(private_exponent_d).inverse(phi))

    return RSA.construct(
        rsa_components=(
            rsa_modulus_n,
            public_exponent_e,
            private_exponent_d,
            first_factor_p,
            second_factor_q,
            crt_coeficient_u,
        ),
        consistency_check=True,
    )
