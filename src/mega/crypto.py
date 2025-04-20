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
TupleArray = tuple[U32Int, ...]
Array: TypeAlias = TupleArray | list[U32Int]
AnyArray: TypeAlias = Sequence[U32Int]
AnyDict: TypeAlias = dict[str, Any]
Chunk = tuple[int, int]  # index, size


EMPTY_IV = b"\0" * 16
CHUNK_LAST_BLOCK_LEN = 16


def random_u32int() -> U32Int:
    return random.randint(0, 0xFFFFFFFF)


def _makebyte(x: str) -> bytes:
    return codecs.latin_1_encode(x)[0]


def _makestring(x: bytes) -> str:
    return codecs.latin_1_decode(x)[0]


def _aes_cbc_encrypt(data: bytes, key: bytes) -> bytes:
    aes_cipher = AES.new(key, AES.MODE_CBC, EMPTY_IV)
    return aes_cipher.encrypt(data)


def _aes_cbc_decrypt(data: bytes, key: bytes) -> bytes:
    aes_cipher = AES.new(key, AES.MODE_CBC, EMPTY_IV)
    return aes_cipher.decrypt(data)


def _aes_cbc_encrypt_a32(data: AnyArray, key: AnyArray) -> TupleArray:
    return str_to_a32(_aes_cbc_encrypt(a32_to_bytes(data), a32_to_bytes(key)))


def _aes_cbc_decrypt_a32(data: AnyArray, key: AnyArray) -> TupleArray:
    return str_to_a32(_aes_cbc_decrypt(a32_to_bytes(data), a32_to_bytes(key)))


def stringhash(str: str, aeskey: AnyArray) -> str:
    s32 = str_to_a32(str)
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


def encrypt_key(a: AnyArray, key: AnyArray) -> TupleArray:
    # this sum, which is applied to a generator of tuples, actually flattens the output list of lists of that generator
    # i.e. it's equivalent to tuple([item for t in generatorOfLists for item in t])

    return sum((_aes_cbc_encrypt_a32(a[i : i + 4], key) for i in range(0, len(a), 4)), ())


def decrypt_key(a: AnyArray, key: AnyArray) -> TupleArray:
    return sum((_aes_cbc_decrypt_a32(a[i : i + 4], key) for i in range(0, len(a), 4)), ())


def encrypt_attr(attr_dict: dict, key: AnyArray) -> bytes:
    attr: bytes = _makebyte("MEGA" + json.dumps(attr_dict))
    if len(attr) % 16:
        attr += b"\0" * (16 - len(attr) % 16)
    return _aes_cbc_encrypt(attr, a32_to_bytes(key))


def decrypt_attr(attr: bytes, key: AnyArray) -> AnyDict:
    attr_bytes = _aes_cbc_decrypt(attr, a32_to_bytes(key))
    attr_str = _makestring(attr_bytes).rstrip("\0")
    if attr_str.startswith('MEGA{"'):
        i1 = 4
        i2 = attr_str.find("}")
        if i2 >= 0:
            i2 += 1
            return json.loads(attr_str[i1:i2])
        else:
            raise RuntimeError(f"Unable to properly decode filename, raw content is: {attr_str}")
    else:
        return {}


def a32_to_bytes(a: AnyArray) -> bytes:
    return struct.pack(f">{len(a):.0f}I", *a)


def str_to_a32(b: str | bytes) -> TupleArray:
    if isinstance(b, str):
        array = _makebyte(b)
    else:
        array: bytes = b
    if len(array) % 4:
        # pad to multiple of 4
        padding = b"\0" * (4 - len(array) % 4)
        array += padding  # type: ignore
    return struct.unpack(f">{(len(array) / 4):.0f}I", array)


def map_bytes_to_int(s: bytes) -> int:
    """
    A Multi-precision integer is encoded as a series of bytes in big-endian
    order. The first two bytes are a header which tell the number of bits in
    the integer. The rest of the bytes are the integer.
    """
    return int(binascii.hexlify(s[2:]), 16)


def _extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = _extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modular_inverse(a: int, m: int) -> int:
    g, x, y = _extended_gcd(a, m)
    if g != 1:
        raise Exception("modular inverse does not exist")
    else:
        return x % m


def base64_url_decode(data: str) -> bytes:
    data += "=="[(2 - len(data) * 3) % 4 :]
    for search, replace in (("-", "+"), ("_", "/"), (",", "")):
        data = data.replace(search, replace)
    return base64.b64decode(data)


def base64_to_a32(s: str) -> TupleArray:
    return str_to_a32(base64_url_decode(s))


def base64_url_encode(data: bytes) -> str:
    data_bytes = base64.b64encode(data)
    data_str = _makestring(data_bytes)
    for search, replace in (("+", "-"), ("/", "_"), ("=", "")):
        data_str = data_str.replace(search, replace)
    return data_str


def a32_to_base64(a: AnyArray) -> str:
    return base64_url_encode(a32_to_bytes(a))


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
