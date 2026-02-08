from __future__ import annotations

import dataclasses
import logging
from collections.abc import Generator
from typing import TYPE_CHECKING

from Crypto.Cipher import AES
from Crypto.Util import Counter

from mega.crypto import CHUNK_BLOCK_LEN, EMPTY_IV, a32_to_bytes, pad_bytes, str_to_a32

if TYPE_CHECKING:
    from collections.abc import Generator


logger = logging.getLogger(__name__)


@dataclasses.dataclass(slots=True)
class MegaChunker:
    """Decrypts/encrypts a flow of chunks using Mega's CBC algorithm"""

    iv: tuple[int, int]
    key: tuple[int, int, int, int]
    expected_meta_mac: tuple[int, int] | None = None

    _gen: Generator[bytes, bytes | None, tuple[int, int]] = dataclasses.field(init=False, repr=False)
    _computed_meta_mac: tuple[int, int] | None = dataclasses.field(init=False, default=None)

    def __post_init__(self) -> None:
        self._gen = _iter_chunks(self.iv, self.key, decrypt=bool(self.expected_meta_mac))
        _ = next(self._gen)

    def read(self, raw_chunk: bytes) -> bytes:
        return self._gen.send(raw_chunk)

    def compute_meta_mac(self) -> tuple[int, int]:
        if self._computed_meta_mac is None:
            try:
                _ = self._gen.send(None)
            except StopIteration as e:
                self._computed_meta_mac = e.value
            else:
                raise RuntimeError
        assert self._computed_meta_mac
        return self._computed_meta_mac

    def check_integrity(self) -> None:
        if not self.expected_meta_mac:
            raise RuntimeError
        meta_mac = self.compute_meta_mac()
        if self.expected_meta_mac != meta_mac:
            raise RuntimeError("Mismatched mac")


def _iter_chunks(
    iv: tuple[int, int],
    key: tuple[int, int, int, int],
    *,
    decrypt: bool,
) -> Generator[bytes, bytes | None, tuple[int, int]]:
    key_bytes = a32_to_bytes(key)
    counter = Counter.new(128, initial_value=((iv[0] << 32) + iv[1]) << 64)
    aes = AES.new(key_bytes, AES.MODE_CTR, counter=counter)

    mac_bytes = EMPTY_IV
    mac_cypher = AES.new(key_bytes, AES.MODE_CBC, mac_bytes)
    iv_bytes = a32_to_bytes([iv[0], iv[1], iv[0], iv[1]])
    data_in: bytes | None = yield b""

    while data_in is not None:
        if decrypt:
            decrypted_data = data_out = aes.decrypt(data_in)
        else:
            decrypted_data = data_in
            data_out = aes.encrypt(data_in)

        chunk_cypher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        mem_view = memoryview(decrypted_data)
        last_16b_index = (len(decrypted_data) % CHUNK_BLOCK_LEN) or CHUNK_BLOCK_LEN
        last_16b = pad_bytes(mem_view[-last_16b_index:])
        chunk_cypher.encrypt(mem_view[:-last_16b_index])
        mac_bytes = mac_cypher.encrypt(chunk_cypher.encrypt(last_16b))
        data_in = yield data_out

    file_mac = str_to_a32(mac_bytes)
    meta_mac = file_mac[0] ^ file_mac[1], file_mac[2] ^ file_mac[3]
    return meta_mac
