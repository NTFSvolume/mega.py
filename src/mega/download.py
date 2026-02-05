from __future__ import annotations

import asyncio
import dataclasses
import errno
import logging
import shutil
import tempfile
from collections.abc import Generator
from typing import TYPE_CHECKING

from Crypto.Cipher import AES
from Crypto.Util import Counter

from mega.crypto import CHUNK_BLOCK_LEN, EMPTY_IV, a32_to_bytes, get_chunks, pad_bytes, str_to_a32
from mega.progress import ProgressManager

if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path

    from mega.api import MegaAPI
    from mega.data_structures import TupleArray


logger = logging.getLogger(__name__)


class MegaDownloader:
    def __init__(self, api: MegaAPI) -> None:
        self._api = api
        self._progress = ProgressManager()

    async def run(
        self,
        url: str,
        output_path: Path,
        file_size: int,
        iv: tuple[int, ...],
        meta_mac: tuple[int, int],
        key: tuple[int, ...],
    ):
        if await asyncio.to_thread(output_path.exists):
            raise FileExistsError(errno.EEXIST, output_path)

        with (
            tempfile.NamedTemporaryFile(prefix="megapy_", delete=False) as temp_file,
            self._progress.new_task(output_path.name, total=file_size) as advance,
        ):
            chunk_decryptor = MegaDecryptor(iv, key, meta_mac)

            async with self._api.download(url) as response:
                for _, chunk_size in get_chunks(file_size):
                    raw_chunk = await response.content.readexactly(chunk_size)
                    chunk = chunk_decryptor.decrypt(raw_chunk)
                    temp_file.write(chunk)
                    advance(len(chunk))

        chunk_decryptor.check_integrity()

        def move():
            output_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(temp_file.name, output_path)

        await asyncio.to_thread(move)
        return output_path


@dataclasses.dataclass(slots=True, weakref_slot=True)
class MegaDecryptor:
    iv: tuple[int, ...]
    key: tuple[int, ...]
    meta_mac: tuple[int, int]
    _gen: Generator[bytes, bytes | None, None] = dataclasses.field(init=False)

    def __post_init__(self) -> None:
        self._gen = _decrypt_chunks(self.iv, self.key, self.meta_mac)
        _ = next(self._gen)

    def decrypt(self, raw_chunk: bytes) -> bytes:
        return self._gen.send(raw_chunk)

    def check_integrity(self) -> None:
        try:
            _ = self._gen.send(None)
        except StopIteration:
            pass


def _decrypt_chunks(
    iv: TupleArray,
    key: TupleArray,
    meta_mac: tuple[int, int],
) -> Generator[bytes, bytes | None, None]:
    """
    Decrypts chunks of data received via `send()` and yields the decrypted chunks.
    It decrypts chunks indefinitely until a sentinel value (`None`) is sent.

    NOTE: You MUST send `None` once after all chunks are processed to execute the MAC check.

    Args:
        iv (AnyArray):  Initialization vector (iv) as a list or tuple of two 32-bit unsigned integers.
        k_decrypted (TupleArray):  Decryption key as a tuple of four 32-bit unsigned integers.
        meta_mac (AnyArray):  The expected MAC value of the final file.

    Yields:
        bytes:  Decrypted chunk of data. The first `yield` is a blank (`b''`) to initialize generator.

    """
    key_bytes = a32_to_bytes(key)
    counter = Counter.new(128, initial_value=((iv[0] << 32) + iv[1]) << 64)
    aes = AES.new(key_bytes, AES.MODE_CTR, counter=counter)

    # mega.nz improperly uses CBC as a MAC mode, so after each chunk
    # the last 16 bytes are used as IV for the next chunk MAC accumulation

    mac_bytes = EMPTY_IV
    mac_encryptor = AES.new(key_bytes, AES.MODE_CBC, mac_bytes)
    iv_bytes = a32_to_bytes([iv[0], iv[1], iv[0], iv[1]])
    chunk: bytes | None = yield b""

    while chunk is not None:
        decrypted_chunk = aes.decrypt(chunk)
        chunk = yield decrypted_chunk
        encryptor = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)

        mem_view = memoryview(decrypted_chunk)
        modchunk = len(decrypted_chunk) % CHUNK_BLOCK_LEN or CHUNK_BLOCK_LEN

        last_16b = pad_bytes(mem_view[-modchunk:])
        encryptor.encrypt(mem_view[:-modchunk])
        mac_bytes = mac_encryptor.encrypt(encryptor.encrypt(last_16b))

    file_mac = str_to_a32(mac_bytes)
    computed_mac = file_mac[0] ^ file_mac[1], file_mac[2] ^ file_mac[3]
    if computed_mac != meta_mac:
        raise RuntimeError("Mismatched mac")
