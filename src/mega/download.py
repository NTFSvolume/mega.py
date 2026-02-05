from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import errno
import logging
import shutil
import tempfile
from collections.abc import Generator
from pathlib import Path
from typing import IO, TYPE_CHECKING, Self

from Crypto.Cipher import AES
from Crypto.Util import Counter

from mega.crypto import CHUNK_BLOCK_LEN, EMPTY_IV, a32_to_bytes, get_chunks, pad_bytes, str_to_a32

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Callable, Generator

    import aiohttp

    from mega.data_structures import TupleArray


logger = logging.getLogger(__name__)


async def stream_download(
    stream: aiohttp.StreamReader,
    output_path: Path,
    file_size: int,
    iv: tuple[int, ...],
    meta_mac: tuple[int, int],
    key: tuple[int, ...],
    progress_hook: Callable[[float], None] | None = None,
):
    if await asyncio.to_thread(output_path.exists):
        raise FileExistsError(errno.EEXIST, output_path)

    async with _new_temp_download(output_path) as output:
        with MegaDecryptor(iv, key, meta_mac, file_size) as cypher:
            await cypher.read_stream(stream, output, progress_hook)

    return output_path


@contextlib.asynccontextmanager
async def _new_temp_download(output_path: Path) -> AsyncGenerator[IO[bytes]]:
    temp_file = tempfile.NamedTemporaryFile(prefix="megapy_", delete=False)
    logger.info(f"Created temp file '{temp_file.name!r}' for '{output_path}'")
    try:
        yield temp_file

        def move():
            temp_file.close()
            output_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(temp_file.name, output_path)
            logger.info(f"Moved temp file '{temp_file.name!r}' to '{output_path}'")

        await asyncio.to_thread(move)

    finally:

        def delete():
            if not temp_file.closed:
                temp_file.close()
            Path(temp_file.name).unlink()

        await asyncio.to_thread(delete)


@dataclasses.dataclass(slots=True)
class MegaDecryptor:
    iv: tuple[int, ...]
    key: tuple[int, ...]
    meta_mac: tuple[int, int]
    file_size: int
    _gen: Generator[bytes, bytes | None, None] = dataclasses.field(init=False)

    def __post_init__(self) -> None:
        self._gen = _decrypt_chunks(self.iv, self.key, self.meta_mac)

    def __enter__(self) -> Self:
        first = next(self._gen)
        assert first == b""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if exc_val is None:
            self.check_integrity()

    def decrypt(self, raw_chunk: bytes) -> bytes:
        return self._gen.send(raw_chunk)

    def check_integrity(self) -> None:
        try:
            _ = self._gen.send(None)
        except StopIteration:
            pass

    async def read_stream(
        self,
        stream: aiohttp.StreamReader,
        file_out: IO[bytes],
        progress_hook: Callable[[float], None] | None,
    ) -> None:
        for _, chunk_size in get_chunks(self.file_size):
            raw_chunk = await stream.readexactly(chunk_size)
            chunk = self.decrypt(raw_chunk)
            file_out.write(chunk)
            if progress_hook is not None:
                progress_hook(len(chunk))


def _decrypt_chunks(
    iv: TupleArray,
    key: TupleArray,
    meta_mac: tuple[int, int],
) -> Generator[bytes, bytes | None, None]:
    """
    Decrypts chunks of data received via `send()` and yields the decrypted chunks.

    Sending `None` after all chunks are processed will execute a MAC check

    The first `yield` is a blank (`b''`) to initialize generator.

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
