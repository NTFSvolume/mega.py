from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import errno
import logging
import shutil
import tempfile
from pathlib import Path
from typing import IO, TYPE_CHECKING

from mega import progress
from mega.chunker import MegaChunker
from mega.crypto import get_chunks

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    import aiohttp


logger = logging.getLogger(__name__)


async def encrypted_stream(
    stream: aiohttp.StreamReader,
    output_path: Path,
    file_size: int,
    iv: tuple[int, int],
    meta_mac: tuple[int, int],
    key: tuple[int, int, int, int],
) -> Path:
    if await asyncio.to_thread(output_path.exists):
        raise FileExistsError(errno.EEXIST, output_path)

    chunker = MegaChunker(iv, key, meta_mac)
    progress_hook = progress.current_hook.get()
    async with _new_temp_download(output_path) as output:
        for _, chunk_size in get_chunks(file_size):
            encrypted_chunk = await stream.readexactly(chunk_size)
            chunk = chunker.read(encrypted_chunk)
            output.write(chunk)
            progress_hook(len(chunk))

        chunker.check_integrity()

    return output_path


async def stream(stream: aiohttp.StreamReader, output_path: Path) -> Path:
    if await asyncio.to_thread(output_path.exists):
        raise FileExistsError(errno.EEXIST, output_path)

    chunk_size = 1024 * 1024 * 5  # 5MB
    progress_hook = progress.current_hook.get()
    async with _new_temp_download(output_path) as output:
        async for chunk in stream.iter_chunked(chunk_size):
            output.write(chunk)
            progress_hook(len(chunk))

    return output_path


@contextlib.asynccontextmanager
async def _new_temp_download(output_path: Path) -> AsyncGenerator[IO[bytes]]:
    # We need NamedTemporaryFile to not delete on file.close() but on context exit, which is not supported until python 3.12
    temp_file = tempfile.NamedTemporaryFile(prefix="mega_py_", delete=False)
    logger.debug(f'Created temp file "{temp_file.name!s}" for "{output_path!s}"')
    try:
        yield temp_file

        def move():
            temp_file.close()
            output_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(temp_file.name, output_path)
            logger.debug(f'Moved temp file "{temp_file.name!s}" to "{output_path!s}"')

        await asyncio.to_thread(move)

    finally:

        def delete():
            if not temp_file.closed:
                temp_file.close()
            Path(temp_file.name).unlink(missing_ok=True)

        await asyncio.to_thread(delete)


@dataclasses.dataclass(slots=True, frozen=True)
class DownloadResult:
    success: tuple[Path, ...]
    fails: tuple[Exception, ...]

    def __iter__(self) -> tuple[tuple[Path, ...], tuple[Exception, ...]]:
        return self.success, self.fails

    @classmethod
    def build(cls, results: list[Path | Exception]):
        success: list[Path] = []
        fails: list[Exception] = [
            result for result in results if isinstance(result, Exception) or (success.append(result) and False)
        ]
        return cls(tuple(success), tuple(fails))
