from __future__ import annotations

import asyncio
import contextlib
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


async def stream_download(
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
            raw_chunk = await stream.readexactly(chunk_size)
            chunk = chunker.read(raw_chunk)
            output.write(chunk)
            progress_hook(len(chunk))

        chunker.check_integrity()

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
            Path(temp_file.name).unlink(missing_ok=True)

        await asyncio.to_thread(delete)
