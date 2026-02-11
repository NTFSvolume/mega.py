from __future__ import annotations

import asyncio
import datetime
import errno
import logging
import random
import string
from collections.abc import Callable
from enum import Enum
from stat import S_ISREG
from typing import TYPE_CHECKING, Literal, TypeVar, overload

import yarl

from mega.errors import ValidationError

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Generator, Iterable, Sequence
    from pathlib import Path

    _T1 = TypeVar("_T1")
    _T2 = TypeVar("_T2")


logger = logging.getLogger(__name__)


class Site(Enum):
    MEGA = yarl.URL("https://mega.nz")
    TRANSFER_IT = yarl.URL("https://transfer.it")

    if TYPE_CHECKING:

        @property
        def value(self) -> yarl.URL: ...

    def check_host(self, url: yarl.URL) -> None:
        if url.host != self.value.host:
            raise ValidationError(f"Not a {self.value.host} URL: {url}")


def setup_logger(level: int = logging.INFO) -> None:
    try:
        from rich.logging import RichHandler
    except ImportError:
        handler = logging.StreamHandler()
    else:
        handler = RichHandler(show_time=False, rich_tracebacks=True, show_path=False)

    logger = logging.getLogger("mega")
    logger.setLevel(level)
    logger.addHandler(handler)


def progress_logger(output_path: Path, file_size: int, *, download: bool) -> Callable[[float], None]:
    if not logger.isEnabledFor(10):
        return lambda _: None

    from mega.data_structures import ByteSize

    def log() -> Generator[None, float]:
        bytes_uploaded: float = 0
        threshold = 0
        kind = "downloaded" if download else "uploaded"
        human_total = ByteSize(file_size).human_readable()
        last_log_size = 0
        _50MB = 1024 * 1024 * 50
        while True:
            chunk_size: float = yield
            bytes_uploaded += chunk_size
            ratio: float = (bytes_uploaded / file_size) * 100
            if ratio >= threshold or (bytes_uploaded - last_log_size) > _50MB:
                human_progress = ByteSize(bytes_uploaded).human_readable()
                threshold = ((ratio // 10) + 1) * 10
                last_log_size = bytes_uploaded
                logger.debug(f'{human_progress}/{human_total} {kind} ({ratio:0.1f}%) for "{output_path!s}"')

    gen = log()
    _ = next(gen)
    return gen.send


def random_u32int() -> int:
    return random.randint(0, 0xFFFFFFFF)


def random_u32int_array(lenght: int) -> tuple[int, ...]:
    return tuple(random_u32int() for _ in range(lenght))


def random_id(length: int) -> str:
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(length))


def utc_now() -> datetime.datetime:
    """Naive UTC now"""
    return datetime.datetime.now().astimezone(datetime.UTC).replace(tzinfo=None)


def str_utc_now() -> str:
    return utc_now().strftime("%Y%m%d_%H%M%S_%f")


def transform_v1_url(url: yarl.URL) -> yarl.URL:
    frag = url.fragment
    if url.path == "/" and frag.count("!") == 2:
        if frag.startswith("F!"):
            folder_id, shared_key = frag.removeprefix("F!").split("!")
            return (url.origin() / "folder" / folder_id).with_fragment(shared_key)
        if frag.startswith("!"):
            file_id, shared_key = frag.removeprefix("!").split("!")
            return (url.origin() / "file" / file_id).with_fragment(shared_key)
    return url


def get_file_size(file_path: Path) -> int:
    try:
        stat = file_path.stat()
    except (OSError, ValueError):
        raise FileNotFoundError(errno.ENOENT, str(file_path)) from None

    if not S_ISREG(stat.st_mode):
        raise IsADirectoryError(errno.EISDIR, str(file_path))

    return stat.st_size


@overload
async def async_map(
    coro_factory: Callable[[_T1], Awaitable[_T2]],
    values: Iterable[_T1],
    *,
    return_exceptions: Literal[True],
    task_limit: int = 10,
) -> list[_T2 | Exception]: ...


@overload
async def async_map(
    coro_factory: Callable[[_T1], Awaitable[_T2]],
    values: Iterable[_T1],
    *,
    return_exceptions: Literal[False] = False,
    task_limit: int = 10,
) -> list[_T2]: ...


async def async_map(
    coro_factory: Callable[[_T1], Awaitable[_T2]],
    values: Iterable[_T1],
    *,
    return_exceptions: bool = False,
    task_limit: int = 10,
) -> Sequence[_T2 | Exception]:
    """Creates tasks lazily to minimize event loop overhead.

    This function ensures there are never more than `task_limit` tasks are created at any given time.
    """
    semaphore = asyncio.BoundedSemaphore(task_limit)
    tasks: list[asyncio.Task[_T2 | Exception]] = []
    abort = asyncio.Event()

    async def worker(coro: Awaitable[_T2]) -> _T2 | Exception:
        try:
            return await coro
        except Exception as e:
            if return_exceptions:
                return e
            abort.set()
            raise

        finally:
            semaphore.release()

    async with asyncio.TaskGroup() as tg:
        for value in values:
            if abort.is_set():
                break

            await semaphore.acquire()
            coro = coro_factory(value)
            tasks.append(tg.create_task(worker(coro)))

    return [t.result() for t in tasks]
