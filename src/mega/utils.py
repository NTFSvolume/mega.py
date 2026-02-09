from __future__ import annotations

import asyncio
import datetime
import logging
import random
import string
from enum import Enum
from typing import TYPE_CHECKING, Literal, TypeVar, overload

import yarl

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Iterable, Sequence

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
            raise ValueError(f"Not a {self.value.host} URL: {url}")


def setup_logger(level: int = logging.INFO) -> None:
    from rich.logging import RichHandler

    handler = RichHandler(show_time=False, rich_tracebacks=True, show_path=False)
    logger = logging.getLogger("mega")
    logger.setLevel(level)
    logger.addHandler(handler)


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


@overload
async def throttled_gather(
    coro_factory: Callable[[_T1], Awaitable[_T2]],
    values: Iterable[_T1],
    *,
    return_exceptions: bool = True,
    task_limit: int = 10,
) -> list[_T2 | Exception]: ...


@overload
async def throttled_gather(
    coro_factory: Callable[[_T1], Awaitable[_T2]],
    values: Iterable[_T1],
    *,
    return_exceptions: Literal[False],
    task_limit: int = 10,
) -> list[_T2]: ...


async def throttled_gather(
    coro_factory: Callable[[_T1], Awaitable[_T2]],
    values: Iterable[_T1],
    *,
    return_exceptions: bool = True,
    task_limit: int = 10,
) -> Sequence[_T2 | Exception]:
    """Creates tasks lazily to minimize event loop overhead.

    This function ensures there are never more than `task_limit` tasks are created at any given time.

    If `return_exceptions` is `False`, any exceptions other than `asyncio.CancelledError` raised within
    a task will cancel all remaining tasks and wait for them to exit.
    The exceptions are then combined and raised as an `ExceptionGroup`.
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
