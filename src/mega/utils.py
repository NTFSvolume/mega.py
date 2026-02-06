import asyncio
import logging
import re
from collections.abc import Awaitable, Iterable, Sequence
from typing import Literal, TypeVar, overload

from rich.logging import RichHandler

from mega.errors import ValidationError

_T = TypeVar("_T")


def setup_logger(name: str = "mega") -> None:
    handler = RichHandler(show_time=False, rich_tracebacks=True)
    logger = logging.getLogger(name)
    logger.setLevel(10)
    logger.addHandler(handler)


def parse_file_url(url: str) -> tuple[str, str]:
    """Parse file id and key from url."""
    if "/file/" in url:
        # V2 URL structure
        # ex: https://mega.nz/file/cH51DYDR#qH7QOfRcM-7N9riZWdSjsRq
        url = url.replace(" ", "")
        file_id = re.findall(r"\W\w\w\w\w\w\w\w\w\W", url)[0][1:-1]
        match = re.search(file_id, url)
        assert match
        id_index = match.end()
        key = url[id_index + 1 :]
        return file_id, key
    elif "!" in url:
        # V1 URL structure
        # ex: https://mega.nz/#!Ue5VRSIQ!kC2E4a4JwfWWCWYNJovGFHlbz8F
        match = re.findall(r"/#!(.*)", url)
        path = match[0]
        return tuple(path.split("!"))
    else:
        raise ValueError(f"URL key missing from {url}")


def parse_folder_url(url: str) -> tuple[str, str]:
    if "/folder/" in url:
        _, parts = url.split("/folder/", 1)
    elif "#F!" in url:
        _, parts = url.split("#F!", 1)
    else:
        raise ValidationError("Not a valid folder URL")
    root_folder_id, shared_key = parts.split("#")
    return root_folder_id, shared_key


@overload
async def throttled_gather(
    coros: Iterable[Awaitable[_T]], batch_size: int = 10, *, return_exceptions: Literal[False]
) -> list[_T]: ...


@overload
async def throttled_gather(
    coros: Iterable[Awaitable[_T]], batch_size: int = 10, *, return_exceptions: bool = True
) -> list[_T | Exception]: ...


async def throttled_gather(
    coros: Iterable[Awaitable[_T]], batch_size: int = 10, *, return_exceptions: bool = True
) -> Sequence[_T | Exception]:
    """Like `asyncio.gather`, but creates tasks lazily to minimize event loop overhead.

    This function ensures there are never more than `batch_size` tasks created at any given time.

    If `return_exceptions` is `False`, any exceptions other than `asyncio.CancelledError` raised within
    a task will cancel all remaining tasks and wait for them to exit.
    The exceptions are then combined and raised as an `ExceptionGroup`.
    """

    semaphore = asyncio.BoundedSemaphore(batch_size)
    tasks: list[asyncio.Task[_T | Exception]] = []

    abort = False

    async def worker(coro: Awaitable[_T]) -> _T | Exception:
        try:
            return await coro
        except Exception as e:
            if return_exceptions:
                return e
            nonlocal abort
            abort = True
            raise

        finally:
            semaphore.release()

    async with asyncio.TaskGroup() as tg:
        for coro in coros:
            if abort:
                break
            await semaphore.acquire()
            tasks.append(tg.create_task(worker(coro)))

    return [t.result() for t in tasks]
