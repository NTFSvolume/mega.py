from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Generator
from contextvars import ContextVar
from typing import TYPE_CHECKING, Literal, TypeAlias

from rich.progress import BarColumn, DownloadColumn, Progress, SpinnerColumn, TimeRemainingColumn, TransferSpeedColumn

if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    ProgressHook: TypeAlias = Callable[[float], None]


_SHOW_PROGRESS = ContextVar[bool]("_SHOW_PROGRESS", default=False)
_PROGRESS = ContextVar[Progress | None]("_PROGRESS", default=None)


def do_nothing(_: float) -> None: ...


current_hook: ContextVar[ProgressHook] = ContextVar("current_hook", default=do_nothing)


@contextlib.contextmanager
def new_task(description: str, total: float, kind: Literal["UP", "DOWN"]) -> Generator[None]:
    progress = _PROGRESS.get()
    if progress is None:
        yield
        return

    task_id = progress.add_task(description, total=total, kind=kind)

    def progress_hook(advance: float) -> None:
        progress.advance(task_id, advance)

    token = current_hook.set(progress_hook)
    try:
        yield
    finally:
        progress.remove_task(task_id=task_id)
        current_hook.reset(token)


@contextlib.contextmanager
def new_progress() -> Generator[None]:
    progress = Progress(
        "[{task.fields[kind]}]",
        SpinnerColumn(),
        "{task.description}",
        BarColumn(bar_width=None),
        "[progress.percentage]{task.percentage:>6.2f}%",
        "-",
        DownloadColumn(),
        "-",
        TransferSpeedColumn(),
        "-",
        TimeRemainingColumn(compact=True, elapsed_when_finished=True),
        transient=True,
    )
    token = _PROGRESS.set(progress)
    try:
        with progress:
            yield
    finally:
        _PROGRESS.reset(token)


async def test() -> None:
    import random

    async def task(name: str) -> None:
        total = 1e6 * random.randint(200, 2000)
        max_step = int(total / 20)
        kind = random.choice(("UP", "DOWN"))
        with new_task(name, total, kind=kind):
            advance = current_hook.get()
            done = 0
            while done < total:
                chunk = min(random.randint(0, max_step), total - done)
                done += chunk
                advance(chunk)
                await asyncio.sleep(0.1)

    with new_progress():
        async with asyncio.TaskGroup() as tg:
            for idx in range(random.randint(2, 10)):
                tg.create_task(task(f"file{idx}"))


if __name__ == "__main__":  # pragma: no coverage
    asyncio.run(test())
