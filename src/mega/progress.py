from __future__ import annotations

import asyncio
import contextlib
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any, Literal, Protocol, TypeAlias

if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from types import TracebackType

    from rich.progress import Progress

    ProgressHook: TypeAlias = Callable[[float], None]

    class ProgressHookContext(Protocol):
        def __enter__(self) -> ProgressHook: ...

        def __exit__(
            self, typ: type[BaseException] | None, value: BaseException | None, traceback: TracebackType | None, /
        ) -> Any: ...

    class ProgressHookFactory(Protocol):
        def __call__(self, description: str, total: float, kind: Literal["UP", "DOWN"]) -> ProgressHookContext: ...


_PROGRESS_HOOK_FACTORY: ContextVar[ProgressHookFactory | None] = ContextVar("_PROGRESS_HOOK_FACTORY", default=None)
current_hook: ContextVar[ProgressHook] = ContextVar("current_hook", default=lambda _: None)


@contextlib.contextmanager
def new_task(description: str, total: float, kind: Literal["UP", "DOWN"]) -> Generator[None]:
    factory = _PROGRESS_HOOK_FACTORY.get()
    if factory is None:
        yield
        return

    with factory(description, total, kind) as progress_hook:
        token = current_hook.set(progress_hook)
        try:
            yield
        finally:
            current_hook.reset(token)


@contextlib.contextmanager
def new_progress() -> Generator[None]:
    progress = _new_rich_progress()
    if progress is None:
        yield
        return

    def hook_factory(*args, **kwargs):
        return _new_rich_task(progress, *args, **kwargs)

    token = _PROGRESS_HOOK_FACTORY.set(hook_factory)

    try:
        with progress:
            yield
    finally:
        _PROGRESS_HOOK_FACTORY.reset(token)


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


def _new_rich_progress() -> Progress | None:
    try:
        from rich.progress import (
            BarColumn,
            DownloadColumn,
            Progress,
            SpinnerColumn,
            TimeRemainingColumn,
            TransferSpeedColumn,
        )
    except ImportError:
        return None

    else:
        return Progress(
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


@contextlib.contextmanager
def _new_rich_task(
    progress: Progress, description: str, total: float, kind: Literal["UP", "DOWN"]
) -> Generator[ProgressHook]:
    task_id = progress.add_task(description, total=total, kind=kind)

    def progress_hook(advance: float) -> None:
        progress.advance(task_id, advance)

    try:
        yield progress_hook
    finally:
        progress.remove_task(task_id=task_id)


if __name__ == "__main__":  # pragma: no coverage
    asyncio.run(test())
