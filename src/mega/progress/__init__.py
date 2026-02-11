from __future__ import annotations

import asyncio
import contextlib
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any, Literal, Protocol, TypeAlias, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from types import TracebackType

    from rich.progress import Progress

    _T = TypeVar("_T")

    ProgressHook: TypeAlias = Callable[[float], None]

    class ProgressHookContext(Protocol):
        def __enter__(self) -> ProgressHook: ...

        def __exit__(
            self,
            typ: type[BaseException] | None,
            value: BaseException | None,
            traceback: TracebackType | None,
            /,
        ) -> Any: ...

    class ProgressHookFactory(Protocol):
        def __call__(self, description: str, total: float, kind: Literal["UP", "DOWN"]) -> ProgressHookContext: ...


try:
    from mega.progress.rich_progress import create as create_rich_progress
except ImportError:

    def create_rich_progress() -> Progress | None:
        return None


_PROGRESS_HOOK_FACTORY: ContextVar[ProgressHookFactory | None] = ContextVar("_PROGRESS_HOOK_FACTORY", default=None)
current_hook: ContextVar[ProgressHook] = ContextVar("current_hook", default=lambda _: None)


@contextlib.contextmanager
def new_task(description: str, total: float, kind: Literal["UP", "DOWN"]) -> Generator[None]:
    factory = _PROGRESS_HOOK_FACTORY.get()
    if factory is None:
        yield
        return

    with factory(description, total, kind) as new_hook:
        _ = current_hook.set(new_hook)
        yield


@contextlib.contextmanager
def new_progress() -> Generator[None]:
    progress = create_rich_progress()
    if progress is None:
        yield
        return

    def hook_factory(*args, **kwargs):
        return _create_rich_task_ctx(progress, *args, **kwargs)

    with progress:
        _ = _PROGRESS_HOOK_FACTORY.set(hook_factory)
        yield


@contextlib.contextmanager
def _create_rich_task_ctx(
    progress: Progress,
    description: str,
    total: float,
    kind: Literal["UP", "DOWN"],
) -> Generator[ProgressHook]:
    task_id = progress.add_task(description, total=total, kind=kind)

    def progress_hook(advance: float) -> None:
        progress.advance(task_id, advance)

    try:
        yield progress_hook
    finally:
        progress.remove_task(task_id=task_id)


async def test() -> None:
    import random

    async def task(name: str) -> None:
        total = 1e6 * random.randint(200, 2000)
        max_step = int(total / 20)
        kind = random.choice(("UP", "DOWN"))
        with new_task(name, total, kind):
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
