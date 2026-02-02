from __future__ import annotations

import contextlib
import logging
from collections.abc import Generator
from contextvars import ContextVar
from typing import TYPE_CHECKING

from rich.progress import BarColumn, DownloadColumn, Progress, SpinnerColumn, TimeRemainingColumn, TransferSpeedColumn

if TYPE_CHECKING:
    from collections.abc import Callable, Generator


logger = logging.getLogger(__name__)
_SHOW_PROGRESS = ContextVar[bool]("_SHOW_PROGRESS", default=False)
_PROGRESS = ContextVar[Progress | None]("_PROGRESS", default=None)


class ProgressManager:
    @property
    def show(self) -> bool:
        return _SHOW_PROGRESS.get()

    @show.setter
    def show(self, value: bool) -> None:
        _ = _SHOW_PROGRESS.set(value)

    @contextlib.contextmanager
    def _new_progress(self) -> Generator[Progress]:
        progress = Progress(
            SpinnerColumn(),
            "{task.description}",
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>6.2f}%",
            "━",
            DownloadColumn(),
            "━",
            TransferSpeedColumn(),
            "━",
            TimeRemainingColumn(compact=True, elapsed_when_finished=True),
        )
        progress.disable = not self.show
        token = _PROGRESS.set(progress)
        try:
            yield progress
        finally:
            _PROGRESS.reset(token)

    @contextlib.contextmanager
    def new_task(self, *args, **kwargs) -> Generator[Callable[[float], None]]:
        progress = _PROGRESS.get()
        if progress is None:

            def hook(_: float) -> None: ...

            yield hook
            return

        task_id = progress.add_task(*args, **kwargs)

        def progress_hook(advance: float) -> None:
            progress.advance(task_id, advance)

        try:
            yield progress_hook
        finally:
            progress.remove_task(task_id=task_id)
