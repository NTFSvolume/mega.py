from __future__ import annotations

from typing import TYPE_CHECKING

from rich import get_console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    SpinnerColumn,
    Task,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)
from rich.table import Column

if TYPE_CHECKING:
    from rich.text import Text

console = get_console()


class AutoTruncatedTextColumn(TextColumn):
    def render(self, task: Task) -> Text:
        text = super().render(task)
        width = console.width
        available_witdh = min((width * 60 // 100), (width - 65))
        desc_limit = max(available_witdh, 8)
        text.truncate(desc_limit, overflow="ellipsis")
        return text


def create() -> Progress:
    return Progress(
        "[{task.fields[kind]}]",
        SpinnerColumn(),
        AutoTruncatedTextColumn("{task.description}"),
        BarColumn(
            bar_width=None,
        ),
        "[progress.percentage]{task.percentage:>6.1f}%",
        "•",
        DownloadColumn(
            table_column=Column(justify="right", no_wrap=True),
        ),
        "•",
        TransferSpeedColumn(table_column=Column(justify="right", no_wrap=True)),
        "•",
        TimeRemainingColumn(
            compact=True,
            elapsed_when_finished=True,
            table_column=Column(justify="right", no_wrap=True),
        ),
        transient=True,
        console=console,
        expand=True,
    )
