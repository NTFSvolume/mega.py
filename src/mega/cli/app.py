import asyncio
import functools
import inspect
from collections.abc import Callable, Coroutine
from typing import Any, ParamSpec, TypeVar

import typer
from typer.models import CommandFunctionType

_P = ParamSpec("_P")
_R = TypeVar("_R")
_T = TypeVar("_T")


def _copy_signature(target: Callable[_P, _R]) -> Callable[[Callable[..., _T]], Callable[_P, _T]]:
    def decorator(func: Callable[..., _T]) -> Callable[_P, _T]:
        @functools.wraps(target)
        def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _T:
            return func(*args, **kwargs)

        wrapper.__signature__ = inspect.signature(target, eval_str=True).replace(  # pyright: ignore[reportAttributeAccessIssue]
            return_annotation=inspect.signature(func, eval_str=True).return_annotation
        )
        return wrapper

    return decorator


def _make_sync(func: Callable[_P, Coroutine[Any, Any, _R]]) -> Callable[_P, _R]:
    @_copy_signature(func)
    def runner(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        return asyncio.run(func(*args, **kwargs))

    return runner


def _maybe_run_async(
    typer_wrapper: Callable[[CommandFunctionType], CommandFunctionType], func: CommandFunctionType
) -> CommandFunctionType:
    if inspect.iscoroutinefunction(func):
        _ = typer_wrapper(_make_sync(func))  # pyright: ignore[reportArgumentType]
    else:
        _ = typer_wrapper(func)

    return func


class CLIApp(typer.Typer):
    """An async aware typer that can auto detect and run coroutines commands"""

    @_copy_signature(typer.Typer.callback)
    def callback(self, *args: Any, **kwargs: Any) -> Callable[[CommandFunctionType], CommandFunctionType]:
        wrapper = super().callback(*args, **kwargs)
        return functools.partial(_maybe_run_async, wrapper)

    @_copy_signature(typer.Typer.command)
    def command(self, *args: Any, **kwargs: Any) -> Callable[[CommandFunctionType], CommandFunctionType]:
        wrapper = super().command(*args, **kwargs)
        return functools.partial(_maybe_run_async, wrapper)
