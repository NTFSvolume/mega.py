from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Sequence
from functools import wraps
from typing import TYPE_CHECKING, Any, ClassVar, ParamSpec, Self, TypeVar

import aiohttp
import yarl

from mega.crypto import generate_hashcash_token
from mega.utils import random_id, random_u32int

from .errors import RequestError, RetryRequestError

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Callable, Coroutine

    _P = ParamSpec("_P")
    _R = TypeVar("_R")


logger = logging.getLogger(__name__)


_HEADERS: dict[str, str] = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
}


def retry(
    *,
    exceptions: Sequence[type[Exception]] | type[Exception],
    attempts: int = 10,
    delay: float = 0.5,
    min_delay: float = 2.0,
    max_delay: float = 30.0,
    backoff: int = 2,
) -> Callable[[Callable[_P, Coroutine[None, None, _R]]], Callable[_P, Coroutine[None, None, _R]]]:
    if not isinstance(exceptions, Sequence):
        exceptions = [exceptions]

    def wrapper(func: Callable[_P, Coroutine[None, None, _R]]) -> Callable[_P, Coroutine[None, None, _R]]:
        @wraps(func)
        async def inner_wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _R:
            current_delay = delay
            for attempt in range(1, attempts + 1):
                try:
                    return await func(*args, **kwargs)
                except tuple(exceptions) as exc:
                    if attempt >= attempts:
                        raise

                    logger.warning(f"Retrying {func.__qualname__} after attempt {attempt} ({exc})")
                    await asyncio.sleep(current_delay)
                    exp = current_delay**backoff
                    current_delay = max(min_delay, min(exp, max_delay))
            raise RuntimeError

        return inner_wrapper

    return wrapper


class MegaAPI:
    __slots__ = (
        "__session",
        "_auto_close_session",
        "_client_id",
        "_request_id",
        "session_id",
    )

    entrypoint: ClassVar[yarl.URL] = yarl.URL("https://g.api.mega.co.nz/cs")

    def __init__(self, session: aiohttp.ClientSession | None = None) -> None:
        self.session_id: str | None = None
        self._request_id: int = random_u32int()
        self._client_id: str = random_id(10)
        self.__session: aiohttp.ClientSession | None = session
        self._auto_close_session: bool = session is None

    def __repr__(self) -> str:
        return f"<{type(self).__name__}>(session_id={self.session_id!r}, client_id={self._client_id!r})"

    async def close(self) -> None:
        if self._auto_close_session and self.__session:
            await self.__session.close()

    async def __enter__(self) -> Self:
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()

    def _lazy_session(self) -> aiohttp.ClientSession:
        if self.__session is None:
            self.__session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(sock_connect=160, sock_read=60))
        return self.__session

    @retry(exceptions=RetryRequestError, attempts=10, max_delay=60.0)
    async def request(self, data: dict[str, Any] | list[dict[str, Any]], params: dict[str, Any] | None = None) -> Any:
        params = {"id": self._request_id} | (params or {})
        self._request_id += 1
        if self.session_id:
            params["sid"] = self.session_id

        if not isinstance(data, list):
            data = [data]

        headers = _HEADERS

        for solve_xhashcash in (True, False):
            logger.debug(f"Making POST request with {params=!r} {data=!r} {headers=!r}")
            async with self._lazy_session().post(
                self.entrypoint, params=params, json=data, headers=headers
            ) as response:
                # Since around feb 2025, MEGA requires clients to solve a challenge during each login attempt.
                # When that happens, initial responses returns "402 Payment Required".
                # Challenge is inside the `X-Hashcash` header.
                # We need to solve the challenge and re-made the request with same params + the computed token
                # See:  https://github.com/gpailler/MegaApiClient/issues/248#issuecomment-2692361193

                if xhashcash_challenge := response.headers.get("X-Hashcash"):
                    if not solve_xhashcash:
                        msg = f"Login failed. Mega requested a proof of work with xhashcash: {xhashcash_challenge}"
                        raise RequestError(msg)

                    logger.info("Solving xhashcash login challenge, this could take a few seconds...")
                    xhashcash_token = await asyncio.to_thread(generate_hashcash_token, xhashcash_challenge)
                    logger.debug(f"Solved xhashcash: challenge={xhashcash_challenge!r}, result={xhashcash_token}")
                    headers = headers | {"X-Hashcash": xhashcash_token}
                    continue

                return await self._process_resp(response)

        raise ValueError

    @contextlib.asynccontextmanager
    async def download(self, url: str | yarl.URL) -> AsyncGenerator[aiohttp.ClientResponse]:
        async with self._lazy_session().get(url, headers=_HEADERS) as resp:
            resp.raise_for_status()
            yield resp

    async def upload_chunk(self, upload_url: str, offset: int, data: bytes) -> str:
        async with self._lazy_session().post(upload_url + "/" + str(offset), data=data) as resp:
            return await resp.text()

    @staticmethod
    async def _process_resp(response: aiohttp.ClientResponse) -> Any:
        json_resp: list[Any] | int = await response.json()
        resp = json_resp
        logger.debug(f"Got response [{response.status}] json={json_resp!r}")

        if isinstance(json_resp, list) and len(json_resp) == 1:
            resp = json_resp[0]

        if isinstance(resp, int):
            if resp == 0:
                return resp

            if resp == -3:
                msg = "Request failed, retrying"
                logger.warning(msg)
                raise RetryRequestError()
            raise RequestError(resp)

        return resp
