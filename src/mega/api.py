from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import logging
from collections.abc import Mapping, Sequence
from functools import wraps
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, ClassVar, Literal, ParamSpec, Self, TypeVar

import aiohttp
import yarl
from aiolimiter import AsyncLimiter

from mega.crypto import generate_hashcash_token
from mega.errors import RequestError, RetryRequestError
from mega.utils import random_id, random_u32int

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Callable, Coroutine

    _P = ParamSpec("_P")
    _R = TypeVar("_R")


_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0"
_DEFAULT_HEADERS: MappingProxyType[str, str] = MappingProxyType({"User-Agent": _UA})


logger = logging.getLogger(__name__)


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


@dataclasses.dataclass(slots=True, weakref_slot=True, init=False)
class MegaAPI:
    session_id: str | None
    _request_id: int
    _client_id: str

    __session: aiohttp.ClientSession | None
    _auto_close_session: bool
    _rate_limiter: AsyncLimiter

    _entrypoint: ClassVar[yarl.URL] = yarl.URL("https://g.api.mega.co.nz/cs")

    def __init__(self, session: aiohttp.ClientSession | None = None) -> None:
        self.session_id = None
        self._request_id = random_u32int()
        self._client_id = random_id(10)
        self.__session = session
        self._auto_close_session = session is None
        self._rate_limiter = AsyncLimiter(100, 60)

    @property
    def entrypoint(self) -> yarl.URL:
        return self._entrypoint

    @property
    def client_id(self) -> str:
        return self._client_id

    @property
    def request_id(self) -> int:
        return self._request_id

    @property
    def _session(self) -> aiohttp.ClientSession:
        if self.__session is None:
            self.__session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(sock_connect=160, sock_read=60))
        return self.__session

    def __repr__(self) -> str:
        return f"<{type(self).__name__}>(session_id={self.session_id!r}, client_id={self.client_id!r}, auto_close_session={self._auto_close_session!r})"

    async def aclose(self) -> None:
        if self._auto_close_session and self.__session:
            await self.__session.close()

    async def __enter__(self) -> Self:
        return self

    async def __aexit__(self, *_) -> None:
        await self.aclose()

    close = aclose

    @retry(exceptions=RetryRequestError, attempts=10, max_delay=60.0)
    async def post(self, json: dict[str, Any] | list[dict[str, Any]], params: dict[str, Any] | None = None) -> Any:
        params = {"id": self._request_id} | (params or {})
        self._request_id += 1
        if self.session_id:
            params["sid"] = self.session_id

        headers = {"Content-Type": "application/json"}

        for solve_xhashcash in (True, False):
            async with self.__request(
                "POST",
                self._entrypoint,
                params=params,
                json=json if isinstance(json, list) else [json],
                headers=headers,
            ) as resp:
                # Since around feb 2025, MEGA requires clients to solve a challenge during each login attempt.
                # When that happens, initial responses returns "402 Payment Required".
                # We need to solve the challenge and re-made the request with same params + the computed token
                # See:  https://github.com/gpailler/MegaApiClient/issues/248#issuecomment-2692361193

                if xhashcash_challenge := resp.headers.get("X-Hashcash"):
                    if not solve_xhashcash:
                        msg = f"Login failed. Mega requested a proof of work with xhashcash: {xhashcash_challenge}"
                        raise RequestError(msg)

                    headers["X-Hashcash"] = await asyncio.to_thread(generate_hashcash_token, xhashcash_challenge)
                    continue

                return await self._parse_response(resp)

        raise ValueError

    @contextlib.asynccontextmanager
    async def get(
        self, url: str | yarl.URL, headers: Mapping[str, str] | None = None
    ) -> AsyncGenerator[aiohttp.ClientResponse]:
        async with self.__request("GET", url, headers=headers) as resp:
            resp.raise_for_status()
            yield resp

    async def upload_chunk(self, upload_url: str | yarl.URL, offset: int, data: bytes) -> str:
        async with self.__request("POST", yarl.URL(upload_url) / str(offset), data=data) as resp:
            return await resp.text()

    @contextlib.asynccontextmanager
    async def __request(
        self,
        method: Literal["GET", "POST"],
        url: str | yarl.URL,
        headers: Mapping[str, str] | None = None,
        **kwargs: Any,
    ) -> AsyncGenerator[aiohttp.ClientResponse]:
        kwargs["headers"] = _DEFAULT_HEADERS | (headers or {})
        params = ", ".join(f"{name} = {value!r}" for name, value in kwargs.items())
        logger.debug(f"Making {method} request to {url!s} with {params}")
        async with self._rate_limiter, self._session.request(method, url, **kwargs) as resp:
            yield resp

    @staticmethod
    async def _parse_response(response: aiohttp.ClientResponse) -> Any:
        json_resp = await response.json()
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


class AbstractApiClient:
    __slots__ = ("_api",)

    def __init__(self, session: aiohttp.ClientSession | None = None) -> None:
        self._api: MegaAPI = MegaAPI(session)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()

    async def close(self) -> None:
        await self._api.close()
