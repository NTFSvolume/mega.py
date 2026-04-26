from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import logging
import uuid
from collections.abc import Mapping, Sequence
from functools import wraps
from typing import TYPE_CHECKING, Any, ClassVar, Generic, Literal, ParamSpec, Self, TypeVar

import aiohttp
import yarl
from aiolimiter import AsyncLimiter

from mega import LOG_HTTP_TRAFFIC, __version__, _package_name_
from mega.crypto import generate_hashcash
from mega.errors import RequestError, RetryRequestError
from mega.utils import random_id, random_u32int

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Callable, Coroutine

    _P = ParamSpec("_P")
    _R = TypeVar("_R")


logger = logging.getLogger(__name__)


def retry(
    *,
    exceptions: Sequence[type[Exception]] | type[Exception],
    attempts: int = 10,
    delay: float = 0.5,
    max_delay: float = 30.0,
    backoff: int = 2,
) -> Callable[[Callable[_P, Coroutine[None, None, _R]]], Callable[_P, Coroutine[None, None, _R]]]:
    min_delay: float = 2.0
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


@dataclasses.dataclass(slots=True, weakref_slot=True)
class MegaAPI:
    _session: aiohttp.ClientSession | None = None

    user_agent: str = f"{_package_name_}/{__version__}"

    session_id: str | None = dataclasses.field(init=False, default=None)
    _request_id: int = dataclasses.field(init=False, default_factory=random_u32int)
    _client_id: str = dataclasses.field(init=False, default_factory=lambda: random_id(10))

    _auto_close_session: bool = dataclasses.field(init=False)
    _rate_limiter: AsyncLimiter = dataclasses.field(init=False, default_factory=lambda: AsyncLimiter(100, 60))

    _entrypoint: ClassVar[yarl.URL] = dataclasses.field(init=False, default=yarl.URL("https://g.api.mega.co.nz/cs"))

    def __post_init__(self) -> None:
        self._auto_close_session = self._session is None

    @property
    def entrypoint(self) -> yarl.URL:
        return self._entrypoint

    @property
    def client_id(self) -> str:
        return self._client_id

    def __repr__(self) -> str:
        return f"<{type(self).__name__}>(session_id={self.session_id!r}, client_id={self.client_id!r}, auto_close_session={self._auto_close_session!r})"

    async def aclose(self) -> None:
        if self._auto_close_session and self._session:
            await self._session.close()

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

                    headers["X-Hashcash"] = await asyncio.to_thread(generate_hashcash, xhashcash_challenge)
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
        kwargs["headers"] = {"User-Agent": self.user_agent, **(headers or {})}
        request_id = str(uuid.uuid4())
        if LOG_HTTP_TRAFFIC.get():
            logger.debug(
                "Starting %s request [id=%s] to %s \n%s",
                method,
                request_id,
                url,
                kwargs,
            )

        resp = None
        if self._session is None:
            self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(sock_connect=160, sock_read=60))

        try:
            async with self._rate_limiter, self._session.request(method, url, **kwargs) as resp:
                yield resp
        except RetryRequestError:
            logger.warning("Request [id=%s] failed, retrying", request_id)
            raise
        finally:
            if resp and LOG_HTTP_TRAFFIC.get():
                logger.debug(
                    "Finished %s request [id=%s]\n%s",
                    method,
                    request_id,
                    _LazyResponseLog(resp),
                )

    @staticmethod
    async def _parse_response(response: aiohttp.ClientResponse) -> Any:
        json_resp = await response.json()
        resp = json_resp

        if isinstance(json_resp, list) and len(json_resp) == 1:
            resp = json_resp[0]

        if isinstance(resp, int):
            if resp == 0:
                return resp

            if resp == -3:
                raise RetryRequestError
            raise RequestError(resp)

        return resp


class _LazyResponseLog:
    def __init__(self, resp: aiohttp.ClientResponse) -> None:
        self.resp = resp

    def __json__(self) -> dict[str, Any]:
        me = {
            "url": str(self.resp.url),
            "status_code": self.resp.status,
            "response_headers": dict(self.resp.headers),
            "content": None,
        }
        if self.resp._body:
            stripped = self.resp._body.strip()
            if stripped:
                content = json.loads(stripped.decode(self.resp.get_encoding()))
                me.update(content=content)

        return me

    def __str__(self) -> str:
        return str(self.__json__())


_API_T = TypeVar("_API_T", bound=MegaAPI, covariant=True)


class APIContextManager(Generic[_API_T]):
    __slots__ = ("_api",)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._api.aclose()

    close = aclose
