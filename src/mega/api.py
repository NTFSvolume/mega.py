from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import string
from typing import TYPE_CHECKING, Any, Self

import aiohttp
import tenacity
import yarl

from mega.crypto import generate_hashcash_token, random_u32int

from .errors import RequestError, RetryRequestError

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator


logger = logging.getLogger(__name__)


class MegaAPI:
    __slots__ = (
        "__session",
        "_client_id",
        "_default_headers",
        "_entrypoint",
        "_managed_session",
        "_request_id",
        "session_id",
    )

    def __init__(self, session: aiohttp.ClientSession | None = None) -> None:
        self.session_id: str | None = None
        self._request_id: int = random_u32int()
        self._client_id: str = "".join(random.choices(string.ascii_letters + string.digits, k=10))
        self._default_headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
        }
        self.__session: aiohttp.ClientSession | None = session
        self._managed_session: bool = session is not None
        self._entrypoint: yarl.URL = yarl.URL("https://g.api.mega.co.nz/cs")  # api still uses the old mega.co.nz domain

    def __repr__(self) -> str:
        return f"<{type(self).__name__}>(session_id={self.session_id!r}, client_id={self._client_id!r})"

    async def close(self) -> None:
        if self._managed_session and self.__session:
            await self.__session.close()

    async def __enter__(self) -> Self:
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()

    def _lazy_session(self) -> aiohttp.ClientSession:
        if self.__session is None:
            self.__session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(sock_connect=160, sock_read=60))
        return self.__session

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(RetryRequestError),
        wait=tenacity.wait_exponential(multiplier=2, min=2, max=60),
    )
    async def request(self, data: dict[str, Any] | list[dict[str, Any]], params: dict[str, Any] | None = None) -> Any:
        params = {"id": self._request_id} | (params or {})
        self._request_id += 1
        if self.session_id:
            params["sid"] = self.session_id

        if not isinstance(data, list):
            data = [data]

        headers = self._default_headers

        for solve_xhashcash in (True, False):
            logger.debug(f"Making POST request with {params=!r} {data=!r} {headers=!r}")
            async with self._lazy_session().post(
                self._entrypoint, params=params, json=data, headers=headers
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
                    headers = self._default_headers | {"X-Hashcash": xhashcash_token}
                    continue

                return await self._process_resp(response)

        else:
            raise ValueError

    @contextlib.asynccontextmanager
    async def download(self, url: str | yarl.URL) -> AsyncGenerator[aiohttp.ClientResponse]:
        async with self._lazy_session().get(url, headers=self._default_headers) as resp:
            resp.raise_for_status()
            yield resp

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
