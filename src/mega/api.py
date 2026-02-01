from __future__ import annotations

import logging
import random
import string
from typing import TYPE_CHECKING, Any

import aiohttp
import tenacity
import yarl
from typing_extensions import Self

from mega.crypto import random_u32int

from .errors import RequestError
from .xhashcash import generate_hashcash_token

if TYPE_CHECKING:
    from mega.data_structures import U32Int


logger = logging.getLogger(__name__)


class MegaApi:
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
        self._request_id: U32Int = random_u32int()
        self._client_id: str = "".join(random.choices(string.ascii_letters + string.digits, k=10))
        self._default_headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
        }
        self.__session: aiohttp.ClientSession | None = session
        self._managed_session: bool = session is not None
        self._entrypoint: yarl.URL = yarl.URL("https://g.api.mega.co.nz/cs")  # api still uses the old mega.co.nz domain

    def __repr__(self) -> str:
        return f"<{type(self).__name__}>  (session_id={self.session_id!r}, client_id={self._client_id!r})"

    async def close(self) -> None:
        if self._managed_session and self.__session:
            await self.__session.close()

    async def __enter__(self) -> Self:
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()

    def _get_session(self) -> aiohttp.ClientSession:
        if self.__session is None:
            self.__session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(160))
        return self.__session

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(RuntimeError),
        wait=tenacity.wait_exponential(multiplier=2, min=2, max=60),
    )
    async def request(self, data: dict[str, Any], params: dict[str, Any] | None = None) -> Any:
        params = {"id": self._request_id} | (params or {})
        self._request_id += 1
        if self.session_id:
            params["sid"] = self.session_id

        session = self._get_session()
        headers = self._default_headers

        for retry in (True, False):
            response = await session.post(self._entrypoint, params=params, json=[data], headers=headers)

            # Since around feb 2025, MEGA requires clients to solve a challenge during each login attempt.
            # When that happens, initial responses returns "402 Payment Required".
            # Challenge is inside the `X-Hashcash` header.
            # We need to solve the challenge and re-made the request with same params + the computed token
            # See:  https://github.com/gpailler/MegaApiClient/issues/248#issuecomment-2692361193

            if xhashcash_challenge := response.headers.get("X-Hashcash"):
                if not retry:
                    msg = f"Login failed. Mega requested a proof of work with xhashcash: {xhashcash_challenge}"
                    raise RequestError(msg)

                logger.info("Solving xhashcash login challenge, this could take a few seconds...")
                xhashcash_token = generate_hashcash_token(xhashcash_challenge)
                headers = self._default_headers | {"X-Hashcash": xhashcash_token}
                continue
            break
        else:
            raise ValueError

        json_resp: list[Any] | int = await response.json()

        if isinstance(json_resp, int):
            if json_resp == 0:
                return json_resp
            if json_resp == -3:
                msg = "Request failed, retrying"
                logger.warning(msg)
                raise RuntimeError(msg)
            raise RequestError(json_resp)

        if json_resp and isinstance(json_resp, list):
            return json_resp[0]

        raise RequestError(f"Unknown response: {json_resp:r}")
