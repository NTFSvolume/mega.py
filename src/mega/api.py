from __future__ import annotations

import logging
import random
import string
from typing import TYPE_CHECKING, Any

from aiohttp import ClientSession, ClientTimeout
from tenacity import retry, retry_if_exception_type, wait_exponential

from mega.crypto import random_u32int

from .errors import RequestError
from .xhashcash import generate_hashcash_token

if TYPE_CHECKING:
    from mega.data_structures import AnyDict, U32Int

VALID_REQUEST_ID_CHARS = string.ascii_letters + string.digits


logger = logging.getLogger(__name__)


class MegaApi:
    def __init__(self) -> None:
        self.schema = "https"
        self.domain = "mega.nz"
        # api still uses the old mega.co.nz domain
        self.api_domain = "g.api.mega.co.nz"
        self.sid: str | None = None
        self.timeout = ClientTimeout(160)
        self.sequence_num: U32Int = random_u32int()
        self.request_id: str = "".join(random.choice(VALID_REQUEST_ID_CHARS) for _ in range(10))
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0"
        self.default_headers = {"Content-Type": "application/json", "User-Agent": self.user_agent}
        self.session: ClientSession = None  # type: ignore

    async def close(self):
        if self.session:
            await self.session.close()

    @property
    def entrypoint(self) -> str:
        return f"{self.schema}://{self.api_domain}/cs"

    @retry(retry=retry_if_exception_type(RuntimeError), wait=wait_exponential(multiplier=2, min=2, max=60))
    async def request(self, data_input: list[AnyDict] | AnyDict, add_params: AnyDict | None = None) -> Any:
        if not self.session:
            self.session = ClientSession(timeout=self.timeout)

        add_params = add_params or {}

        params: AnyDict = {"id": self.sequence_num} | add_params
        self.sequence_num += 1

        if self.sid:
            params["sid"] = self.sid

        # ensure input data is a list
        if not isinstance(data_input, list):
            data = [data_input]
        else:
            data: list[AnyDict] = data_input

        response = await self.session.post(self.entrypoint, params=params, json=data, headers=self.default_headers)

        # Since around feb 2025, MEGA requires clients to solve a challenge during each login attempt.
        # When that happens, initial responses returns "402 Payment Required".
        # Challenge is inside the `X-Hashcash` header.
        # We need to solve the challenge and re-made the request with same params + the computed token
        # See:  https://github.com/gpailler/MegaApiClient/issues/248#issuecomment-2692361193

        if xhashcash_challenge := response.headers.get("X-Hashcash"):
            logger.info("Solving xhashcash login challenge, this could take a few seconds...")
            xhashcash_token = generate_hashcash_token(xhashcash_challenge)
            headers = self.default_headers | {"X-Hashcash": xhashcash_token}
            response = await self.session.post(
                self.entrypoint, params=params, json=data, timeout=self.timeout, headers=headers
            )

        if xhashcash_challenge := response.headers.get("X-Hashcash"):
            # Computed token failed
            msg = f"Login failed. Mega requested a proof of work with xhashcash: {xhashcash_challenge}"
            raise RequestError(msg)

        json_resp: list[Any] | list[int] | int = await response.json()

        def handle_int_resp(int_resp: int):
            if int_resp == 0:
                return int_resp
            if int_resp == -3:
                msg = "Request failed, retrying"
                logger.info(msg)
                raise RuntimeError(msg)
            raise RequestError(int_resp)

        if isinstance(json_resp, int):
            return handle_int_resp(json_resp)
        elif not isinstance(json_resp, list):
            raise RequestError(f"Unknown response: {json_resp:r}")
        elif json_resp:
            first = json_resp[0]
            if isinstance(first, int):
                return handle_int_resp(first)
            return first
        else:
            raise RequestError(f"Unknown response: {json_resp:r}")
