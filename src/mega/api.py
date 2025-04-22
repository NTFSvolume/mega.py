from __future__ import annotations

import logging
import random
import string
from typing import TYPE_CHECKING, Any

import requests
from tenacity import retry, retry_if_exception_type, wait_exponential

from mega.crypto import random_u32int

from .errors import RequestError
from .xhashcash import generate_hashcash_token

if TYPE_CHECKING:
    from mega.data_structures import AnyDict, U32Int

VALID_REQUEST_ID_CHARS = string.ascii_letters + string.digits

DEFAULT_HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
}


def make_request_id(length: int = 10) -> str:
    text = ""
    for _ in range(length):
        text += random.choice(VALID_REQUEST_ID_CHARS)
    return text


logger = logging.getLogger(__name__)


class MegaApi:
    def __init__(self) -> None:
        self.schema = "https"
        self.domain = "mega.nz"
        # api still uses the old mega.co.nz domain
        self.api_domain = "g.api.mega.co.nz"
        self.timeout = 160  # max secs to wait for resp from api requests
        self.sid: str | None = None
        self.sequence_num: U32Int = random_u32int()
        self.request_id: str = make_request_id()

    @property
    def entrypoint(self) -> str:
        return f"{self.schema}://{self.api_domain}/cs"

    @retry(retry=retry_if_exception_type(RuntimeError), wait=wait_exponential(multiplier=2, min=2, max=60))
    def request(self, data_input: list[AnyDict] | AnyDict) -> Any:
        params: AnyDict = {"id": self.sequence_num}
        self.sequence_num += 1

        if self.sid:
            params["sid"] = self.sid

        # ensure input data is a list
        if not isinstance(data_input, list):
            data = [data_input]
        else:
            data: list[AnyDict] = data_input

        response = requests.post(
            self.entrypoint, params=params, json=data, timeout=self.timeout, headers=DEFAULT_HEADERS
        )

        # Since around feb 2025, MEGA requires clients to solve a challenge during each login attempt.
        # When that happens, initial responses returns "402 Payment Required".
        # Challenge is inside the `X-Hashcash` header.
        # We need to solve the challenge and re-made the request with same params + the computed token
        # See:  https://github.com/gpailler/MegaApiClient/issues/248#issuecomment-2692361193

        if xhashcash_challenge := response.headers.get("X-Hashcash"):
            logger.info("Solving xhashcash login challenge, this could take a few seconds...")
            xhashcash_token = generate_hashcash_token(xhashcash_challenge)
            new_headers = DEFAULT_HEADERS | {"X-Hashcash": xhashcash_token}
            response = requests.post(
                self.entrypoint, params=params, json=data, timeout=self.timeout, headers=new_headers
            )

        if xhashcash_challenge := response.headers.get("X-Hashcash"):
            # Computed token failed
            msg = f"Login failed. Mega requested a proof of work with xhashcash: {xhashcash_challenge}"
            raise RequestError(msg)

        json_resp: list[AnyDict] | list[int] | int = response.json()

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
