from __future__ import annotations

import logging
import random
import string
from typing import Any, cast

import requests
from tenacity import retry, retry_if_exception_type, wait_exponential

from mega.crypto import (
    a32_to_bytes,
    base64_to_a32,
    base64_url_decode,
    base64_url_encode,
    decrypt_attr,
    decrypt_key,
    decrypt_rsa_key,
    encrypt_key,
    mpi_to_int,
    random_u32int,
    str_to_a32,
)
from mega.data_structures import (
    AnyDict,
    Array,
    Attributes,
    FileOrFolder,
    NodeType,
    SharedKey,
    SharedkeysDict,
    U32Int,
)

from .errors import RequestError
from .xhashcash import generate_hashcash_token

VALID_REQUEST_ID_CHARS = string.ascii_letters + string.digits


def make_request_id(length: int = 10) -> str:
    text = ""
    for _ in range(length):
        text += random.choice(VALID_REQUEST_ID_CHARS)
    return text


logger = logging.getLogger(__name__)


class MegaApi:
    def __init__(self, options: AnyDict | None = None) -> None:
        self.schema = "https"
        self.domain = "mega.nz"
        # api still uses the old mega.co.nz domain
        self.api_domain = "g.api.mega.co.nz"
        self.timeout = 160  # max secs to wait for resp from api requests
        self.sid = None
        self.sequence_num: U32Int = random_u32int()
        self.request_id: str = make_request_id()
        self._trash_folder_node_id: str | None = None

    def _process_login(self, resp: AnyDict, password: Array):
        encrypted_master_key = base64_to_a32(resp["k"])
        self.master_key = decrypt_key(encrypted_master_key, password)
        if b64_tsid := resp.get("tsid"):
            tsid = base64_url_decode(b64_tsid)
            key_encrypted = a32_to_bytes(encrypt_key(str_to_a32(tsid[:16]), self.master_key))
            if key_encrypted == tsid[-16:]:
                self.sid = resp["tsid"]

        elif b64_csid := resp.get("csid"):
            encrypted_sid = mpi_to_int(base64_url_decode(b64_csid))
            encrypted_private_key = base64_to_a32(resp["privk"])
            private_key = a32_to_bytes(decrypt_key(encrypted_private_key, self.master_key))
            rsa_key = decrypt_rsa_key(private_key)

            # TODO: Investigate how to decrypt using the current pycryptodome library.
            # The _decrypt method of RSA is deprecated and no longer available.
            # The documentation suggests using Crypto.Cipher.PKCS1_OAEP,
            # but the algorithm differs and requires bytes as input instead of integers.
            decrypted_sid = int(rsa_key._decrypt(encrypted_sid))  # type: ignore
            sid_hex = f"{decrypted_sid:x}"
            sid_bytes = bytes.fromhex("0" + sid_hex if len(sid_hex) % 2 else sid_hex)
            sid = base64_url_encode(sid_bytes[:43])
            self.sid = sid

    @retry(retry=retry_if_exception_type(RuntimeError), wait=wait_exponential(multiplier=2, min=2, max=60))
    def _api_request(self, data_input: list[AnyDict] | AnyDict) -> Any:
        params: AnyDict = {"id": self.sequence_num}
        self.sequence_num += 1
        DEFAULT_HEADERS = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
        }

        if self.sid:
            params["sid"] = self.sid

        # ensure input data is a list
        if not isinstance(data_input, list):
            data = [data_input]
        else:
            data: list[AnyDict] = data_input

        url = f"{self.schema}://{self.api_domain}/cs"

        response = requests.post(url, params=params, json=data, timeout=self.timeout, headers=DEFAULT_HEADERS)

        # Since around feb 2025, MEGA requires clients to solve a challenge during each login attempt.
        # When that happens, initial responses returns "402 Payment Required".
        # Challenge is inside the `X-Hashcash` header.
        # We need to solve the challenge and re-made the request with same params + the computed token
        # See:  https://github.com/gpailler/MegaApiClient/issues/248#issuecomment-2692361193

        if xhashcash_challenge := response.headers.get("X-Hashcash"):
            logger.info("Solving xhashcash login challenge, this could take a few seconds...")
            xhashcash_token = generate_hashcash_token(xhashcash_challenge)
            new_headers = DEFAULT_HEADERS | {"X-Hashcash": xhashcash_token}
            response = requests.post(url, params=params, json=data, timeout=self.timeout, headers=new_headers)

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

    def _process_file(self, file: FileOrFolder, shared_keys: SharedkeysDict) -> FileOrFolder:
        if file["t"] == NodeType.FILE or file["t"] == NodeType.FOLDER:
            keys = dict(keypart.split(":", 1) for keypart in file["k"].split("/") if ":" in keypart)
            uid = file["u"]
            key = None
            # my objects
            if uid in keys:
                key = decrypt_key(base64_to_a32(keys[uid]), self.master_key)
            # shared folders
            elif "su" in file and "sk" in file and ":" in file["k"]:
                shared_key = decrypt_key(base64_to_a32(file["sk"]), self.master_key)
                key = decrypt_key(base64_to_a32(keys[file["h"]]), shared_key)
                if file["su"] not in shared_keys:
                    shared_keys[file["su"]] = {}
                shared_keys[file["su"]][file["h"]] = shared_key
            # shared files
            elif file["u"] and file["u"] in shared_keys:
                for hkey in shared_keys[file["u"]]:
                    shared_key = shared_keys[file["u"]][hkey]
                    if hkey in keys:
                        key = keys[hkey]
                        key = decrypt_key(base64_to_a32(key), shared_key)
                        break
            if file["h"] and file["h"] in shared_keys.get("EXP", ()):
                shared_key = shared_keys["EXP"][file["h"]]
                encrypted_key = str_to_a32(base64_url_decode(file["k"].split(":")[-1]))
                key = decrypt_key(encrypted_key, shared_key)
                file["sk_decrypted"] = shared_key

            if key is not None:
                # file
                if file["t"] == NodeType.FILE:
                    k = (key[0] ^ key[4], key[1] ^ key[5], key[2] ^ key[6], key[3] ^ key[7])
                    file["iv"] = key[4:6] + (0, 0)
                    file["meta_mac"] = key[6:8]
                # folder
                else:
                    k = key

                file["key"] = key
                file["k_decrypted"] = k
                attributes_bytes = base64_url_decode(file["a"])
                attributes = decrypt_attr(attributes_bytes, k)
                file["attributes"] = cast(Attributes, attributes)

            # other => wrong object
            elif file["k"] == "":
                file["attributes"] = {"n": "Unknown Object"}

        elif file["t"] == NodeType.ROOT_FOLDER:
            self.root_id: str = file["h"]
            file["attributes"] = {"n": "Cloud Drive"}

        elif file["t"] == NodeType.INBOX:
            self.inbox_id = file["h"]
            file["attributes"] = {"n": "Inbox"}

        elif file["t"] == NodeType.TRASH:
            self.trashbin_id = file["h"]
            file["attributes"] = {"n": "Rubbish Bin"}

        return file

    def _init_shared_keys(self, files: dict[str, list[FileOrFolder]], shared_keys: SharedkeysDict) -> None:
        """
        Init shared key not associated with a user.
        Seems to happen when a folder is shared,
        some files are exchanged and then the
        folder is un-shared.
        Keys are stored in files['s'] and files['ok']
        """
        shared_key: SharedKey = {}
        for ok_item in files["ok"]:
            decrypted_shared_key = decrypt_key(base64_to_a32(ok_item["k"]), self.master_key)
            shared_key[ok_item["h"]] = decrypted_shared_key
        for s_item in files["s"]:
            if s_item["u"] not in shared_keys:
                shared_keys[s_item["u"]] = {}
            if s_item["h"] in shared_key:
                shared_keys[s_item["u"]][s_item["h"]] = shared_key[s_item["h"]]
        self.shared_keys = shared_keys
