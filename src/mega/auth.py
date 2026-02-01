from __future__ import annotations

import dataclasses
import hashlib
import logging
from typing import TYPE_CHECKING, Any

from typing_extensions import Self

from mega.crypto import (
    a32_to_base64,
    a32_to_bytes,
    base64_to_a32,
    base64_url_decode,
    base64_url_encode,
    decrypt_key,
    decrypt_rsa_key,
    encrypt_key,
    generate_v1_hash,
    mpi_to_int,
    prepare_v1_key,
    random_u32int,
    str_to_a32,
)

if TYPE_CHECKING:
    from mega.api import MegaApi
    from mega.data_structures import TupleArray


logger = logging.getLogger(__name__)


@dataclasses.dataclass(slots=True, frozen=True)
class AuthInfo:
    email: str
    password_aes_key: tuple[int, int, int, int]
    hash: str
    mfa_key: str | None = None


@dataclasses.dataclass(slots=True, frozen=True)
class LoginResponse:
    session_id: str
    temp_session_id: str | None
    private_key: str
    master_key: str

    @classmethod
    def parse(cls, resp: dict[str, Any]) -> Self:
        return cls(
            session_id=resp.get("csid", ""),
            temp_session_id=resp.get("tsid"),
            master_key=resp["k"],
            private_key=resp["privk"],
        )


class MegaAuth:
    def __init__(self, api: MegaApi) -> None:
        self._api = api

    async def login_anonymous(self) -> tuple[TupleArray, str]:
        logger.info("Logging as an anonymous temporary user...")
        master_key = [random_u32int()] * 4
        password_aes_key = [random_u32int()] * 4
        session_self_challenge = [random_u32int()] * 4

        user: str = await self._api.request(
            {
                "a": "up",
                "k": a32_to_base64(encrypt_key(master_key, password_aes_key)),
                "ts": base64_url_encode(
                    a32_to_bytes(session_self_challenge) + a32_to_bytes(encrypt_key(session_self_challenge, master_key))
                ),
            }
        )

        resp = await self._api.request({"a": "us", "user": user})
        login = LoginResponse.parse(resp)

        real_master_key = decrypt_key(base64_to_a32(login.master_key), password_aes_key)
        tsid = base64_url_decode(login.temp_session_id)
        key_encrypted = a32_to_bytes(encrypt_key(str_to_a32(tsid[:16]), real_master_key))
        assert key_encrypted == tsid[-16:]
        return real_master_key, login.temp_session_id

    async def login(self, email: str, password: str, _mfa: str | None = None) -> tuple[TupleArray, str]:
        email = email.lower()
        logger.info("Logging in as user [REDACTED]...")
        auth = await self._get_info(email, password)
        resp = await self._api.request(
            {
                "a": "us",
                "user": auth.email,
                "uh": auth.hash,
            }
        )
        login = LoginResponse.parse(resp)
        master_key: tuple[int, int, int, int] = decrypt_key(base64_to_a32(login.master_key), auth.password_aes_key)

        encrypted_sid = mpi_to_int(base64_url_decode(login.session_id))
        encrypted_private_key: tuple[int, ...] = base64_to_a32(login.private_key)
        private_key = a32_to_bytes(decrypt_key(encrypted_private_key, master_key))
        rsa_key = decrypt_rsa_key(private_key)

        # TODO: Investigate how to decrypt using the current pycryptodome library.
        # The _decrypt method of RSA is deprecated and no longer available.
        # The documentation suggests using Crypto.Cipher.PKCS1_OAEP,
        # but the algorithm differs and requires bytes as input instead of integers.
        decrypted_sid = int(rsa_key._decrypt(encrypted_sid))  # type: ignore  # pyright: ignore[reportUnknownMemberType, reportAttributeAccessIssue, reportUnknownArgumentType]
        sid_bytes = decrypted_sid.to_bytes((decrypted_sid.bit_length() + 7) // 8 or 1, "big")
        session_id = base64_url_encode(sid_bytes[:43])
        return master_key, session_id

    async def _get_info(self, email: str, password: str, mfa_key: str | None = None) -> AuthInfo:
        email = email.lower()
        resp: dict[str, Any] = await self._api.request(
            {
                "a": "us0",
                "user": email,
            }
        )
        version: int = resp["v"]
        salt: str | None = resp.get("s")

        if version == 2 and salt:
            pbkdf2_key = hashlib.pbkdf2_hmac(
                hash_name="sha512",
                password=password.encode(),
                salt=base64_url_decode(salt),
                iterations=100_000,
                dklen=32,
            )
            password_aes = str_to_a32(pbkdf2_key[:16])
            user_hash = base64_url_encode(pbkdf2_key[-16:])

        elif version == 1:
            password_aes = prepare_v1_key(password)
            user_hash = generate_v1_hash(email, password_aes)

        else:
            raise RuntimeError(f"Account version not supported: {version = }")

        return AuthInfo(email, password_aes, user_hash, mfa_key)  # pyright: ignore[reportArgumentType]
