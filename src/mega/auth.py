from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import logging
from typing import TYPE_CHECKING, Any, NamedTuple

from mega.crypto import (
    a32_to_base64,
    a32_to_bytes,
    b64_to_a32,
    b64_url_decode,
    b64_url_encode,
    decrypt_key,
    decrypt_rsa_key,
    encrypt_key,
    generate_v1_hash,
    mpi_to_int,
    prepare_v1_key,
    str_to_a32,
)
from mega.utils import random_u32int_array

if TYPE_CHECKING:
    from Crypto.PublicKey.RSA import RsaKey

    from mega.api import MegaAPI


logger = logging.getLogger(__name__)


@dataclasses.dataclass(slots=True, frozen=True)
class AuthInfo:
    email: str
    password_aes_key: tuple[int, int, int, int]
    hash: str
    mfa_key: str | None = None


class Credentials(NamedTuple):
    master_key: tuple[int, ...]
    session_id: str


async def login_anonymous(api: MegaAPI) -> Credentials:
    logger.info("Logging as an anonymous temporary user...")

    master_key = random_u32int_array(4)
    password_aes_key = random_u32int_array(4)
    session_challenge = random_u32int_array(4)

    user_id: str = await api.post(
        {
            "a": "up",
            "k": a32_to_base64(encrypt_key(master_key, password_aes_key)),
            "ts": b64_url_encode(
                a32_to_bytes(session_challenge) + a32_to_bytes(encrypt_key(session_challenge, master_key)),
            ),
        },
    )

    temp_session_id: str = (await api.post({"a": "us", "user": user_id}))["tsid"]
    _verify_anon_login(temp_session_id, master_key)
    return Credentials(master_key, temp_session_id)


def _verify_anon_login(b64_temp_session_id: str, master_key: tuple[int, ...]) -> None:
    tsid = b64_url_decode(b64_temp_session_id)
    user_hash = a32_to_bytes(encrypt_key(str_to_a32(tsid[:16]), master_key))
    if user_hash != tsid[-16:]:
        raise RuntimeError


async def login(api: MegaAPI, email: str, password: str, _mfa: str | None = None) -> Credentials:
    email = email.lower()
    logger.info(f"Login in as {email}...")
    auth = await get_auth_info(api, email, password)
    resp = await api.post(
        {
            "a": "us",
            "user": auth.email,
            "uh": auth.hash,
        },
    )

    b64_session_id: str = resp["csid"]
    b64_master_key: str = resp["k"]
    b64_private_key: str = resp["privk"]

    master_key = decrypt_key(b64_to_a32(b64_master_key), auth.password_aes_key)
    private_key = a32_to_bytes(decrypt_key(b64_to_a32(b64_private_key), master_key))
    rsa_key = decrypt_rsa_key(private_key)
    session_id = _decrypt_session_id(rsa_key, b64_session_id)
    return Credentials(master_key, session_id)


def _decrypt_session_id(rsa_key: RsaKey, b64_session_id: str) -> str:
    logger.debug("Decrypting session id")
    encrypted_sid = mpi_to_int(b64_url_decode(b64_session_id))

    # TODO: Investigate how to decrypt using the current pycryptodome library.
    # The _decrypt method of RSA is deprecated and no longer available.
    # The documentation suggests using Crypto.Cipher.PKCS1_OAEP,
    # but the algorithm differs and requires bytes as input instead of integers.
    decrypted_sid = int(rsa_key._decrypt(encrypted_sid))  # type: ignore  # pyright: ignore[reportUnknownMemberType, reportAttributeAccessIssue, reportUnknownArgumentType]
    sid_bytes = decrypted_sid.to_bytes((decrypted_sid.bit_length() + 7) // 8 or 1, "big")
    session_id = b64_url_encode(sid_bytes[:43])
    return session_id


async def get_auth_info(api: MegaAPI, email: str, password: str, mfa_key: str | None = None) -> AuthInfo:
    email = email.lower()
    resp: dict[str, Any] = await api.post(
        {
            "a": "us0",
            "user": email,
        },
    )
    version: int = resp["v"]
    salt: str | None = resp.get("s")

    if version == 2 and salt:
        pbkdf2_key = await asyncio.to_thread(
            hashlib.pbkdf2_hmac,
            hash_name="sha512",
            password=password.encode(),
            salt=b64_url_decode(salt),
            iterations=100_000,
            dklen=32,
        )
        password_aes = str_to_a32(pbkdf2_key[:16])
        user_hash = b64_url_encode(pbkdf2_key[-16:])

    elif version == 1:
        password_aes = prepare_v1_key(password)
        user_hash = generate_v1_hash(email, password_aes)

    else:
        raise RuntimeError(f"Account version not supported: {version = }")

    return AuthInfo(email, password_aes, user_hash, mfa_key)  # pyright: ignore[reportArgumentType]
