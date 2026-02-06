from __future__ import annotations

import dataclasses
import logging
import os
from os import PathLike
from pathlib import Path
from typing import TYPE_CHECKING, Self

from Crypto.Cipher import AES
from Crypto.Util import Counter

from mega.crypto import (
    CHUNK_BLOCK_LEN,
    EMPTY_IV,
    a32_to_base64,
    a32_to_bytes,
    b64_url_encode,
    encrypt_attr,
    encrypt_key,
    get_chunks,
    pad_bytes,
    random_u32int,
    str_to_a32,
)

if TYPE_CHECKING:
    from collections.abc import Generator

    from mega.api import MegaAPI
    from mega.core import MegaCore
    from mega.data_structures import GetNodesResponse, NodeID


logger = logging.getLogger(__name__)


@dataclasses.dataclass(slots=True)
class MegaEncryptor:
    iv: tuple[int, ...]
    key: tuple[int, ...]
    file_size: int
    expected_mac: tuple[int, int] | None = None
    _gen: Generator[bytes, bytes | None, tuple[int, int]] = dataclasses.field(init=False)

    def __post_init__(self) -> None:
        self._gen = _encrypt_chunks(self.iv, self.key)

    def __enter__(self) -> Self:
        first = next(self._gen)
        assert first == b""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if exc_val is None and self.expected_mac:
            self.check_integrity(self.expected_mac)

    def encrypt(self, raw_chunk: bytes) -> bytes:
        return self._gen.send(raw_chunk)

    def compute_meta_mac(self) -> tuple[int, int]:
        try:
            _ = self._gen.send(None)
        except StopIteration as e:
            return e.value
        else:
            raise RuntimeError

    def check_integrity(self, expected_mac: tuple[int, int]) -> None:
        meta_mac = self.compute_meta_mac()
        if expected_mac != meta_mac:
            raise RuntimeError("Mismatched mac")


def _encrypt_chunks(
    iv: tuple[int, ...],
    key: tuple[int, ...],
) -> Generator[bytes, bytes | None, tuple[int, int]]:
    key_bytes = a32_to_bytes(key)
    counter = Counter.new(128, initial_value=((iv[0] << 32) + iv[1]) << 64)
    aes = AES.new(key_bytes, AES.MODE_CTR, counter=counter)

    mac_bytes = EMPTY_IV
    mac_encryptor = AES.new(key_bytes, AES.MODE_CBC, mac_bytes)
    iv_bytes = a32_to_bytes([iv[0], iv[1], iv[0], iv[1]])
    chunk: bytes | None = yield b""

    while chunk is not None:
        encryptor = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        mem_view = memoryview(chunk)
        last_16b_index = len(chunk) % CHUNK_BLOCK_LEN or CHUNK_BLOCK_LEN
        last_16b = pad_bytes(mem_view[-last_16b_index:])
        encryptor.encrypt(mem_view[:-last_16b_index])
        mac_bytes = mac_encryptor.encrypt(encryptor.encrypt(last_16b))
        chunk = yield aes.encrypt(chunk)

    file_mac = str_to_a32(mac_bytes)
    meta_mac = file_mac[0] ^ file_mac[1], file_mac[2] ^ file_mac[3]
    return meta_mac


async def _request_upload(api: MegaAPI, file_size: int) -> str:
    resp = await api.request({"a": "u", "s": file_size})
    return resp["p"]


async def upload(self: MegaCore, file_path: str | PathLike[str], dest_node_id: NodeID) -> GetNodesResponse:
    file_path = Path(file_path)
    with file_path.open("rb") as input_file:
        file_size = os.path.getsize(file_path)
        upload_url = await _request_upload(self._api, file_size)
        random_key = tuple(random_u32int() for _ in range(6))
        key, iv = random_key[:4], random_key[4:6]

        upload_progress = 0
        file_handle = ""

        cypher = MegaEncryptor(iv, key, file_size)
        for offset, chunk_size in get_chunks(file_size):
            chunk = cypher.encrypt(input_file.read(chunk_size))
            file_handle = await self._api.upload_chunk(upload_url, offset, chunk)
            upload_progress += len(chunk)
            logger.info(f"{upload_progress} of {file_size} uploaded ({upload_progress / file_size:0.1f}%)")

        meta_mac = cypher.compute_meta_mac()
        full_key: tuple[int, ...] = (
            key[0] ^ iv[0],
            key[1] ^ iv[1],
            key[2] ^ meta_mac[0],
            key[3] ^ meta_mac[1],
            *iv,
            *meta_mac,
        )

        logger.info("Chunks uploaded")
        return await _finish_file_upload(
            self._api,
            self._vault.master_key,
            file_handle,
            file_path,
            dest_node_id,
            full_key,
            key,
        )


async def _finish_file_upload(
    api: MegaAPI,
    master_key: tuple[int, ...],
    file_id: NodeID,
    file_path: Path,
    dest_node_id: str,
    full_key: tuple[int, ...],
    key: tuple[int, ...],
):
    logger.info(f"Setting attributes to complete upload of {file_path}")
    encrypt_attribs = b64_url_encode(encrypt_attr({"n": file_path.name}, key))
    encrypted_key = a32_to_base64(encrypt_key(full_key, master_key))

    data: GetNodesResponse = await api.request(
        {
            "a": "p",
            "t": dest_node_id,
            "i": api._client_id,
            "n": [
                {
                    "h": file_id,
                    "t": 0,
                    "a": encrypt_attribs,
                    "k": encrypted_key,
                }
            ],
        }
    )
    logger.info("Upload complete")
    return data
