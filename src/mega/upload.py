from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

from mega.chunker import MegaChunker
from mega.crypto import a32_to_base64, b64_url_encode, encrypt_attr, encrypt_key, get_chunks, random_u32int
from mega.data_structures import Crypto

if TYPE_CHECKING:
    from pathlib import Path

    from mega.api import MegaAPI
    from mega.data_structures import GetNodesResponse, NodeID


logger = logging.getLogger(__name__)


async def _request_upload(api: MegaAPI, file_size: int) -> str:
    resp = await api.request({"a": "u", "s": file_size})
    return resp["p"]


async def upload(api: MegaAPI, file_path: Path) -> tuple[str, Crypto]:
    with file_path.open("rb") as input_file:
        file_size = os.path.getsize(file_path)
        upload_url = await _request_upload(api, file_size)
        random_key = tuple(random_u32int() for _ in range(6))
        key, iv = random_key[:4], random_key[4:6]

        upload_progress = 0
        file_handle = ""

        chunker = MegaChunker(iv, key)
        for offset, size in get_chunks(file_size):
            chunk = chunker.read(input_file.read(size))
            file_handle = await api.upload_chunk(upload_url, offset, chunk)
            upload_progress += len(chunk)
            logger.info(f"{upload_progress} of {file_size} uploaded ({upload_progress / file_size:0.1f}%)")

        meta_mac = chunker.compute_meta_mac()
        full_key: tuple[int, ...] = (
            key[0] ^ iv[0],
            key[1] ^ iv[1],
            key[2] ^ meta_mac[0],
            key[3] ^ meta_mac[1],
            *iv,
            *meta_mac,
        )
        logger.info("Chunks uploaded")
        return file_handle, Crypto(key, iv, meta_mac, full_key, None)  # pyright: ignore[reportArgumentType]


async def finish_file_upload(
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
