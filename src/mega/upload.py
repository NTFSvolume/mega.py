from __future__ import annotations

import logging
from typing import IO, TYPE_CHECKING

from mega import progress
from mega.chunker import MegaChunker
from mega.crypto import a32_to_base64, b64_url_encode, encrypt_attr, encrypt_key, get_chunks
from mega.data_structures import Crypto
from mega.utils import random_u32int_array

if TYPE_CHECKING:
    from pathlib import Path

    from mega.api import MegaAPI
    from mega.data_structures import GetNodesResponse, NodeID


logger = logging.getLogger(__name__)


async def _request_upload_url(api: MegaAPI, file_size: int) -> str:
    return (await api.request({"a": "u", "s": file_size}))["p"]


async def upload(api: MegaAPI, file_path: Path, file_size: int) -> tuple[str, Crypto]:
    with file_path.open("rb") as input_file:
        random_array = random_u32int_array(6)
        key, iv = random_array[:4], random_array[4:]

        if file_size == 0:
            upload_url = await _request_upload_url(api, file_size)
            file_handle = await api.upload_chunk(upload_url, 0, b"")
            meta_mac = 0, 0
            return file_handle, Crypto.compose(key, iv, meta_mac)

        chunker = MegaChunker(iv, key)
        return await _upload_chunks(api, chunker, input_file, file_size)


async def _upload_chunks(
    api: MegaAPI,
    chunker: MegaChunker,
    input_file: IO[bytes],
    file_size: int,
) -> tuple[str, Crypto]:
    upload_progress = 0
    file_handle = ""
    upload_url = await _request_upload_url(api, file_size)
    progress_hook = progress.current_hook.get()

    for offset, size in get_chunks(file_size):
        chunk = chunker.read(input_file.read(size))
        file_handle = await api.upload_chunk(upload_url, offset, chunk)
        logger.info(f"{upload_progress} of {file_size} uploaded ({upload_progress / file_size:0.1f}%)")
        real_size = len(chunk)
        upload_progress += real_size
        progress_hook(real_size)

    assert file_handle
    return file_handle, Crypto.compose(chunker.key, chunker.iv, chunker.compute_meta_mac())


async def finish_upload(
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
                },
            ],
        },
    )
    logger.info("Upload complete")
    return data
