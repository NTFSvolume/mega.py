from __future__ import annotations

import asyncio
import dataclasses
import errno
import logging
import re
import shutil
import tempfile
from collections.abc import Generator
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from Crypto.Cipher import AES
from Crypto.Util import Counter

from mega.auth import MegaAuth
from mega.crypto import CHUNK_BLOCK_LEN, EMPTY_IV, a32_to_bytes, b64_to_a32, get_chunks, pad_bytes, str_to_a32
from mega.data_structures import Attributes, Node, NodeType
from mega.progress import ProgressManager
from mega.vault import MegaKeysVault

from .errors import ValidationError

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable, Mapping

    from mega.api import MegaAPI
    from mega.data_structures import GetNodesResponse, NodeSerialized, TupleArray


logger = logging.getLogger(__name__)


@dataclasses.dataclass(slots=True, frozen=True)
class SystemNodes:
    root: Node
    inbox: Node
    trash_bin: Node


class MegaCore:
    def __init__(self, api: MegaAPI) -> None:
        self._api = api
        self._primary_url = "https://mega.nz"
        self._system_nodes: SystemNodes | None = None
        self._auth = MegaAuth(self._api)
        self._vault = MegaKeysVault(())
        self._progress = ProgressManager()

    def __repr__(self) -> str:
        return f"<{type(self).__name__}>(system_nodes={self._system_nodes!r}, vault={self._vault!r})"

    @property
    def logged_in(self) -> bool:
        return bool(self._vault.master_key)

    @property
    def system_nodes(self) -> SystemNodes:
        assert self._system_nodes is not None
        return self._system_nodes

    async def login(self, email: str | None, password: str | None, _mfa: str | None = None) -> None:
        if email and password:
            master_key, self._api.session_id = await self._auth.login(email, password)
        else:
            master_key, self._api.session_id = await self._auth.login_anonymous()

        self._vault = MegaKeysVault(master_key)
        logger.info("Getting all files and decryption keys of the account...")
        _ = await self._get_nodes()
        logger.info(f"Special folders: {self._system_nodes}")
        logger.info("Login complete")

    def _deserialize_node(self, node: NodeSerialized) -> Node:
        return self._vault.decrypt(self._transform_node(node))

    @staticmethod
    def _transform_node(node: NodeSerialized) -> Node:
        if k := node.get("k"):
            keys = dict(key_pair.split(":", 1) for key_pair in k.split("/") if ":" in key_pair)
        else:
            keys = {}

        return Node(
            id=node["h"],
            parent_id=node["p"],
            owner=node["u"],
            creation_date=node["ts"],
            type=NodeType(node["t"]),
            keys=keys,
            share_owner=node.get("su"),
            share_key=node.get("sk"),
            attributes=Attributes(""),
            _a=node["a"],
        )

    @staticmethod
    def _parse_url(url: str) -> str:
        """Parse file id and key from url."""
        if "/file/" in url:
            # V2 URL structure
            # ex: https://mega.nz/file/cH51DYDR#qH7QOfRcM-7N9riZWdSjsRq
            url = url.replace(" ", "")
            file_id = re.findall(r"\W\w\w\w\w\w\w\w\w\W", url)[0][1:-1]
            match = re.search(file_id, url)
            assert match
            id_index = match.end()
            key = url[id_index + 1 :]
            return f"{file_id}!{key}"
        elif "!" in url:
            # V1 URL structure
            # ex: https://mega.nz/#!Ue5VRSIQ!kC2E4a4JwfWWCWYNJovGFHlbz8F
            match = re.findall(r"/#!(.*)", url)
            path = match[0]
            return path
        else:
            raise ValueError(f"URL key missing from {url}")

    @staticmethod
    def _parse_folder_url(url: str) -> tuple[str, str]:
        if "/folder/" in url:
            _, parts = url.split("/folder/", 1)
        elif "#F!" in url:
            _, parts = url.split("#F!", 1)
        else:
            raise ValidationError("Not a valid folder URL")
        root_folder_id, shared_key = parts.split("#")
        return root_folder_id, shared_key

    async def _get_nodes(self) -> dict[str, Node]:
        nodes_resp: GetNodesResponse = await self._api.request(
            {
                "a": "f",
                "c": 1,
                "r": 1,  # recursive
            }
        )

        self._vault.init_shared_keys(nodes_resp)
        return await self._deserialize_nodes(nodes_resp["f"])

    async def _deserialize_nodes(
        self, nodes: Iterable[NodeSerialized], public_key: str | None = None
    ) -> dict[str, Node]:
        """
        Processes multiple nodes at once, decrypting their keys and attributes.
        """

        share_key = b64_to_a32(public_key) if public_key else None
        results: dict[str, Node] = {}
        system_nodes: list[Node] = [None] * 3  # pyright: ignore[reportAssignmentType]

        for idx, node in enumerate(nodes):
            node_id = node["h"]
            if share_key:
                self._vault.shared_keys["EXP"][node_id] = share_key

            results[node_id] = node = self._deserialize_node(node)

            if node.type in (NodeType.ROOT_FOLDER, NodeType.INBOX, NodeType.TRASH):
                system_nodes[node.type - NodeType.ROOT_FOLDER] = node

            if idx % 500 == 0:
                await asyncio.sleep(0)

        if self._system_nodes is None and all(system_nodes):
            self._system_nodes = SystemNodes(*system_nodes)

        return results

    async def _really_download_file(
        self,
        direct_file_url: str,
        output_path: Path,
        file_size: int,
        iv: TupleArray,
        meta_mac: tuple[int, int],
        key: TupleArray,
    ):
        if await asyncio.to_thread(output_path.exists):
            raise FileExistsError(errno.EEXIST, output_path)

        with (
            tempfile.NamedTemporaryFile(prefix="megapy_", delete=False) as temp_file,
            self._progress.new_task(output_path.name, total=file_size) as advance,
        ):
            chunk_decryptor = MegaDecryptor(iv, key, meta_mac)

            async with self._api.download(direct_file_url) as response:
                for _, chunk_size in get_chunks(file_size):
                    raw_chunk = await response.content.readexactly(chunk_size)
                    chunk = chunk_decryptor.decrypt(raw_chunk)
                    temp_file.write(chunk)
                    advance(len(chunk))

        chunk_decryptor.check_integrity()

        def move():
            output_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(temp_file.name, output_path)

        await asyncio.to_thread(move)
        return output_path

    async def build_file_system(self, nodes_map: Mapping[str, Node], root_ids: list[str]) -> dict[PurePosixPath, Node]:
        return await asyncio.to_thread(_build_file_system, nodes_map, root_ids)


def _build_file_system(nodes_map: Mapping[str, Node], root_ids: list[str]) -> dict[PurePosixPath, Node]:
    """Builds a flattened dictionary representing the users' file system"""

    filesystem: dict[PurePosixPath, Node] = {}
    parents_map: dict[str, list[Node]] = {}

    for node in nodes_map.values():
        parents_map.setdefault(node.parent_id, []).append(node)

    def build_tree(parent_id: str, current_path: PurePosixPath) -> None:
        for node in parents_map.get(parent_id, []):
            node_path = current_path / node.attributes.name
            filesystem[node_path] = node

            if node.type is NodeType.FOLDER:
                build_tree(node.id, node_path)

    for root_id in root_ids:
        root_node = nodes_map[root_id]
        name = root_node.attributes.name
        path = PurePosixPath("." if root_node.type is NodeType.ROOT_FOLDER else name)
        filesystem[path] = root_node
        build_tree(root_id, path)

    return dict(sorted(filesystem.items()))


@dataclasses.dataclass(slots=True, weakref_slot=True)
class MegaDecryptor:
    iv: tuple[int, ...]
    key: tuple[int, ...]
    meta_mac: tuple[int, int]
    _gen: Generator[bytes, bytes | None, None] = dataclasses.field(init=False)

    def __post_init__(self) -> None:
        self._gen = _decrypt_chunks(self.iv, self.key, self.meta_mac)
        _ = next(self._gen)

    def decrypt(self, raw_chunk: bytes) -> bytes:
        return self._gen.send(raw_chunk)

    def check_integrity(self) -> None:
        try:
            _ = self._gen.send(None)
        except StopIteration:
            pass


def _decrypt_chunks(
    iv: TupleArray,
    key: TupleArray,
    meta_mac: tuple[int, int],
) -> Generator[bytes, bytes | None, None]:
    """
    Decrypts chunks of data received via `send()` and yields the decrypted chunks.
    It decrypts chunks indefinitely until a sentinel value (`None`) is sent.

    NOTE: You MUST send `None` once after all chunks are processed to execute the MAC check.

    Args:
        iv (AnyArray):  Initialization vector (iv) as a list or tuple of two 32-bit unsigned integers.
        k_decrypted (TupleArray):  Decryption key as a tuple of four 32-bit unsigned integers.
        meta_mac (AnyArray):  The expected MAC value of the final file.

    Yields:
        bytes:  Decrypted chunk of data. The first `yield` is a blank (`b''`) to initialize generator.

    """
    key_bytes = a32_to_bytes(key)
    counter = Counter.new(128, initial_value=((iv[0] << 32) + iv[1]) << 64)
    aes = AES.new(key_bytes, AES.MODE_CTR, counter=counter)

    # mega.nz improperly uses CBC as a MAC mode, so after each chunk
    # the last 16 bytes are used as IV for the next chunk MAC accumulation

    mac_bytes = EMPTY_IV
    mac_encryptor = AES.new(key_bytes, AES.MODE_CBC, mac_bytes)
    iv_bytes = a32_to_bytes([iv[0], iv[1], iv[0], iv[1]])
    chunk: bytes | None = yield b""

    while chunk is not None:
        decrypted_chunk = aes.decrypt(chunk)
        chunk = yield decrypted_chunk
        encryptor = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)

        mem_view = memoryview(decrypted_chunk)
        modchunk = len(decrypted_chunk) % CHUNK_BLOCK_LEN or CHUNK_BLOCK_LEN

        last_16b = pad_bytes(mem_view[-modchunk:])
        encryptor.encrypt(mem_view[:-modchunk])
        mac_bytes = mac_encryptor.encrypt(encryptor.encrypt(last_16b))

    file_mac = str_to_a32(mac_bytes)
    computed_mac = file_mac[0] ^ file_mac[1], file_mac[2] ^ file_mac[3]
    if computed_mac != meta_mac:
        raise RuntimeError("Mismatched mac")
