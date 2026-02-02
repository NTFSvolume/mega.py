from __future__ import annotations

import asyncio
import dataclasses
import logging
import re
import shutil
import tempfile
from contextvars import ContextVar
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from Crypto.Cipher import AES
from Crypto.Util import Counter
from rich.progress import BarColumn, DownloadColumn, Progress, SpinnerColumn, TimeRemainingColumn, TransferSpeedColumn
from typing_extensions import Self

from mega.api import MegaApi
from mega.auth import MegaAuth
from mega.crypto import (
    CHUNK_BLOCK_LEN,
    EMPTY_IV,
    a32_to_bytes,
    base64_to_a32,
    base64_url_decode,
    decrypt_attr,
    decrypt_key,
    get_chunks,
    pad_bytes,
    str_to_a32,
)
from mega.data_structures import Attributes, Crypto, Node, NodeType

from .errors import ValidationError

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Iterable, Mapping

    import aiohttp

    from mega.data_structures import GetNodesResponse, NodeSerialized, SharedKeys, TupleArray


logger = logging.getLogger(__name__)
_SHOW_PROGRESS = ContextVar[bool]("_SHOW_PROGRESS", default=False)


@dataclasses.dataclass(slots=True)
class SystemNodes:
    root: str
    inbox: str
    trash_bin: str


class MegaCoreClient:
    def __init__(self, session: aiohttp.ClientSession | None = None) -> None:
        self._api = MegaApi(session)
        self._primary_url = "https://mega.nz"
        self._logged_in = False
        self.root_id: str = ""
        self.inbox_id: str = ""
        self.trashbin_id: str = ""
        self._system_nodes = SystemNodes("", "", "")
        self._shared_keys: dict[str, SharedKeys] = {}
        self._master_key: TupleArray
        self._auth = MegaAuth(self._api)

    @property
    def show_progress(self) -> bool:
        return _SHOW_PROGRESS.get()

    @show_progress.setter
    def show_progress(self, value: bool) -> None:
        _ = _SHOW_PROGRESS.set(value)

    def _new_progress(self) -> Progress:
        progress = Progress(
            SpinnerColumn(),
            "{task.description}",
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>6.2f}%",
            "━",
            DownloadColumn(),
            "━",
            TransferSpeedColumn(),
            "━",
            TimeRemainingColumn(compact=True, elapsed_when_finished=True),
        )
        progress.disable = not self.show_progress
        return progress

    async def login(self, email: str, password: str, _mfa: str | None = None) -> Self:
        if email and password:
            self._master_key, self._api.session_id = await self._auth.login(email, password)
        else:
            self._master_key, self._api.session_id = await self._auth.login_anonymous()
        _ = await self._get_files()  # Required to get the special folders id
        self._logged_in = True
        logger.info(f"Special folders: {self._system_nodes}")
        logger.info("Login complete")
        return self

    async def __enter__(self) -> Self:
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()

    async def close(self) -> None:
        await self._api.close()

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

    def _parse_folder_url(self, url: str) -> tuple[str, str]:
        if "/folder/" in url:
            _, parts = url.split("/folder/", 1)
        elif "#F!" in url:
            _, parts = url.split("#F!", 1)
        else:
            raise ValidationError("Not a valid folder URL")
        root_folder_id, shared_key = parts.split("#")
        return root_folder_id, shared_key

    def _process_node(self, node: NodeSerialized) -> Node:
        parsed_node = Node(**self._deserialize_node(node))

        if parsed_node.type in (NodeType.FILE, NodeType.FOLDER):
            full_key, share_key = self._decrypt_keys(parsed_node)
            parsed_node._crypto = self._parse_crypto(parsed_node.type, full_key, share_key)
            attributes = decrypt_attr(base64_url_decode(parsed_node._a), parsed_node._crypto.key)
            parsed_node.attributes = Attributes(**attributes)

        else:
            name = {
                NodeType.ROOT_FOLDER: "Cloud Drive",
                NodeType.INBOX: "Inbox",
                NodeType.TRASH: "Trash Bin",
            }[parsed_node.type]
            parsed_node.attributes = Attributes(name)

        return parsed_node

    @staticmethod
    def _deserialize_node(node: NodeSerialized) -> dict[str, Any]:
        if k := node.get("k"):
            keys = dict(key_pair.split(":", 1) for key_pair in k.split("/") if ":" in key_pair)
        else:
            keys = {}

        return dict(  # noqa: C408
            id=node["h"],
            parent_id=node["p"],
            owner=node["u"],
            type=NodeType(node["t"]),
            keys=keys,
            share_id=node.get("su"),
            share_key=node.get("sk"),
        )

    @staticmethod
    def _parse_crypto(node_type: NodeType, full_key: tuple[int, ...], share_key: tuple[int, ...] | None) -> Crypto:
        if node_type is NodeType.FILE:
            key = (
                full_key[0] ^ full_key[4],
                full_key[1] ^ full_key[5],
                full_key[2] ^ full_key[6],
                full_key[3] ^ full_key[7],
            )

        else:
            key = full_key

        iv = *full_key[4:6], 0, 0
        meta_mac = full_key[6:8]
        return Crypto(key, iv, meta_mac, full_key, share_key)  # pyright: ignore[reportArgumentType]

    def _decrypt_keys(self, node: Node) -> tuple[tuple[int, ...], tuple[int, ...] | None]:
        # my objects
        share_key: tuple[int, ...] | None = None
        full_key: tuple[int, ...] | None = None

        if node.owner in node.keys:
            full_key = decrypt_key(base64_to_a32(node.keys[node.owner]), self._master_key)

        # shared folders
        elif node.share_id and node.share_key and node.id in node.keys:
            share_key = decrypt_key(base64_to_a32(node.share_key), self._master_key)
            full_key = decrypt_key(base64_to_a32(node.keys[node.id]), share_key)
            self._shared_keys.setdefault(node.share_id, {})[node.id] = share_key

        # shared files
        elif node.owner in self._shared_keys:
            for node_id, share_key in self._shared_keys[node.owner].items():
                if node_id in node.keys:
                    full_key = decrypt_key(base64_to_a32(node.keys[node_id]), share_key)
                    break

        if share_key := self._shared_keys.get("EXP", {}).get(node.id):
            encrypted_key = str_to_a32(base64_url_decode(next(iter(node.keys.values()))))
            full_key = decrypt_key(encrypted_key, share_key)

        assert full_key

        return full_key, share_key

    def _init_shared_keys(self, files: GetNodesResponse, shared_keys_map: dict[str, SharedKeys]) -> None:
        """
        Init shared key not associated with a user.
        Seems to happen when a folder is shared,
        some files are exchanged and then the
        folder is un-shared.
        Keys are stored in files['s'] and files['ok']
        """

        shared_keys: SharedKeys = {}
        for share_key in files["ok"]:
            node_id, key = share_key["h"], share_key["k"]
            shared_keys[node_id] = decrypt_key(base64_to_a32(key), self._master_key)

        for share_key in files["s"]:
            node_id, owner = share_key["h"], share_key["u"]
            if key := shared_keys.get(node_id):
                shared_keys_map.setdefault(owner, {})[node_id] = key

    async def _get_files(self) -> dict[str, Node]:
        logger.info("Getting all files on the account...")
        return await self._get_nodes()

    async def _get_nodes(self) -> dict[str, Node]:
        files: GetNodesResponse = await self._api.request(
            {
                "a": "f",
                "c": 1,
                "r": 1,  # recursive
            }
        )

        if not self._shared_keys:
            self._init_shared_keys(files, self._shared_keys)

        return await self._process_nodes(files["f"])

    async def _process_nodes(
        self,
        nodes: Iterable[NodeSerialized],
        public_key: str | None = None,
        predicate: Callable[[Node], bool] | None = None,
    ) -> dict[str, Node]:
        """
        Processes multiple nodes at once, decrypting their metadata and attributes.

        If predicate is provided, only nodes for which `predicate(node)` returns `False` are included in the result.

        This method is NOT thread safe. It modifies the internal state of the shared keys.
        """

        share_key = base64_to_a32(public_key) if public_key else None
        self._shared_keys.setdefault("EXP", {})

        results: dict[str, Node] = {}

        async def process_nodes() -> dict[str, Node]:
            for idx, node in enumerate(nodes):
                node_id = node["h"]
                if share_key:
                    self._shared_keys["EXP"][node_id] = share_key

                processed_node = self._process_node(node)
                if predicate is None or not predicate(processed_node):
                    results[node_id] = processed_node

                if idx % 500 == 0:
                    await asyncio.sleep(0)

            return results

        return await process_nodes()

    async def _really_download_file(
        self,
        direct_file_url: str,
        output_path: Path,
        file_size: int,
        iv: TupleArray,
        meta_mac: TupleArray,
        key: TupleArray,
    ):
        with (
            tempfile.NamedTemporaryFile(prefix="megapy_", delete=False) as temp_file,
            self._new_progress() as progress_bar,
        ):
            task_id = progress_bar.add_task(output_path.name, total=file_size)
            chunk_decryptor = MegaDecryptor(iv, key, meta_mac)

            async with self._api._get_session().get(direct_file_url) as response:
                for _, chunk_size in get_chunks(file_size):
                    raw_chunk = await response.content.readexactly(chunk_size)
                    chunk = chunk_decryptor.decrypt(raw_chunk)
                    temp_file.write(chunk)
                    progress_bar.advance(task_id, len(chunk))

        chunk_decryptor.check_integrity()

        def move() -> None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(temp_file.name, output_path)

        await asyncio.to_thread(move)
        return output_path

    async def build_file_system(self, nodes_map: Mapping[str, Node], root_ids: list[str]) -> dict[PurePosixPath, Node]:
        return await asyncio.to_thread(self._build_file_system, nodes_map, root_ids)

    def _build_file_system(self, nodes_map: Mapping[str, Node], root_ids: list[str]) -> dict[PurePosixPath, Node]:
        """Builds a flattened dictionary representing a file system from a list of items.

        Returns:
            A 1-level dictionary where the each keys is the full path to a file/folder, and each value is the actual file/folder
        """

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


class MegaDecryptor:
    def __init__(self, iv: TupleArray, k_decrypted: TupleArray, meta_mac: TupleArray) -> None:
        self.chunk_decryptor = _decrypt_chunks(k_decrypted, iv, meta_mac)
        _ = next(self.chunk_decryptor)  # Prime chunk decryptor

    def decrypt(self, raw_chunk: bytes) -> bytes:
        return self.chunk_decryptor.send(raw_chunk)

    def check_integrity(self) -> None:
        try:
            _ = self.chunk_decryptor.send(None)
        except StopIteration:
            pass


def _decrypt_chunks(
    iv: TupleArray,
    k_decrypted: TupleArray,
    meta_mac: TupleArray,
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
    k_bytes = a32_to_bytes(k_decrypted)
    counter = Counter.new(128, initial_value=((iv[0] << 32) + iv[1]) << 64)
    aes = AES.new(k_bytes, AES.MODE_CTR, counter=counter)

    # mega.nz improperly uses CBC as a MAC mode, so after each chunk
    # the last 16 bytes are used as IV for the next chunk MAC accumulation

    mac_bytes = EMPTY_IV
    mac_encryptor = AES.new(k_bytes, AES.MODE_CBC, mac_bytes)
    iv_bytes = a32_to_bytes([iv[0], iv[1], iv[0], iv[1]])
    chunk: bytes | None = yield b""

    while chunk is not None:
        decrypted_chunk = aes.decrypt(chunk)
        chunk = yield decrypted_chunk
        encryptor = AES.new(k_bytes, AES.MODE_CBC, iv_bytes)

        mem_view = memoryview(decrypted_chunk)
        modchunk = len(decrypted_chunk) % CHUNK_BLOCK_LEN or CHUNK_BLOCK_LEN

        last_16b = pad_bytes(mem_view[-modchunk:])
        encryptor.encrypt(mem_view[:-modchunk])
        mac_bytes = mac_encryptor.encrypt(encryptor.encrypt(last_16b))

    file_mac = str_to_a32(mac_bytes)
    computed_mac = file_mac[0] ^ file_mac[1], file_mac[2] ^ file_mac[3]
    if computed_mac != meta_mac:
        raise RuntimeError("Mismatched mac")
