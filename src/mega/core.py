from __future__ import annotations

import asyncio
import dataclasses
import logging
import re
import shutil
import tempfile
from contextvars import ContextVar
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, cast

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
from mega.data_structures import NodeType, TupleArray

from .errors import MegaNzError, ValidationError

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Sequence

    import aiohttp

    from mega.data_structures import (
        Attributes,
        File,
        Folder,
        FolderResponse,
        Node,
        NodesMap,
        SharedKeys,
        SharedKeysMap,
        TupleArray,
    )


logger = logging.getLogger(__name__)
_SHOW_PROGRESS = ContextVar[bool]("_SHOW_PROGRESS", default=False)


@dataclasses.dataclass(slots=True)
class SystemNodes:
    root: str
    inbox: str
    trash_bin: str


class MegaNzCoreClient:
    def __init__(self, use_progress_bar: bool = True, session: aiohttp.ClientSession | None = None) -> None:
        self._api = MegaApi(session)
        self._primary_url = "https://mega.nz"
        self._logged_in = False
        self.root_id: str = ""
        self.inbox_id: str = ""
        self.trashbin_id: str = ""
        self._system_nodes = SystemNodes("", "", "")
        self._shared_keys: SharedKeysMap = {}
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

    def _process_node(self, node: Node) -> Node:
        node_type = NodeType(node["t"])

        match node_type:
            case NodeType.ROOT_FOLDER:
                self._system_nodes.root = node["h"]
                node["attributes"] = {"n": "Cloud Drive"}

            case NodeType.INBOX:
                self._system_nodes.inbox = node["h"]
                node["attributes"] = {"n": "Inbox"}

            case NodeType.TRASH:
                self._system_nodes.trash_bin = node["h"]
                node["attributes"] = {"n": "Trash Bin"}

            case NodeType.FILE | NodeType.FOLDER:
                node = cast("File | Folder", node)
                node = self._process_file_or_folder(node)

        return node

    def _process_file_or_folder(self, node: File | Folder) -> Node:
        keys = dict(keypart.split(":", 1) for keypart in node["k"].split("/") if ":" in keypart)
        node_id: str = node["h"]
        uid: str = node["u"]
        key = None
        # my objects
        if uid in keys:
            key = decrypt_key(base64_to_a32(keys[uid]), self._master_key)

        # shared folders
        elif (share_id := node.get("su")) and (share_key := node.get("sk")) and node_id in keys:
            shared_key = decrypt_key(base64_to_a32(share_key), self._master_key)
            key = decrypt_key(base64_to_a32(keys[node_id]), shared_key)
            self._shared_keys.setdefault(share_id, {})[node_id] = shared_key

        # shared files
        elif (owner := node.get("u")) and owner in self._shared_keys:
            for hkey, shared_key in self._shared_keys[owner].items():
                if hkey in keys:
                    key = decrypt_key(base64_to_a32(keys[hkey]), shared_key)
                    break

        if shared_key := self._shared_keys.get("EXP", {}).get(node_id):
            encrypted_key = str_to_a32(base64_url_decode(node["k"].split(":")[-1]))
            key = decrypt_key(encrypted_key, shared_key)
            node["sk_decrypted"] = shared_key

        if key is not None:
            # file
            if node["t"] == NodeType.FILE:
                node = cast("File", node)
                k = (key[0] ^ key[4], key[1] ^ key[5], key[2] ^ key[6], key[3] ^ key[7])
                node["iv"] = (*key[4:6], 0, 0)
                node["meta_mac"] = key[6:8]
            # folder
            else:
                k = key

            node["full_key"] = key
            node["k_decrypted"] = k
            attributes_bytes = base64_url_decode(node["a"])
            attributes = decrypt_attr(attributes_bytes, k)
            node["attributes"] = cast("Attributes", attributes)

        return node

    def _init_shared_keys(self, files: FolderResponse) -> None:
        """
        Init shared key not associated with a user.
        Seems to happen when a folder is shared,
        some files are exchanged and then the
        folder is un-shared.
        Keys are stored in files['s'] and files['ok']
        """

        shared_keys: SharedKeys = {}
        for node in files["ok"]:
            node_id: str = node["h"]
            decrypted_shared_key = decrypt_key(base64_to_a32(node["k"]), self._master_key)
            shared_keys[node_id] = decrypted_shared_key

        for node in files["s"]:
            node_id = node["h"]
            if key := shared_keys.get(node_id):
                owner = node["u"]
                self._shared_keys.setdefault(owner, {})[node_id] = key

    async def _get_files(self) -> NodesMap:
        logger.info("Getting all files on the account...")
        return await self._get_nodes()

    async def _get_nodes(self) -> NodesMap:
        files: FolderResponse = await self._api.request(
            {
                "a": "f",
                "c": 1,
                "r": 1,
            }
        )

        if not self._shared_keys:
            self._init_shared_keys(files)

        return await self._process_nodes(files["f"])

    async def _process_nodes(
        self,
        nodes: Sequence[Node],
        public_key: str | None = None,
        predicate: Callable[[Node], bool] | None = None,
    ) -> dict[str, Node]:
        """
        Processes multiple nodes at once, decrypting their metadata and attributes.

        If predicate is provided, only nodes for which `predicate(node)` returns `False` are included in the result.

        This method is NOT thread safe. It modifies the internal state of the shared keys.
        """
        # User may already have access to this folder (the key is saved in their account)
        folder_key = base64_to_a32(public_key) if public_key else None
        self._shared_keys.setdefault("EXP", {})

        async def process_nodes() -> dict[str, Node]:
            results = {}
            for index, node in enumerate(nodes):
                node_id = node["h"]
                if folder_key:
                    self._shared_keys["EXP"][node_id] = folder_key

                processed_node = self._process_node(node)
                if predicate is None or not predicate(processed_node):
                    results[node_id] = processed_node

                if index % 500 == 0:
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
        k_decrypted: TupleArray,
    ):
        with (
            tempfile.NamedTemporaryFile(prefix="megapy_", delete=False) as temp_file,
            self._new_progress() as progress_bar,
        ):
            task_id = progress_bar.add_task(output_path.name, total=file_size)
            chunk_decryptor = MegaDecryptor(iv, k_decrypted, meta_mac)

            async with self._api._get_session().get(direct_file_url) as response:
                for _, chunk_size in get_chunks(file_size):
                    raw_chunk = await response.content.readexactly(chunk_size)
                    chunk: bytes = chunk_decryptor.decrypt(raw_chunk)
                    temp_file.write(chunk)
                    progress_bar.advance(task_id, len(chunk))

        chunk_decryptor.check_integrity()

        def move() -> None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(temp_file.name, output_path)

        await asyncio.to_thread(move)
        return output_path

    async def _build_file_system(self, nodes_map: dict[str, Node], root_ids: list[str]) -> dict[PurePosixPath, Node]:
        """Builds a flattened dictionary representing a file system from a list of items.

        Returns:
            A 1-level dictionary where the each keys is the full path to a file/folder, and each value is the actual file/folder
        """
        if not self._logged_in:
            raise MegaNzError("You must log in to build your file system")

        path_mapping: dict[PurePosixPath, Node] = {}
        parents_mapping: dict[str, list[Node]] = {}

        for _, item in nodes_map.items():
            parent_id = item["p"]
            if parent_id not in parents_mapping:
                parents_mapping[parent_id] = []
            parents_mapping[parent_id].append(item)

        async def build_tree(parent_id: str, current_path: PurePosixPath) -> None:
            for item in parents_mapping.get(parent_id, []):
                name = item["attributes"].get("n")
                if not name:
                    continue
                item_path = current_path / name
                path_mapping[item_path] = item

                if item["t"] == NodeType.FOLDER:
                    await build_tree(item["h"], item_path)

            await asyncio.sleep(0)

        for root_id in root_ids:
            root_item = nodes_map[root_id]
            name = root_item["attributes"]["n"]
            path = PurePosixPath(name if name != "Cloud Drive" else ".")
            path_mapping[path] = root_item
            await build_tree(root_id, path)

        sorted_mapping = dict(sorted(path_mapping.items()))
        return sorted_mapping


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
