from __future__ import annotations

import asyncio
import functools
import hashlib
import logging
import os
import random
import re
import shutil
import tempfile
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Literal, TypeVar, cast

from Crypto.Cipher import AES
from Crypto.Util import Counter
from rich.progress import BarColumn, DownloadColumn, Progress, SpinnerColumn, TimeRemainingColumn, TransferSpeedColumn

from mega.api import MegaApi
from mega.crypto import (
    CHUNK_BLOCK_LEN,
    a32_to_base64,
    a32_to_bytes,
    base64_to_a32,
    base64_url_decode,
    base64_url_encode,
    decrypt_attr,
    decrypt_key,
    decrypt_rsa_key,
    encrypt_attr,
    encrypt_key,
    get_chunks,
    make_hash,
    mpi_to_int,
    pad_bytes,
    prepare_key,
    random_u32int,
    str_to_a32,
)
from mega.data_structures import (
    AnyArray,
    AnyDict,
    Array,
    Attributes,
    File,
    FileOrFolder,
    FilesMapping,
    Folder,
    Node,
    NodeType,
    SharedKey,
    SharedkeysDict,
    StorageUsage,
    TupleArray,
)

from .errors import MegaNzError, RequestError, ValidationError

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Callable, Coroutine, Generator
    from typing import ParamSpec

    R = TypeVar("R")
    P = ParamSpec("P")


else:
    P = Any

logger = logging.getLogger(__name__)


class ProgressBar:
    def __init__(self, enabled: bool = True) -> None:
        progress_columns = (
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
        self.progress = Progress(*progress_columns)
        self.enabled = enabled

    def __enter__(self) -> Progress:
        if self.enabled:
            self.progress.start()
        return self.progress

    def __exit__(self, *args, **kwargs) -> None:
        if self.enabled:
            self.progress.stop()


def requires_login(func: Callable[P, Coroutine[None, None, R]]) -> Callable[P, Coroutine[None, None, R]]:
    @functools.wraps(func)
    async def wrapper(*args, **kwargs) -> R:
        self: Mega = args[0]
        if not self.logged_in:
            raise RuntimeError("You need to log in to use this method")
        return await func(*args, **kwargs)

    return wrapper


class Mega:
    def __init__(self, use_progress_bar: bool = True) -> None:
        self.api = MegaApi()
        self.primary_url = f"{self.api.schema}://{self.api.domain}"
        self.logged_in = False
        self.root_id: str = ""
        self.inbox_id: str = ""
        self.trashbin_id: str = ""
        self._progress_bar = ProgressBar(enabled=use_progress_bar)

    @property
    def use_progress_bar(self) -> bool:
        return self._progress_bar.enabled

    @use_progress_bar.setter
    def set_progress_bar(self, value: bool) -> None:
        if not isinstance(value, bool):
            raise ValueError("Only bool values are valid")
        self._progress_bar.enabled = value

    async def close(self):
        await self.api.close()

    async def login(self, email: str | None = None, password: str | None = None):
        if email and password:
            await self._login_user(email, password)
        else:
            await self.login_anonymous()
        _ = await self._get_files()  # Required to get the special folders id
        self.logged_in = True
        logger.info(f"Special folders: root: {self.root_id} inbox: {self.inbox_id} trash_bin: {self.trashbin_id}")
        self.special_nodes_mapping = {
            NodeType.INBOX: self.inbox_id,
            NodeType.ROOT_FOLDER: self.root_id,
            NodeType.TRASH: self.trashbin_id,
        }
        logger.info("Login complete")
        return self

    def _process_login(self, resp: AnyDict, password: Array):
        encrypted_master_key = base64_to_a32(resp["k"])
        self.master_key = decrypt_key(encrypted_master_key, password)
        if b64_tsid := resp.get("tsid"):
            tsid = base64_url_decode(b64_tsid)
            key_encrypted = a32_to_bytes(encrypt_key(str_to_a32(tsid[:16]), self.master_key))
            if key_encrypted == tsid[-16:]:
                self.api.sid = resp["tsid"]

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
            self.api.sid = sid

    async def _login_user(self, email: str, password: str) -> None:
        logger.info("Logging in user...")
        email = email.lower()
        get_user_salt_resp: dict = await self.api.request(
            {
                "a": "us0",
                "user": email,
            }
        )

        if b64_salt := get_user_salt_resp.get("s"):
            # v2 user account
            user_salt = base64_to_a32(b64_salt)
            pbkdf2_key = hashlib.pbkdf2_hmac(
                hash_name="sha512",
                password=password.encode(),
                salt=a32_to_bytes(user_salt),
                iterations=100000,
                dklen=32,
            )
            password_aes = str_to_a32(pbkdf2_key[:16])
            user_hash = base64_url_encode(pbkdf2_key[-16:])

        else:
            # v1 user account
            password_aes = prepare_key(str_to_a32(password))
            user_hash = make_hash(email, password_aes)

        resp = await self.api.request(
            {
                "a": "us",
                "user": email,
                "uh": user_hash,
            }
        )
        self._process_login(resp, password_aes)

    async def login_anonymous(self) -> None:
        logger.info("Logging in anonymous temporary user...")
        master_key = [random_u32int()] * 4
        password_key = [random_u32int()] * 4
        session_self_challenge = [random_u32int()] * 4

        user: str = await self.api.request(
            {
                "a": "up",
                "k": a32_to_base64(encrypt_key(master_key, password_key)),
                "ts": base64_url_encode(
                    a32_to_bytes(session_self_challenge) + a32_to_bytes(encrypt_key(session_self_challenge, master_key))
                ),
            }
        )

        resp = await self.api.request(
            {
                "a": "us",
                "user": user,
            }
        )
        self._process_login(resp, password_key)

    def _parse_url(self, url: str) -> str:
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

    def _process_node(self, file: Node, shared_keys: SharedkeysDict) -> Node:
        if file["t"] == NodeType.FILE or file["t"] == NodeType.FOLDER:
            file = cast("FileOrFolder", file)
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
                    file = cast("File", file)
                    k = (key[0] ^ key[4], key[1] ^ key[5], key[2] ^ key[6], key[3] ^ key[7])
                    file["iv"] = (*key[4:6], 0, 0)
                    file["meta_mac"] = key[6:8]
                # folder
                else:
                    k = key

                file["key_decrypted"] = key
                file["k_decrypted"] = k
                attributes_bytes = base64_url_decode(file["a"])
                attributes = decrypt_attr(attributes_bytes, k)
                file["attributes"] = cast("Attributes", attributes)

            # other => wrong object
            elif file["k"] == "":
                file = cast("Node", file)
                file["attributes"] = {"n": "Unknown Object"}

        elif file["t"] == NodeType.ROOT_FOLDER:
            self.root_id: str = file["h"]
            file["attributes"] = {"n": "Cloud Drive"}

        elif file["t"] == NodeType.INBOX:
            self.inbox_id = file["h"]
            file["attributes"] = {"n": "Inbox"}

        elif file["t"] == NodeType.TRASH:
            self.trashbin_id = file["h"]
            file["attributes"] = {"n": "Trash Bin"}

        return file

    def _init_shared_keys(self, files: Folder, shared_keys: SharedkeysDict) -> None:
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

    async def find(self, path: Path | str, exclude_deleted: bool = False) -> FileOrFolder | None:
        """
        Returns file or folder from given path( if exists)
        """
        results = await self._search(path, exclude_deleted, strict=True)
        return results[0] if results else None

    async def search(self, filename_or_path: Path | str, exclude_deleted: bool = False) -> list[FileOrFolder]:
        """
        Return file object(s) from given filename or path
        """
        return await self._search(filename_or_path, exclude_deleted)

    @requires_login
    async def _search(
        self, filename_or_path: Path | str, exclude_deleted: bool = False, strict=False
    ) -> list[FileOrFolder]:
        """
        Return file object(s) from given filename or path
        """

        filename_or_path = Path(filename_or_path).as_posix()

        fs = await self.build_file_system()

        found = []
        for path, item in fs.items():
            if filename_or_path in (path_str := path.as_posix()):
                if strict and not path_str.startswith(filename_or_path):
                    continue
                if exclude_deleted and item["p"] == self.trashbin_id:
                    continue
                found.append(item)
        return found

    async def find_by_handle(self, handle: str, exclude_deleted: bool = False) -> FileOrFolder | None:
        """Return file object(s) from given filename or path"""
        files = await self.get_files()
        file = found if (found := files.get(handle)) else None
        if file and file["p"] == self.trashbin_id and exclude_deleted:
            return None
        return file

    async def _get_files(self) -> FilesMapping:
        logger.info("Getting all files...")
        files_dict: FilesMapping = {}
        async for node in self._get_nodes():
            if node["attributes"]:
                file = cast("File", node)
                files_dict[file["h"]] = file
        return files_dict

    @requires_login
    async def get_files(self) -> FilesMapping:
        return await self._get_files()

    async def _get_nodes(self) -> AsyncGenerator[Node]:
        files: Folder = await self.api.request(
            {
                "a": "f",
                "c": 1,
                "r": 1,
            }
        )
        shared_keys: SharedkeysDict = {}
        self._init_shared_keys(files, shared_keys)
        for index, node in enumerate(files["f"], 1):
            yield self._process_node(node, shared_keys)
            if index % 100 == 0:
                await asyncio.sleep(0)

    async def _get_nodes_in_shared_folder(self, folder_id: str) -> AsyncGenerator[Node]:
        files: Folder = await self.api.request(
            {
                "a": "f",
                "c": 1,
                "ca": 1,
                "r": 1,
            },
            {
                "n": folder_id,
            },
        )
        for index, node in enumerate(files["f"], 1):
            yield self._process_node(node, self.shared_keys)
            if index % 100 == 0:
                await asyncio.sleep(0)

    def _parse_folder_url(self, url: str) -> tuple[str, str]:
        if "/folder/" in url:
            _, parts = url.split("/folder/", 1)
        elif "#F!" in url:
            _, parts = url.split("#F!", 1)
        else:
            raise ValidationError("Not a valid folder URL")
        root_folder_id, shared_key = parts.split("#")
        return root_folder_id, shared_key

    @requires_login
    async def get_upload_link(self, folder: Folder) -> str:
        """
        Get a files public link inc. decrypted key
        Requires upload() response as input
        """
        if "f" not in folder:
            raise ValueError("""Upload() response required as input, use get_link() for regular file input""")

        file = folder["f"][0]
        public_handle: str = await self.api.request(
            {
                "a": "l",
                "n": file["h"],
            }
        )
        _, file_key = file["k"].split(":", 1)
        decrypted_key = a32_to_base64(decrypt_key(base64_to_a32(file_key), self.master_key))
        return f"{self.primary_url}/#!{public_handle}!{decrypted_key}"

    async def get_link(self, file: FileOrFolder) -> str:
        """
        Get a file public link from given file object
        """

        if not ("h" in file and "key_decrypted" in file):
            raise ValidationError("File id and key must be present")

        public_handle: str = await self._get_public_handle(file)
        decrypted_key = a32_to_base64(file["key_decrypted"])
        return f"{self.primary_url}/#!{public_handle}!{decrypted_key}"

    async def get_folder_link(self, folder: FileOrFolder) -> str:
        if not ("h" in folder and "sk_decrypted" in folder):
            raise ValidationError("Folder id and key must be present")

        public_handle: str = await self._get_public_handle(folder)
        decrypted_key = a32_to_base64(folder["sk_decrypted"])
        return f"{self.primary_url}/#F!{public_handle}!{decrypted_key}"

    @requires_login
    async def _get_public_handle(self, file: FileOrFolder) -> str:
        try:
            public_handle: str = await self.api.request(
                {
                    "a": "l",
                    "n": file["h"],
                }
            )
        except RequestError as e:
            if e.code == -11:
                raise MegaNzError("Can't get a public link from that file (is this a shared file?)") from e
            raise
        else:
            return public_handle

    @requires_login
    async def get_user(self) -> AnyDict:
        user_data: AnyDict = await self.api.request(
            {
                "a": "ug",
            }
        )
        return user_data

    async def get_node_by_type(self, node_type: NodeType | int) -> Node | None:
        """
        Get a node by it's numeric type id, e.g:
        0: file
        1: dir
        2: special: root cloud drive
        3: special: inbox
        4: special trash bin
        """
        nodes = await self.get_files()
        for _, node in nodes.items():
            if node["t"] == node_type:
                return node

    @requires_login
    async def get_files_in_node(
        self, target: Literal[NodeType.INBOX, NodeType.TRASH, NodeType.ROOT_FOLDER]
    ) -> FilesMapping:
        """
        Get all files in a given target, e.g. 4=trash
        """
        folder: Folder = await self.api.request(
            {
                "a": "f",
                "c": 1,
            }
        )
        files_dict: FilesMapping = {}
        shared_keys: SharedkeysDict = {}
        target_id = self.special_nodes_mapping.get(target)
        for index, file in enumerate(folder["f"], 1):
            processed_file = cast("FileOrFolder", self._process_node(file, shared_keys))
            if processed_file["a"] and processed_file["p"] == target_id:
                files_dict[file["h"]] = processed_file
            if index % 100 == 0:
                await asyncio.sleep(0)
        return files_dict

    async def get_id_from_public_handle(self, public_handle: str) -> str:
        node_data: Folder = await self.api.request(
            {
                "a": "f",
                "f": 1,
                "p": public_handle,
            }
        )

        node_id = self.get_id_from_resp_obj(node_data)
        assert node_id
        return node_id

    @staticmethod
    def get_id_from_resp_obj(resp: Folder) -> str | None:
        """
        Get node id from a file object
        """

        for i in resp["f"]:
            if i["h"] != "":
                return i["h"]

    async def get_quota(self) -> int:
        """Get current remaining disk quota."""
        json_resp: AnyDict = await self.api.request(
            {
                "a": "uq",  # Action: user quota
                "xfer": 1,
                "strg": 1,
                "v": 1,
            }
        )
        return json_resp["mstrg"]

    async def get_storage_space(self) -> StorageUsage:
        """
        Get the current storage space.
        Return a dict containing at least:
          'used' : the used space on the account
          'total' : the maximum space allowed with current plan
        All storage space are in bytes unless asked differently.
        """
        json_resp: AnyDict = await self.api.request(
            {
                "a": "uq",
                "xfer": 1,
                "strg": 1,
            }
        )
        return StorageUsage(json_resp["cstrg"], json_resp["mstrg"])

    async def get_balance(self) -> int | None:
        """Get account monetary balance, Pro accounts only."""
        user_data: AnyDict = await self.api.request(
            {
                "a": "uq",
                "pro": 1,
            }
        )
        return user_data.get("balance")

    async def delete(self, public_handle: str) -> AnyDict:
        """Delete a file by its public handle."""
        return await self.move(public_handle, NodeType.TRASH)

    async def delete_url(self, url: str) -> AnyDict:
        """Delete a file by its url"""
        public_handle, _ = self._parse_url(url).split("!")
        file_id = await self.get_id_from_public_handle(public_handle)
        return await self.move(file_id, NodeType.TRASH)

    async def destroy(self, file_id: str) -> AnyDict:
        """Destroy a file or folder by its private id (bypass trash bin)"""
        return await self.api.request(
            {
                "a": "d",  # Action: delete
                "n": file_id,  # Node: file Id
                "i": self.api.request_id,  # Request Id
            }
        )

    async def destroy_url(self, url: str) -> AnyDict:
        """Destroy a file by its url (bypass trash bin)"""
        public_handle, *_ = self._parse_url(url).split("!")
        file_id = await self.get_id_from_public_handle(public_handle)
        return await self.destroy(file_id)

    async def empty_trash(self) -> AnyDict | None:
        """Deletes all file in the trash bin. Returns None if the trash was already empty"""
        # get list of files in rubbish out
        files = await self.get_files_in_node(NodeType.TRASH)

        # make a list of json
        if files != {}:
            post_list = []
            for file in files:
                post_list.append(
                    {
                        "a": "d",  # Action: delete
                        "n": file,  # Node: file #Id
                        "i": self.api.request_id,  # Request Id
                    }
                )
            return await self.api.request(post_list)

    async def download(
        self, file: FileOrFolder | None, dest_path: Path | str | None = None, dest_filename: str | None = None
    ) -> Path:
        """Download a file by it's file object."""
        return await self._download_file(
            file_handle=None,
            file_key=None,
            file=file,
            dest_path=dest_path,
            dest_filename=dest_filename,
            is_public=False,
        )

    async def _export_file(self, node: FileOrFolder) -> str:
        await self.api.request(
            [
                {
                    "a": "l",  # Action: Export file
                    "n": node["h"],  # Node: file Id
                    "i": self.api.request_id,  # Request #Id
                }
            ]
        )
        return await self.get_link(node)

    async def export(self, path: Path | str | None = None, node_id: str | None = None) -> str:
        files = await self.get_files()
        if node_id:
            _node_id = node_id
            file: FileOrFolder = files[_node_id]
        elif path:
            found = await self.find(path)
            if not found:
                raise ValueError
            file = found
        else:
            raise ValueError

        if file["t"] == NodeType.FILE:
            return await self._export_file(file)

        if file:
            try:
                # If already exported
                return await self.get_folder_link(file)
            except (RequestError, KeyError):
                pass

        master_key_cipher = AES.new(a32_to_bytes(self.master_key), AES.MODE_ECB)
        ha = base64_url_encode(master_key_cipher.encrypt(file["h"].encode("utf8") + file["h"].encode("utf8")))

        share_key = random.randbytes(16)
        ok = base64_url_encode(master_key_cipher.encrypt(share_key))

        share_key_cipher = AES.new(share_key, AES.MODE_ECB)
        node_key = file["k_decrypted"]
        encrypted_node_key = base64_url_encode(share_key_cipher.encrypt(a32_to_bytes(node_key)))

        _node_id: str = file["h"]
        await self.api.request(
            {
                "a": "s2",
                "n": _node_id,
                "s": [
                    {
                        "u": "EXP",  # User: export (AKA public)
                        "r": 0,
                    }
                ],
                "i": self.api.request_id,
                "ok": ok,
                "ha": ha,
                "cr": [[_node_id], [_node_id], [0, 0, encrypted_node_key]],
            }
        )
        files = await self.get_files()
        return await self.get_folder_link(files[_node_id])

    async def download_url(self, url: str, dest_path: str | None = None, dest_filename: str | None = None) -> Path:
        """
        Download a file by it's public url
        """
        file_id, file_key = self._parse_url(url).split("!", 1)
        return await self._download_file(
            file_handle=file_id,
            file_key=file_key,
            dest_path=dest_path,
            dest_filename=dest_filename,
            is_public=True,
        )

    async def get_nodes_public_folder(self, url: str) -> dict[str, FileOrFolder]:
        folder_id, b64_share_key = self._parse_folder_url(url)
        shared_key = base64_to_a32(b64_share_key)

        async def prepare_nodes():
            async for node in self._get_nodes_in_shared_folder(folder_id):
                node = cast("FileOrFolder", node)
                encrypted_key = base64_to_a32(node["k"].split(":")[1])
                key = decrypt_key(encrypted_key, shared_key)
                if node["t"] == NodeType.FILE:
                    k = (key[0] ^ key[4], key[1] ^ key[5], key[2] ^ key[6], key[3] ^ key[7])
                elif node["t"] == NodeType.FOLDER:
                    k = key

                iv: AnyArray = (*key[4:6], 0, 0)
                meta_mac: TupleArray = key[6:8]

                attrs = decrypt_attr(base64_url_decode(node["a"]), k)
                node["attributes"] = cast("Attributes", attrs)
                node["k_decrypted"] = k
                node["iv"] = iv
                node["meta_mac"] = meta_mac
                yield node

        nodes = {node["h"]: node async for node in prepare_nodes()}
        return nodes

    async def download_folder_url(self, url: str, dest_path: str | None = None) -> list[Path]:
        folder_id, _ = self._parse_folder_url(url)
        nodes = await self.get_nodes_public_folder(url)
        download_tasks = []
        root_id = next(iter(nodes))
        fs = await self._build_file_system(nodes, [root_id])  # type: ignore
        for path, node in fs.items():
            if node["t"] != NodeType.FILE:
                continue

            async def download_file(file: File, file_path: Path) -> None:
                file_data = await self.api.request(
                    {
                        "a": "g",
                        "g": 1,
                        "n": file["h"],
                    },
                    {"n": folder_id},
                )

                file_url = file_data["g"]
                file_size = file_data["s"]

                if dest_path:
                    download_path = Path(dest_path) / file_path
                else:
                    download_path = file_path

                await self._really_download_file(
                    file_url,
                    download_path,
                    file_size,
                    file["iv"],
                    file["meta_mac"],
                    file["k_decrypted"],
                )

            file = cast("File", node)
            download_tasks.append(download_file(file, Path(path)))

        with self._progress_bar:
            results = await asyncio.gather(*download_tasks)
        return results

    async def _download_file(
        self,
        file_handle: str | None = None,
        file_key: TupleArray | str | None = None,
        dest_path: Path | str | None = None,
        dest_filename: str | None = None,
        is_public: bool = False,
        file: FileOrFolder | None = None,
    ) -> Path:
        if file is None:
            assert file_key
            if isinstance(file_key, str):
                _file_key = base64_to_a32(file_key)
            else:
                _file_key = file_key

            file_data: File = await self.api.request(
                {
                    "a": "g",
                    "g": 1,
                    "p" if is_public else "n": file_handle,
                },
            )

            k: AnyArray = (
                _file_key[0] ^ _file_key[4],
                _file_key[1] ^ _file_key[5],
                _file_key[2] ^ _file_key[6],
                _file_key[3] ^ _file_key[7],
            )
            iv: AnyArray = (*_file_key[4:6], 0, 0)
            meta_mac: TupleArray = _file_key[6:8]
        else:
            file_handle = file["h"]
            file_data = await self.api.request(
                {
                    "a": "g",
                    "g": 1,
                    "p" if is_public else "n": file_handle,
                }
            )
            k = file["k_decrypted"]
            iv = file["iv"]
            meta_mac = file["meta_mac"]

        # Seems to happens sometime... When this occurs, files are
        # inaccessible also in the official web app.
        # Strangely, files can come back later.
        if "g" not in file_data:
            raise RequestError("File not accessible anymore")

        file_url = file_data["g"]
        file_size = file_data["s"]
        attribs_bytes = base64_url_decode(file_data["at"])
        attribs = decrypt_attr(attribs_bytes, k)
        attribs = cast("Attributes", attribs)

        if dest_filename is not None:
            file_name = dest_filename
        else:
            file_name: str = attribs["n"]

        if dest_path is None:
            dest_path = Path()
        elif isinstance(dest_path, str):
            dest_path = Path(dest_path)

        output_path = dest_path / file_name

        with self._progress_bar:
            return await self._really_download_file(file_url, output_path, file_size, iv, meta_mac, k)

    async def _really_download_file(
        self,
        direct_file_url: str,
        output_path: Path,
        file_size: int,
        iv: TupleArray,
        meta_mac: TupleArray,
        k_decrypted: TupleArray,
    ):
        with tempfile.NamedTemporaryFile(mode="w+b", prefix="megapy_", delete=False) as temp_output_file:
            task_id = self._progress_bar.progress.add_task(output_path.name, total=file_size)
            chunk_decryptor = self._decrypt_chunks(iv, k_decrypted, meta_mac)
            _ = next(chunk_decryptor)  # Prime chunk decryptor
            bytes_written: int = 0
            async with self.api.session.get(direct_file_url) as response:
                for _, chunk_size in get_chunks(file_size):
                    raw_chunk = await response.content.readexactly(chunk_size)
                    decrypted_chunk: bytes = chunk_decryptor.send(raw_chunk)
                    actual_size = len(decrypted_chunk)
                    bytes_written += actual_size
                    temp_output_file.write(decrypted_chunk)
                    self._progress_bar.progress.advance(task_id, actual_size)

        try:
            # Stop chunk decryptor and do a mac integrity check
            chunk_decryptor.send(None)  # type: ignore
        except StopIteration:
            pass
        finally:
            self._progress_bar.progress.remove_task(task_id)
        await asyncio.to_thread(output_path.parent.mkdir, parents=True, exist_ok=True)
        await asyncio.to_thread(shutil.move, temp_output_file.name, output_path)
        return output_path

    def _decrypt_chunks(
        self,
        iv: TupleArray,
        k_decrypted: TupleArray,
        meta_mac: TupleArray,
    ) -> Generator[bytes, bytes, None]:
        """
        Decrypts chunks of data received via `send()` and yields the decrypted chunks.
        It decrypts chunks indefinitely until a sentinel value (`None`) is sent.

        NOTE: You MUST send `None` after decrypting every chunk to execute the mac check

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
        # the computed mac_bytes are used as IV for the next chunk MAC accumulation
        mac_bytes = b"\0" * 16
        mac_encryptor = AES.new(k_bytes, AES.MODE_CBC, mac_bytes)
        iv_bytes = a32_to_bytes([iv[0], iv[1], iv[0], iv[1]])
        raw_chunk = yield b""
        while True:
            if raw_chunk is None:
                break
            decrypted_chunk = aes.decrypt(raw_chunk)
            raw_chunk = yield decrypted_chunk
            encryptor = AES.new(k_bytes, AES.MODE_CBC, iv_bytes)

            # take last 16-N bytes from chunk (with N between 1 and 16, including extremes)
            mem_view = memoryview(decrypted_chunk)  # avoid copying memory for the entire chunk when slicing
            modchunk = len(decrypted_chunk) % CHUNK_BLOCK_LEN
            if modchunk == 0:
                # ensure we reserve the last 16 bytes anyway, we have to feed them into mac_encryptor
                modchunk = CHUNK_BLOCK_LEN

            # pad last block to 16 bytes
            last_block = pad_bytes(mem_view[-modchunk:])
            rest_of_chunk = mem_view[:-modchunk]
            _ = encryptor.encrypt(rest_of_chunk)
            input_to_mac = encryptor.encrypt(last_block)
            mac_bytes = mac_encryptor.encrypt(input_to_mac)

        file_mac = str_to_a32(mac_bytes)
        computed_mac = file_mac[0] ^ file_mac[1], file_mac[2] ^ file_mac[3]
        if computed_mac != meta_mac:
            raise RuntimeError("Mismatched mac")

    async def upload(self, filename: str, dest_node: Folder | None = None, dest_filename: str | None = None) -> Folder:
        # determine storage node
        dest_node_id = dest_node["h"] if dest_node else self.root_id
        # request upload url, call 'u' method
        with open(filename, "rb") as input_file:
            file_size = os.path.getsize(filename)
            ul_url: str = (
                await self.api.request(
                    {
                        "a": "u",
                        "s": file_size,
                    }
                )
            )["p"]

            # generate random aes key (128) for file, 192 bits of random data
            ul_key = [random_u32int() for _ in range(6)]
            k_bytes = a32_to_bytes(ul_key[:4])

            # and 64 bits for the IV (which has size 128 bits anyway)
            count = Counter.new(128, initial_value=((ul_key[4] << 32) + ul_key[5]) << 64)
            aes = AES.new(k_bytes, AES.MODE_CTR, counter=count)

            upload_progress = 0
            completion_file_handle = None

            mac_bytes = b"\0" * 16
            mac_encryptor = AES.new(k_bytes, AES.MODE_CBC, mac_bytes)
            iv_bytes = a32_to_bytes([ul_key[4], ul_key[5], ul_key[4], ul_key[5]])
            if file_size > 0:
                for chunk_start, chunk_size in get_chunks(file_size):
                    chunk = input_file.read(chunk_size)
                    actual_size = len(chunk)
                    upload_progress += actual_size
                    encryptor = AES.new(k_bytes, AES.MODE_CBC, iv_bytes)

                    mem_view = memoryview(chunk)
                    for index in range(0, actual_size - CHUNK_BLOCK_LEN, CHUNK_BLOCK_LEN):
                        block = mem_view[index : index + CHUNK_BLOCK_LEN]
                        encryptor.encrypt(block)

                    modchunk = actual_size % CHUNK_BLOCK_LEN
                    if modchunk == 0:
                        # ensure we reserve the last 16 bytes anyway, we have to feed them into mac_encryptor
                        modchunk = CHUNK_BLOCK_LEN

                    # pad last block to 16 bytes
                    last_block = pad_bytes(mem_view[-modchunk:])

                    mac_bytes = mac_encryptor.encrypt(encryptor.encrypt(last_block))

                    # encrypt file and upload
                    chunk = aes.encrypt(chunk)
                    output_file = await self.api.session.post(
                        ul_url + "/" + str(chunk_start), data=chunk, timeout=self.api.timeout
                    )
                    completion_file_handle = await output_file.text()
                    logger.info("%s of %s uploaded", upload_progress, file_size)
            else:
                # empty file
                output_file = await self.api.session.post(ul_url + "/0", data="", timeout=self.api.timeout)
                completion_file_handle = await output_file.text()

            logger.info("Chunks uploaded")
            logger.info("Setting attributes to complete upload")
            logger.info("Computing attributes")
            file_mac: TupleArray = str_to_a32(mac_bytes)

            # determine meta mac
            meta_mac = (file_mac[0] ^ file_mac[1], file_mac[2] ^ file_mac[3])

            dest_filename = dest_filename or os.path.basename(filename)
            attribs = {"n": dest_filename}

            encrypt_attribs = base64_url_encode(encrypt_attr(attribs, ul_key[:4]))
            key: Array = [
                ul_key[0] ^ ul_key[4],
                ul_key[1] ^ ul_key[5],
                ul_key[2] ^ meta_mac[0],
                ul_key[3] ^ meta_mac[1],
                ul_key[4],
                ul_key[5],
                meta_mac[0],
                meta_mac[1],
            ]
            encrypted_key = a32_to_base64(encrypt_key(key, self.master_key))
            logger.info("Sending request to update attributes")
            # update attributes
            data: Folder = await self.api.request(
                {
                    "a": "p",
                    "t": dest_node_id,
                    "i": self.api.request_id,
                    "n": [{"h": completion_file_handle, "t": 0, "a": encrypt_attribs, "k": encrypted_key}],
                }
            )
            logger.info("Upload complete")
            return data

    async def _mkdir(self, name: str, parent_node_id: str) -> Folder:
        # generate random aes key (128) for folder
        ul_key = [random_u32int() for _ in range(6)]

        # encrypt attribs
        attribs = {"n": name}
        encrypt_attribs = base64_url_encode(encrypt_attr(attribs, ul_key[:4]))
        encrypted_key = a32_to_base64(encrypt_key(ul_key[:4], self.master_key))

        # This can return multiple folders if subfolders needed to be created
        folders: dict[str, list[Folder]] = await self.api.request(
            {
                "a": "p",
                "t": parent_node_id,
                "n": [{"h": "xxxxxxxx", "t": 1, "a": encrypt_attribs, "k": encrypted_key}],
                "i": self.api.request_id,
            }
        )
        return folders["f"][0]

    async def create_folder(self, path: Path | str) -> Folder:
        path = Path(path)
        last_parent = await self.find_by_handle(self.root_id)
        assert last_parent
        for parent in reversed(path.parents):
            node = await self.find(parent, exclude_deleted=True)
            if node:
                last_parent = node
            else:
                last_parent = await self._mkdir(name=parent.name, parent_node_id=last_parent["h"])

        return await self._mkdir(name=path.name, parent_node_id=last_parent["h"])

    async def rename(self, node: FileOrFolder, new_name: str) -> int:
        # create new attribs
        attribs = {"n": new_name}
        # encrypt attribs
        encrypt_attribs = base64_url_encode(encrypt_attr(attribs, node["k_decrypted"]))
        encrypted_key = a32_to_base64(encrypt_key(node["key_decrypted"], self.master_key))
        # update attributes
        return await self.api.request(
            {
                "a": "a",
                "attr": encrypt_attribs,
                "key": encrypted_key,
                "n": node["h"],
                "i": self.api.request_id,
            }
        )

    async def move(self, file_id: str, target: Folder | NodeType | str) -> AnyDict:
        """
        Move a file to another parent node
        params:
        a : command
        n : node we're moving
        t : id of target parent node, moving to
        i : request id

        targets
        2 : root
        3 : inbox
        4 : trash

        or...
        target's id
        or...
        target's structure returned by find()
        """

        if isinstance(target, int):
            result = await self.get_node_by_type(target)
            if not result:
                raise MegaNzError(f"Node type {target} does not exists")
            target_node_id = result["h"]
        else:
            target_node_id = target
        return await self.api.request(
            {
                "a": "m",
                "n": file_id,
                "t": target_node_id,
                "i": self.api.request_id,
            }
        )

    async def add_contact(self, email: str) -> AnyDict:
        """
        Add another user to your mega contact list
        """
        return await self._edit_contact(email, True)

    async def remove_contact(self, email: str) -> AnyDict:
        """
        Remove a user to your mega contact list
        """
        return await self._edit_contact(email, False)

    async def _edit_contact(self, email: str, add: bool) -> AnyDict:
        """
        Editing contacts
        """
        if add is True:
            add_or_remove = "1"  # add command
        elif add is False:
            add_or_remove = "0"  # remove command
        else:
            raise ValidationError("add parameter must be of type bool")

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            raise ValidationError("add_contact requires a valid email address")
        else:
            return await self.api.request(
                {
                    "a": "ur",
                    "u": email,
                    "l": add_or_remove,
                    "i": self.api.request_id,
                }
            )

    async def get_public_url_info(self, url: str) -> AnyDict | None:
        """
        Get size and name from a public url, dict returned
        """
        file_handle, file_key = self._parse_url(url).split("!")
        return await self.get_public_file_info(file_handle, file_key)

    async def import_public_url(
        self, url: str, dest_node: FileOrFolder | str | None = None, dest_name: str | None = None
    ) -> Folder:
        """
        Import the public url into user account
        """
        file_handle, file_key = self._parse_url(url).split("!")
        return await self.import_public_file(file_handle, file_key, dest_node=dest_node, dest_name=dest_name)

    async def get_public_file_info(self, file_handle: str, file_key: str) -> AnyDict | None:
        """
        Get size and name of a public file
        """
        data: Folder = await self.api.request(
            {
                "a": "g",
                "p": file_handle,
                "ssm": 1,
            }
        )
        if "at" not in data or "s" not in data:
            raise ValueError("Unexpected result", data)

        key = base64_to_a32(file_key)
        k: TupleArray = (key[0] ^ key[4], key[1] ^ key[5], key[2] ^ key[6], key[3] ^ key[7])

        size = data["s"]
        unencrypted_attrs = decrypt_attr(base64_url_decode(data["at"]), k)
        if not unencrypted_attrs:
            return None
        result = {"size": size, "name": unencrypted_attrs["n"]}
        return result

    async def import_public_file(
        self,
        file_handle: str,
        file_key: str,
        dest_node: FileOrFolder | str | None = None,
        dest_name: str | None = None,
    ) -> Folder:
        """
        Import the public file into user account
        """
        # Providing dest_node spare an API call to retrieve it.
        if not self.logged_in:
            raise MegaNzError("You have to log in to import files")

        if dest_node is None:
            # Get '/Cloud Drive' folder no dest node specified
            dest_node_id: str = self.root_id
        elif isinstance(dest_node, str):
            dest_node_id = dest_node
        else:
            dest_node_id = dest_node["h"]

        # Providing dest_name spares an API call to retrieve it.
        if dest_name is None:
            pl_info = await self.get_public_file_info(file_handle, file_key)
            assert pl_info
            dest_name = pl_info["name"]

        key = base64_to_a32(file_key)
        k: TupleArray = (key[0] ^ key[4], key[1] ^ key[5], key[2] ^ key[6], key[3] ^ key[7])

        encrypted_key: str = a32_to_base64(encrypt_key(key, self.master_key))
        encrypted_name: str = base64_url_encode(encrypt_attr({"n": dest_name}, k))
        return await self.api.request(
            {
                "a": "p",
                "t": dest_node_id,
                "n": [
                    {
                        "ph": file_handle,
                        "t": 0,
                        "a": encrypted_name,
                        "k": encrypted_key,
                    },
                ],
            }
        )

    async def build_file_system(self) -> dict[PurePosixPath, Node]:
        nodes_map = {node["h"]: node async for node in self._get_nodes()}
        return await self._build_file_system(nodes_map, list(self.special_nodes_mapping.values()))

    async def _build_file_system(self, nodes_map: dict[str, Node], root_ids: list[str]) -> dict[PurePosixPath, Node]:
        """Builds a flattened dictionary representing a file system from a list of items.

        Returns:
            A 1-level dictionary where the each keys is the full path to a file/folder, and each value is the actual file/folder
        """
        if not self.logged_in:
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
