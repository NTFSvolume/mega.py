from __future__ import annotations

import hashlib
import logging
import os
import random
import re
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, cast

import requests
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
    from collections.abc import Generator

logger = logging.getLogger(__name__)


class Mega:
    def __init__(self) -> None:
        self.api = MegaApi()
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
        self.primary_url = f"{self.api.schema}://{self.api.domain}"
        self.logged_in = False
        self.root_id: str = ""
        self.inbox_id: str = ""
        self.trashbin_id: str = ""

    def login(self, email: str | None = None, password: str | None = None):
        if email and password:
            self._login_user(email, password)
        else:
            self.login_anonymous()
        _ = self.get_files()  # This is to set the special folders id
        self.logged_in = True
        logger.info(f"Special folders: root: {self.root_id} inbox: {self.inbox_id} trash_bin: {self.trashbin_id}")
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

    def _login_user(self, email: str, password: str) -> None:
        logger.info("Logging in user...")
        email = email.lower()
        get_user_salt_resp: dict = self.api.request(
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

        resp = self.api.request(
            {
                "a": "us",
                "user": email,
                "uh": user_hash,
            }
        )
        self._process_login(resp, password_aes)

    def login_anonymous(self):
        logger.info("Logging in anonymous temporary user...")
        master_key = [random_u32int()] * 4
        password_key = [random_u32int()] * 4
        session_self_challenge = [random_u32int()] * 4

        user: str = self.api.request(
            {
                "a": "up",
                "k": a32_to_base64(encrypt_key(master_key, password_key)),
                "ts": base64_url_encode(
                    a32_to_bytes(session_self_challenge) + a32_to_bytes(encrypt_key(session_self_challenge, master_key))
                ),
            }
        )

        resp = self.api.request(
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
            raise ValueError("URL key missing")

    def _process_node(self, file: Node, shared_keys: SharedkeysDict) -> Node:
        if file["t"] == NodeType.FILE or file["t"] == NodeType.FOLDER:
            file = cast(FileOrFolder, file)
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
                    file = cast(File, file)
                    k = (key[0] ^ key[4], key[1] ^ key[5], key[2] ^ key[6], key[3] ^ key[7])
                    file["iv"] = key[4:6] + (0, 0)
                    file["meta_mac"] = key[6:8]
                # folder
                else:
                    k = key

                file["key_decrypted"] = key
                file["k_decrypted"] = k
                attributes_bytes = base64_url_decode(file["a"])
                attributes = decrypt_attr(attributes_bytes, k)
                file["attributes"] = cast(Attributes, attributes)

            # other => wrong object
            elif file["k"] == "":
                file = cast(Node, file)
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

    def find(self, filename_or_path: Path | str, exclude_deleted: bool = False) -> FileOrFolder | None:
        """
        Return file object(s) from given filename or path
        """
        results = self._search(filename_or_path, exclude_deleted, strict=True)
        return results[0] if results else None

    def search(self, filename_or_path: Path | str, exclude_deleted: bool = False) -> list[FileOrFolder]:
        """
        Return file object(s) from given filename or path
        """
        return self._search(filename_or_path, exclude_deleted)

    def _search(self, filename_or_path: Path | str, exclude_deleted: bool = False, strict=False) -> list[FileOrFolder]:
        """
        Return file object(s) from given filename or path
        """

        filename_or_path = str(filename_or_path)

        fs = self.build_file_system()

        found = []
        for path, item in fs.items():
            if filename_or_path in (path_str := str(path)):
                if strict and not path_str.startswith(filename_or_path):
                    continue
                if exclude_deleted and item["p"] == self.trashbin_id:
                    continue
                found.append(item)
        return found

    def find_by_handle(self, handle: str, exclude_deleted: bool = False) -> FileOrFolder | None:
        """Return file object(s) from given filename or path"""
        files = self.get_files()
        return found if (found := files.get(handle)) else None

    def get_files(self) -> FilesMapping:
        logger.info("Getting all files...")
        files_dict: FilesMapping = {}
        for node in self._get_nodes():
            if node["attributes"]:
                file = cast(File, node)
                files_dict[file["h"]] = file
        return files_dict

    def _get_nodes(self) -> Generator[Node]:
        files: Folder = self.api.request(
            {
                "a": "f",
                "c": 1,
                "r": 1,
            }
        )
        shared_keys: SharedkeysDict = {}
        self._init_shared_keys(files, shared_keys)
        for node in files["f"]:
            yield self._process_node(node, shared_keys)

    def _get_nodes_in_shared_folder(self, folder_id: str) -> Generator[Node]:
        files: Folder = self.api.request(
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
        for node in files["f"]:
            yield self._process_node(node, self.shared_keys)

    def _parse_folder_url(self, url: str) -> tuple[str, str]:
        if "/folder/" in url:
            _, parts = url.split("/folder/", 1)
        elif "#F!" in url:
            _, parts = url.split("#F!", 1)
        else:
            raise ValidationError("Not a valid folder URL")
        root_folder_id, shared_key = parts.split("#")
        return root_folder_id, shared_key

    def get_upload_link(self, folder: Folder) -> str:
        """
        Get a files public link inc. decrypted key
        Requires upload() response as input
        """
        if "f" not in folder:
            raise ValueError("""Upload() response required as input, use get_link() for regular file input""")

        file = folder["f"][0]
        public_handle: str = self.api.request(
            {
                "a": "l",
                "n": file["h"],
            }
        )
        _, file_key = file["k"].split(":", 1)
        decrypted_key = a32_to_base64(decrypt_key(base64_to_a32(file_key), self.master_key))
        return f"{self.primary_url}/#!{public_handle}!{decrypted_key}"

    def get_link(self, file: FileOrFolder) -> str:
        """
        Get a file public link from given file object
        """

        if not ("h" in file and "key_decrypted" in file):
            raise ValidationError("File id and key must be present")

        public_handle: str = self._get_public_handle(file)
        decrypted_key = a32_to_base64(file["key_decrypted"])
        return f"{self.primary_url}/#!{public_handle}!{decrypted_key}"

    def get_folder_link(self, folder: FileOrFolder) -> str:
        if not ("h" in folder and "sk_decrypted" in folder):
            raise ValidationError("Folder id and key must be present")

        public_handle: str = self._get_public_handle(folder)
        decrypted_key = a32_to_base64(folder["sk_decrypted"])
        return f"{self.primary_url}/#F!{public_handle}!{decrypted_key}"

    def _get_public_handle(self, file: FileOrFolder) -> str:
        try:
            public_handle: str = self.api.request(
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

    def get_user(self) -> AnyDict:
        user_data: AnyDict = self.api.request(
            {
                "a": "ug",
            }
        )
        return user_data

    def get_node_by_type(self, node_type: NodeType | int) -> Node | None:
        """
        Get a node by it's numeric type id, e.g:
        0: file
        1: dir
        2: special: root cloud drive
        3: special: inbox
        4: special trash bin
        """
        nodes = self.get_files()
        for _, node in nodes.items():
            if node["t"] == node_type:
                return node

    def get_files_in_node(self, target: NodeType | str) -> FilesMapping:
        """
        Get all files in a given target, e.g. 4=trash
        """
        node_id = target
        folder: Folder = self.api.request(
            {
                "a": "f",
                "c": 1,
            }
        )
        files_dict: FilesMapping = {}
        shared_keys: SharedkeysDict = {}
        self._init_shared_keys(folder, shared_keys)
        for file in folder["f"]:
            processed_file = cast(FileOrFolder, self._process_node(file, shared_keys))
            if processed_file["a"] and processed_file["p"] == node_id:
                files_dict[file["h"]] = processed_file
        return files_dict

    def get_id_from_public_handle(self, public_handle: str) -> str:
        # get node data
        node_data: Folder = self.api.request(
            {
                "a": "f",
                "f": 1,
                "p": public_handle,
            }
        )

        def get_id_from_obj() -> str | None:
            """
            Get node id from a file object
            """

            for i in node_data["f"]:
                if i["h"] != "":
                    return i["h"]

        node_id = get_id_from_obj()
        assert node_id
        return node_id

    def get_quota(self) -> int:
        """Get current remaining disk quota."""
        json_resp: AnyDict = self.api.request(
            {
                "a": "uq",  # Action: user quota
                "xfer": 1,
                "strg": 1,
                "v": 1,
            }
        )
        return json_resp["mstrg"]

    def get_storage_space(self) -> StorageUsage:
        """
        Get the current storage space.
        Return a dict containing at least:
          'used' : the used space on the account
          'total' : the maximum space allowed with current plan
        All storage space are in bytes unless asked differently.
        """
        json_resp: AnyDict = self.api.request(
            {
                "a": "uq",
                "xfer": 1,
                "strg": 1,
            }
        )
        return StorageUsage(json_resp["cstrg"], json_resp["mstrg"])

    def get_balance(self) -> int | None:
        """Get account monetary balance, Pro accounts only."""
        user_data: AnyDict = self.api.request(
            {
                "a": "uq",
                "pro": 1,
            }
        )
        return user_data.get("balance")

    def delete(self, public_handle: str) -> AnyDict:
        """Delete a file by its public handle."""
        return self.move(public_handle, NodeType.TRASH)

    def delete_url(self, url: str) -> AnyDict:
        """Delete a file by its url"""
        public_handle, _ = self._parse_url(url).split("!")
        file_id = self.get_id_from_public_handle(public_handle)
        return self.move(file_id, NodeType.TRASH)

    def destroy(self, file_id: str) -> AnyDict:
        """Destroy a file by its private id (bypass trash bin)"""
        return self.api.request(
            {
                "a": "d",  # Action: delete
                "n": file_id,  # Node: file Id
                "i": self.api.request_id,  # Request Id
            }
        )

    def destroy_url(self, url: str) -> AnyDict:
        """Destroy a file by its url (bypass trash bin)"""
        public_handle, *_ = self._parse_url(url).split("!")
        file_id = self.get_id_from_public_handle(public_handle)
        return self.destroy(file_id)

    def empty_trash(self) -> AnyDict | None:
        """Deletes all file in the trash bin. Returns None if the trash was already empty"""
        # get list of files in rubbish out
        files = self.get_files_in_node(NodeType.TRASH)

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
            return self.api.request(post_list)

    def download(
        self, file: FileOrFolder | None, dest_path: str | None = None, dest_filename: str | None = None
    ) -> Path:
        """Download a file by it's file object."""
        return self._download_file(
            file_handle=None,
            file_key=None,
            file=file,
            dest_path=dest_path,
            dest_filename=dest_filename,
            is_public=False,
        )

    def _export_file(self, node: FileOrFolder) -> str:
        self.api.request(
            [
                {
                    "a": "l",  # Action: Export file
                    "n": node["h"],  # Node: file Id
                    "i": self.api.request_id,  # Request #Id
                }
            ]
        )
        return self.get_link(node)

    def export(self, path: Path | str | None = None, node_id: str | None = None) -> str:
        files = self.get_files()
        if node_id:
            _node_id = node_id
            file: FileOrFolder = files[_node_id]
        elif path:
            found = self.find(path)
            if not found:
                raise ValueError
            file = found
        else:
            raise ValueError

        if file["t"] == NodeType.FILE:
            return self._export_file(file)

        if file:
            try:
                # If already exported
                return self.get_folder_link(file)
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
        self.api.request(
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
        files = self.get_files()
        return self.get_folder_link(files[_node_id])

    def download_url(self, url: str, dest_path: str | None = None, dest_filename: str | None = None) -> Path:
        """
        Download a file by it's public url
        """
        file_id, file_key = self._parse_url(url).split("!", 1)
        return self._download_file(
            file_handle=file_id,
            file_key=file_key,
            dest_path=dest_path,
            dest_filename=dest_filename,
            is_public=True,
        )

    def get_nodes_public_folder(self, url: str) -> dict[str, FileOrFolder]:
        folder_id, b64_share_key = self._parse_folder_url(url)
        shared_key = base64_to_a32(b64_share_key)

        def prepare_nodes():
            for node in self._get_nodes_in_shared_folder(folder_id):
                node = cast(FileOrFolder, node)
                encrypted_key = base64_to_a32(node["k"].split(":")[1])
                key = decrypt_key(encrypted_key, shared_key)
                if node["t"] == NodeType.FILE:
                    k = (key[0] ^ key[4], key[1] ^ key[5], key[2] ^ key[6], key[3] ^ key[7])
                elif node["t"] == NodeType.FOLDER:
                    k = key

                iv: AnyArray = key[4:6] + (0, 0)
                meta_mac: TupleArray = key[6:8]

                attrs = decrypt_attr(base64_url_decode(node["a"]), k)
                node["attributes"] = cast(Attributes, attrs)
                node["k_decrypted"] = k
                node["iv"] = iv
                node["meta_mac"] = meta_mac
                yield node

        nodes = {node["h"]: node for node in prepare_nodes()}
        return nodes

    def download_folder_url(self, url: str, dest_path: str | None = None) -> list[Path]:
        nodes = self.get_nodes_public_folder(url)
        downloaded: list[Path] = []
        root_id = next(iter(nodes))

        with self.progress:
            for path, node in self._build_file_system(nodes, [root_id]).items():  # type: ignore
                if node["t"] != NodeType.FILE:
                    continue

                file = cast(File, node)
                file_data = self.api.request(
                    {
                        "a": "g",
                        "g": 1,
                        "n": file["h"],
                    }
                )

                file_url = file_data["g"]
                file_size = file_data["s"]

                if dest_path:
                    path = Path(dest_path) / path

                result = self._really_download_file(
                    file_url,
                    path,
                    file_size,
                    file["iv"],
                    file["meta_mac"],
                    file["k_decrypted"],
                )
                downloaded.append(result)
        return downloaded

    def _download_file(
        self,
        file_handle: str | None = None,
        file_key: TupleArray | str | None = None,
        dest_path: str | None = None,
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

            file_data: File = self.api.request(
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
            iv: AnyArray = _file_key[4:6] + (0, 0)
            meta_mac: TupleArray = _file_key[6:8]
        else:
            file_data = self.api.request(
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
        attribs = cast(Attributes, attribs)

        if dest_filename is not None:
            file_name = dest_filename
        else:
            file_name: str = attribs["n"]

        if dest_path is None:
            dest_path = ""
        else:
            dest_path += "/"

        output_path = Path(dest_path + file_name)

        with self.progress:
            return self._really_download_file(file_url, output_path, file_size, iv, meta_mac, k)

    def _really_download_file(
        self,
        direct_file_url: str,
        output_path: Path,
        file_size: int,
        iv: TupleArray,
        meta_mac: TupleArray,
        k_decrypted: TupleArray,
    ):
        input_file = requests.get(direct_file_url, stream=True).raw

        with tempfile.NamedTemporaryFile(mode="w+b", prefix="megapy_", delete=False) as temp_output_file:
            task_id = self.progress.add_task(output_path.name, total=file_size)
            chunk_decryptor = self._decrypt_chunks(iv, k_decrypted, meta_mac)
            _ = next(chunk_decryptor)  # Prime chunk decryptor
            bytes_written: int = 0
            for _, chunk_size in get_chunks(file_size):
                raw_chunk = input_file.read(chunk_size)
                decrypted_chunk: bytes = chunk_decryptor.send(raw_chunk)
                actual_size = len(decrypted_chunk)
                bytes_written += actual_size
                temp_output_file.write(decrypted_chunk)
                self.progress.advance(task_id, actual_size)

        try:
            # Stop chunk decryptor and do a mac integrity check
            chunk_decryptor.send(None)  # type: ignore
        except StopIteration:
            pass
        finally:
            self.progress.remove_task(task_id)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(temp_output_file.name, output_path)
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

    def upload(self, filename: str, dest: str | None = None, dest_filename: str | None = None) -> Folder:
        # determine storage node
        dest = dest or self.root_id
        # request upload url, call 'u' method
        with open(filename, "rb") as input_file:
            file_size = os.path.getsize(filename)
            ul_url: str = self.api.request(
                {
                    "a": "u",
                    "s": file_size,
                }
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
                    output_file = requests.post(ul_url + "/" + str(chunk_start), data=chunk, timeout=self.api.timeout)
                    completion_file_handle = output_file.text
                    logger.info("%s of %s uploaded", upload_progress, file_size)
            else:
                # empty file
                output_file = requests.post(ul_url + "/0", data="", timeout=self.api.timeout)
                completion_file_handle = output_file.text

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
            data: Folder = self.api.request(
                {
                    "a": "p",
                    "t": dest,
                    "i": self.api.request_id,
                    "n": [{"h": completion_file_handle, "t": 0, "a": encrypt_attribs, "k": encrypted_key}],
                }
            )
            logger.info("Upload complete")
            return data

    def _mkdir(self, name: str, parent_node_id: str) -> AnyDict:
        # generate random aes key (128) for folder
        ul_key = [random_u32int() for _ in range(6)]

        # encrypt attribs
        attribs = {"n": name}
        encrypt_attribs = base64_url_encode(encrypt_attr(attribs, ul_key[:4]))
        encrypted_key = a32_to_base64(encrypt_key(ul_key[:4], self.master_key))

        # update attributes
        data: AnyDict = self.api.request(
            {
                "a": "p",
                "t": parent_node_id,
                "n": [{"h": "xxxxxxxx", "t": 1, "a": encrypt_attribs, "k": encrypted_key}],
                "i": self.api.request_id,
            }
        )
        return data

    def create_folder(self, path: Path | str) -> AnyDict:
        path = Path(path)
        last_parent = self.find_by_handle(self.root_id)
        assert last_parent
        for parent in reversed(path.parents):
            node = self.find(parent, exclude_deleted=True)
            if node:
                last_parent = node
            else:
                created_node = self._mkdir(name=parent.name, parent_node_id=last_parent["h"])
                last_parent = created_node["f"][0]

        actual_node = self._mkdir(name=path.name, parent_node_id=last_parent["h"])
        return actual_node

    def rename(self, file: FileOrFolder, new_name: str) -> AnyDict:
        # create new attribs
        attribs = {"n": new_name}
        # encrypt attribs
        encrypt_attribs = base64_url_encode(encrypt_attr(attribs, file["k_decrypted"]))
        encrypted_key = a32_to_base64(encrypt_key(file["key_decrypted"], self.master_key))
        # update attributes
        return self.api.request(
            {
                "a": "a",
                "attr": encrypt_attribs,
                "key": encrypted_key,
                "n": file["h"],
                "i": self.api.request_id,
            }
        )

    def move(self, file_id: str, target: Folder | NodeType | str) -> AnyDict:
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
            result = self.get_node_by_type(target)
            if not result:
                raise MegaNzError(f"Node type {target} does not exists")
            target_node_id = result["h"]
        else:
            target_node_id = target
        return self.api.request(
            {
                "a": "m",
                "n": file_id,
                "t": target_node_id,
                "i": self.api.request_id,
            }
        )

    def add_contact(self, email: str) -> AnyDict:
        """
        Add another user to your mega contact list
        """
        return self._edit_contact(email, True)

    def remove_contact(self, email: str) -> AnyDict:
        """
        Remove a user to your mega contact list
        """
        return self._edit_contact(email, False)

    def _edit_contact(self, email: str, add: bool) -> AnyDict:
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
            return self.api.request(
                {
                    "a": "ur",
                    "u": email,
                    "l": add_or_remove,
                    "i": self.api.request_id,
                }
            )

    def get_public_url_info(self, url: str) -> AnyDict | None:
        """
        Get size and name from a public url, dict returned
        """
        file_handle, file_key = self._parse_url(url).split("!")
        return self.get_public_file_info(file_handle, file_key)

    def import_public_url(
        self, url: str, dest_node: FileOrFolder | str | None = None, dest_name: str | None = None
    ) -> Folder:
        """
        Import the public url into user account
        """
        file_handle, file_key = self._parse_url(url).split("!")
        return self.import_public_file(file_handle, file_key, dest_node=dest_node, dest_name=dest_name)

    def get_public_file_info(self, file_handle: str, file_key: str) -> AnyDict | None:
        """
        Get size and name of a public file
        """
        data: Folder = self.api.request(
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

    def import_public_file(
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
            pl_info = self.get_public_file_info(file_handle, file_key)
            assert pl_info
            dest_name = pl_info["name"]

        key = base64_to_a32(file_key)
        k: TupleArray = (key[0] ^ key[4], key[1] ^ key[5], key[2] ^ key[6], key[3] ^ key[7])

        encrypted_key: str = a32_to_base64(encrypt_key(key, self.master_key))
        encrypted_name: str = base64_url_encode(encrypt_attr({"n": dest_name}, k))
        return self.api.request(
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

    def build_file_system(self) -> dict[Path, Node]:
        special_folders_id = [self.root_id, self.inbox_id, self.trashbin_id]
        nodes_map = {node["h"]: node for node in self._get_nodes()}
        return self._build_file_system(nodes_map, special_folders_id)

    def _build_file_system(self, nodes_map: dict[str, Node], root_ids: list[str]) -> dict[Path, Node]:
        """Builds a flattened dictionary representing a file system from a list of items.

        Returns:
            A 1-level dictionary where the each keys is the full path to a file/folder, and each value is the actual file/folder
        """
        if not self.logged_in:
            raise MegaNzError("You must log in to build your file system")

        path_mapping: dict[Path, Node] = {}
        parents_mapping: dict[str, list[Node]] = {}

        for _, item in nodes_map.items():
            parent_id = item["p"]
            if parent_id not in parents_mapping:
                parents_mapping[parent_id] = []
            parents_mapping[parent_id].append(item)

        def build_tree(parent_id: str, current_path: Path) -> None:
            for item in parents_mapping.get(parent_id, []):
                item_path = current_path / item["attributes"]["n"]
                path_mapping[item_path] = item

                if item["t"] == NodeType.FOLDER:
                    build_tree(item["h"], item_path)

        for root_id in root_ids:
            root_item = nodes_map[root_id]
            name = root_item["attributes"]["n"]
            path = Path(name if name != "Cloud Drive" else ".")
            path_mapping[path] = root_item
            build_tree(root_id, path)

        sorted_mapping = dict(sorted(path_mapping.items()))
        return sorted_mapping
