from __future__ import annotations

import binascii
import hashlib
import logging
import math
import os
import random
import re
import secrets
import shutil
import string
import tempfile
from pathlib import Path
from typing import Any, Union, cast

import requests
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from rich.progress import BarColumn, DownloadColumn, Progress, SpinnerColumn, TimeRemainingColumn, TransferSpeedColumn
from tenacity import retry, retry_if_exception_type, wait_exponential

from mega.crypto import (
    CHUNK_BLOCK_LEN,
    a32_to_base64,
    a32_to_bytes,
    base64_to_a32,
    base64_url_decode,
    base64_url_encode,
    decrypt_attr,
    decrypt_key,
    encrypt_attr,
    encrypt_key,
    get_chunks,
    make_hash,
    modular_inverse,
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
    FileOrFolderDict,
    FileOrFolderTuple,
    Folder,
    NodeType,
    SharedKey,
    SharedkeysDict,
    StorageUsage,
    TupleArray,
    U32Int,
)

from .errors import RequestError, ValidationError
from .xhashcash import generate_hashcash_token

VALID_REQUEST_ID_CHARS = string.ascii_letters + string.digits


def make_request_id(length: int = 10) -> str:
    text = ""
    for _ in range(length):
        text += random.choice(VALID_REQUEST_ID_CHARS)
    return text


logger = logging.getLogger(__name__)


class Mega:
    def __init__(self, options: AnyDict | None = None) -> None:
        self.schema = "https"
        self.domain = "mega.nz"
        # api still uses the old mega.co.nz domain
        self.api_domain = "g.api.mega.co.nz"
        self.timeout = 160  # max secs to wait for resp from api requests
        self.sid = None
        self.sequence_num: U32Int = random_u32int()
        self.request_id: str = make_request_id()
        self._trash_folder_node_id: str | None = None

        if options is None:
            options = {}
        self.options: AnyDict = options

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
            TimeRemainingColumn(),
        )
        self.progress = Progress(*progress_columns)

    def login(self, email: str | None = None, password: str | None = None):
        if email and password:
            self._login_user(email, password)
        else:
            self.login_anonymous()
        node_info = self.get_node_by_type(NodeType.TRASH)
        self._trash_folder_node_id = node_info[0] if node_info else None
        logger.info("Login complete")
        return self

    def _login_user(self, email: str, password: str) -> None:
        logger.info("Logging in user...")
        email = email.lower()
        get_user_salt_resp = self._api_request({"a": "us0", "user": email})
        try:
            user_salt = base64_to_a32(get_user_salt_resp["s"])
        except KeyError:
            # v1 user account
            password_aes = prepare_key(str_to_a32(password))
            user_hash = make_hash(email, password_aes)
        else:
            # v2 user account
            pbkdf2_key = hashlib.pbkdf2_hmac(
                hash_name="sha512",
                password=password.encode(),
                salt=a32_to_bytes(user_salt),
                iterations=100000,
                dklen=32,
            )
            password_aes = str_to_a32(pbkdf2_key[:16])
            user_hash = base64_url_encode(pbkdf2_key[-16:])
        resp = self._api_request({"a": "us", "user": email, "uh": user_hash})
        if isinstance(resp, int):
            raise RequestError(resp)
        self._login_process(resp, password_aes)

    def login_anonymous(self):
        logger.info("Logging in anonymous temporary user...")
        master_key = [random_u32int()] * 4
        password_key = [random_u32int()] * 4
        session_self_challenge = [random_u32int()] * 4

        user: str = self._api_request(
            {
                "a": "up",
                "k": a32_to_base64(encrypt_key(master_key, password_key)),
                "ts": base64_url_encode(
                    a32_to_bytes(session_self_challenge) + a32_to_bytes(encrypt_key(session_self_challenge, master_key))
                ),
            }
        )

        resp = self._api_request({"a": "us", "user": user})
        if isinstance(resp, int):
            raise RequestError(resp)
        self._login_process(resp, password_key)

    def _login_process(self, resp: AnyDict, password: Array):
        encrypted_master_key = base64_to_a32(resp["k"])
        self.master_key = decrypt_key(encrypted_master_key, password)
        if "tsid" in resp:
            tsid = base64_url_decode(resp["tsid"])
            key_encrypted = a32_to_bytes(encrypt_key(str_to_a32(tsid[:16]), self.master_key))
            if key_encrypted == tsid[-16:]:
                self.sid = resp["tsid"]
        elif "csid" in resp:
            encrypted_private_key = base64_to_a32(resp["privk"])
            private_key = a32_to_bytes(decrypt_key(encrypted_private_key, self.master_key))

            # The private_key contains 4 MPI integers concatenated together.
            rsa_private_key = [0, 0, 0, 0]
            for i in range(4):
                # An MPI integer has a 2-byte header which describes the number
                # of bits in the integer.
                bitlength = (private_key[0] * 256) + private_key[1]
                bytelength = math.ceil(bitlength / 8)
                # Add 2 bytes to accommodate the MPI header
                bytelength += 2
                rsa_private_key[i] = mpi_to_int(private_key[:bytelength])
                private_key = private_key[bytelength:]

            first_factor_p = rsa_private_key[0]
            second_factor_q = rsa_private_key[1]
            private_exponent_d = rsa_private_key[2]
            crt_coeficient_u = rsa_private_key[3]
            # In MEGA's webclient javascript, they assign [3] to a variable
            # called u, but I do not see how it corresponds to pycryptodome's
            # RSA.construct and it does not seem to be necessary.

            rsa_modulus_n = first_factor_p * second_factor_q
            phi = (first_factor_p - 1) * (second_factor_q - 1)
            public_exponent_e = modular_inverse(private_exponent_d, phi)

            rsa_components = (
                rsa_modulus_n,
                public_exponent_e,
                private_exponent_d,
                first_factor_p,
                second_factor_q,
                crt_coeficient_u,
            )

            rsa_key = RSA.construct(rsa_components, consistency_check=True)
            encrypted_sid = mpi_to_int(base64_url_decode(resp["csid"]))

            # TODO: Investigate how to decrypt using the current pycryptodome library.
            # The _decrypt method of RSA is deprecated and no longer available.
            # The documentation suggests using Crypto.Cipher.PKCS1_OAEP,
            # but the algorithm differs and requires bytes as input instead of integers.
            sid_hex = f"{rsa_key._decrypt(encrypted_sid):x}"
            sid_bytes = binascii.unhexlify("0" + sid_hex if len(sid_hex) % 2 else sid_hex)
            sid = base64_url_encode(sid_bytes[:43])
            self.sid = sid

    @retry(retry=retry_if_exception_type(RuntimeError), wait=wait_exponential(multiplier=2, min=2, max=60))
    def _api_request(self, data_input: list[AnyDict] | AnyDict) -> Any:
        params: AnyDict = {"id": self.sequence_num}
        self.sequence_num += 1
        DEFAULT_HEADERS = {"Content-Type": "application/json"}

        if self.sid:
            params["sid"] = self.sid

        # ensure input data is a list
        if not isinstance(data_input, list):
            data = [data_input]
        else:
            data: list[AnyDict] = data_input

        url = f"{self.schema}://{self.api_domain}/cs"

        response = requests.post(url, params=params, json=data, timeout=self.timeout, headers=DEFAULT_HEADERS)

        # Since around feb 2025, MEGA requires clients to solve a challenge during each login attempt.
        # When that happends, initial responses returns "402 Payment Required".
        # Challenge is inside the `X-Hashcash` header.
        # We need to solve the challenge and re-made the request with same params + the computed token
        # See:  https://github.com/gpailler/MegaApiClient/issues/248#issuecomment-2692361193

        if xhashcash_challenge := response.headers.get("X-Hashcash"):
            logger.info("Solving xhashcash login challenge, this could take a few seconds...")
            xhashcash_token = generate_hashcash_token(xhashcash_challenge)
            new_headers = DEFAULT_HEADERS | {"X-Hashcash": xhashcash_token}
            response = requests.post(url, params=params, json=data, timeout=self.timeout, headers=new_headers)

        # Computed token failed
        if xhashcash_challenge := response.headers.get("X-Hashcash"):
            msg = f"Login failed. Mega requested a proof of work with xhashcash: {xhashcash_challenge}"
            raise RequestError(msg)

        json_resp = response.json()
        try:
            if isinstance(json_resp, list):
                int_resp = json_resp[0] if isinstance(json_resp[0], int) else None
            elif isinstance(json_resp, int):
                int_resp = json_resp
        except IndexError:
            int_resp = None
        if int_resp is not None:
            if int_resp == 0:
                return int_resp
            if int_resp == -3:
                msg = "Request failed, retrying"
                logger.info(msg)
                raise RuntimeError(msg)
            raise RequestError(int_resp)
        return json_resp[0]  # type: ignore

    def _parse_url(self, url: str) -> str:
        """Parse file id and key from url."""
        if "/file/" in url:
            # V2 URL structure
            url = url.replace(" ", "")
            file_id = re.findall(r"\W\w\w\w\w\w\w\w\w\W", url)[0][1:-1]
            match = re.search(file_id, url)
            assert match
            id_index = match.end()
            key = url[id_index + 1 :]
            return f"{file_id}!{key}"
        elif "!" in url:
            # V1 URL structure
            match = re.findall(r"/#!(.*)", url)
            path = match[0]
            return path
        else:
            raise RequestError("Url key missing")

    def _process_file(self, file: FileOrFolder, shared_keys: SharedkeysDict) -> FileOrFolder:
        if file["t"] == NodeType.FILE or file["t"] == NodeType.FOLDER:
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
                file["decrypted_sk"] = shared_key

            if key is not None:
                # file
                if file["t"] == NodeType.FILE:
                    k = (key[0] ^ key[4], key[1] ^ key[5], key[2] ^ key[6], key[3] ^ key[7])
                    file["iv"] = key[4:6] + (0, 0)
                    file["meta_mac"] = key[6:8]
                # folder
                else:
                    k = key

                file["key"] = key
                file["decrypted_k"] = k
                attributes_bytes = base64_url_decode(file["a"])
                attributes = decrypt_attr(attributes_bytes, k)
                file["attributes"] = cast(Attributes, attributes)

            # other => wrong object
            elif file["k"] == "":
                file["attributes"] = {"n": "Unknown Object"}

        elif file["t"] == NodeType.ROOT_FOLDER:
            self.root_id: str = file["h"]
            file["attributes"] = {"n": "Cloud Drive"}

        elif file["t"] == NodeType.INBOX:
            self.inbox_id = file["h"]
            file["attributes"] = {"n": "Inbox"}

        elif file["t"] == NodeType.TRASH:
            self.trashbin_id = file["h"]
            file["attributes"] = {"n": "Rubbish Bin"}

        return file

    def _init_shared_keys(self, files: dict[str, list[FileOrFolder]], shared_keys: SharedkeysDict) -> None:
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

    def find_path_descriptor(self, path: str, files: FileOrFolderDict | None = None) -> str | None:
        """
        Find descriptor of folder inside a path. i.e.: folder1/folder2/folder3
        Params:
            path, string like folder1/folder2/folder3
        Return:
            Descriptor (str) of folder3 if exists, None otherwise
        """
        paths = path.split("/")

        _files: FileOrFolderDict = files or self.get_files()
        parent_desc = self.root_id
        found = False
        for foldername in paths:
            if foldername != "":
                for name, item in _files.items():
                    file: FileOrFolder = item
                    if file["a"] and file["t"] and file["attributes"]["n"] == foldername:
                        if parent_desc == file["p"]:
                            parent_desc = name
                            found = True
                if found:
                    found = False
                else:
                    return None
        return parent_desc

    def find(
        self, filename: Path | str | None = None, handle: str | None = None, exclude_deleted: bool = False
    ) -> FileOrFolderTuple | None:
        """
        Return file object from given filename
        """
        files = self.get_files()
        if handle:
            return handle, files[handle]
        assert filename
        path = Path(filename)
        filename = path.name
        parent_dir_name = path.parent.name
        for parent_id, file in files.items():
            file: FileOrFolder = file
            parent_node_id = None
            try:
                if parent_dir_name:
                    parent_node_id = self.find_path_descriptor(parent_dir_name, files)
                    if (
                        filename
                        and parent_node_id
                        and file["a"]
                        and file["attributes"]["n"] == filename
                        and parent_node_id == file["p"]
                    ):
                        if exclude_deleted and self._trash_folder_node_id == file["p"]:
                            continue
                        return parent_id, file

                elif filename and file["a"] and file["attributes"]["n"] == filename:
                    if exclude_deleted and self._trash_folder_node_id == file["p"]:
                        continue
                    return parent_id, file
            except TypeError:
                continue
        return None

    def get_files(self) -> FileOrFolderDict:
        logger.info("Getting all files...")
        files: dict[str, list[FileOrFolder]] = self._api_request({"a": "f", "c": 1, "r": 1})
        files_dict = {}
        shared_keys: SharedkeysDict = {}
        self._init_shared_keys(files, shared_keys)
        for file in files["f"]:
            processed_file = self._process_file(file, shared_keys)
            # ensure each file has a name before returning
            if processed_file["a"]:
                files_dict[file["h"]] = processed_file
        return files_dict

    def get_upload_link(self, folder: Folder) -> str:
        """
        Get a files public link inc. decrypted key
        Requires upload() response as input
        """
        if "f" in folder:
            file = folder["f"][0]
            public_handle: str = self._api_request({"a": "l", "n": file["h"]})
            file_key = file["k"][file["k"].index(":") + 1 :]
            decrypted_key = a32_to_base64(decrypt_key(base64_to_a32(file_key), self.master_key))
            return f"{self.schema}://{self.domain}/#!{public_handle}!{decrypted_key}"
        else:
            raise ValueError("""Upload() response required as input,
                            use get_link() for regular file input""")

    @staticmethod
    def __get_file(node_or_file: FileOrFolderTuple | FileOrFolder) -> FileOrFolder:
        if isinstance(node_or_file, tuple):
            file: FileOrFolder = node_or_file[1]
        else:
            file = node_or_file
        return file

    def get_link(self, file_or_node: FileOrFolderTuple | FileOrFolder) -> str:
        """
        Get a file public link from given file object
        """
        file: FileOrFolder = self.__get_file(file_or_node)
        if "h" in file and "k" in file:
            public_handle: str | int = self._api_request({"a": "l", "n": file["h"]})
            if public_handle == -11:
                raise RequestError("Can't get a public link from that file (is this a shared file?)")
            decrypted_key = a32_to_base64(file["key"])
            return f"{self.schema}://{self.domain}/#!{public_handle}!{decrypted_key}"
        else:
            raise ValidationError("File id and key must be present")

    def get_folder_link(self, file_or_node: FileOrFolderTuple | FileOrFolder) -> str:
        file: FileOrFolder = self.__get_file(file_or_node)
        if "h" in file and "k" in file:
            public_handle: str | int = self._api_request({"a": "l", "n": file["h"]})
            if public_handle == -11:
                raise RequestError("Can't get a public link from that file (is this a shared file?)")
            decrypted_key = a32_to_base64(file["decrypted_sk"])
            return f"{self.schema}://{self.domain}/#F!{public_handle}!{decrypted_key}"
        else:
            raise ValidationError("File id and key must be present")

    def get_user(self) -> AnyDict:
        user_data: AnyDict = self._api_request({"a": "ug"})
        return user_data

    def get_node_by_type(self, node_type: NodeType | int) -> FileOrFolderTuple | None:
        """
        Get a node by it's numeric type id, e.g:
        0: file
        1: dir
        2: special: root cloud drive
        3: special: inbox
        4: special trash bin
        """
        nodes = self.get_files()
        for name, node in nodes.items():
            if node["t"] == node_type:
                return name, node

    def get_files_in_node(self, target: NodeType | str) -> FileOrFolderDict:
        """
        Get all files in a given target, e.g. 4=trash
        """
        if isinstance(target, Union[NodeType, int]):
            # convert special nodes (e.g. trash)
            node_id: str = self.get_node_by_type(target)[0]
        else:
            node_id = target

        files: dict[str, list[FileOrFolder]] = self._api_request({"a": "f", "c": 1})
        files_dict: FileOrFolderDict = {}
        shared_keys: SharedkeysDict = {}
        self._init_shared_keys(files, shared_keys)
        for file in files["f"]:
            processed_file = self._process_file(file, shared_keys)
            if processed_file["a"] and processed_file["p"] == node_id:
                files_dict[file["h"]] = processed_file
        return files_dict

    def get_id_from_public_handle(self, public_handle: str) -> str:
        # get node data
        node_data: Folder = self._api_request({"a": "f", "f": 1, "p": public_handle})
        node_id = self.get_id_from_obj(node_data)
        assert node_id
        return node_id

    def get_id_from_obj(self, node_data: Folder) -> str | None:
        """
        Get node id from a file object
        """
        node_id = None

        for i in node_data["f"]:
            if i["h"] != "":
                node_id = i["h"]
        return node_id

    def get_quota(self) -> int:
        """
        Get current remaining disk quota in MegaBytes
        """
        json_resp: AnyDict = self._api_request({"a": "uq", "xfer": 1, "strg": 1, "v": 1})
        # convert bytes to megabytes
        return json_resp["mstrg"] / 1048576

    def get_storage_space(self, giga: bool = False, mega: bool = False, kilo: bool = False) -> StorageUsage:
        """
        Get the current storage space.
        Return a dict containing at least:
          'used' : the used space on the account
          'total' : the maximum space allowed with current plan
        All storage space are in bytes unless asked differently.
        """
        if sum(1 if x else 0 for x in (kilo, mega, giga)) > 1:
            raise ValueError("Only one unit prefix can be specified")
        unit_coef = 1
        if kilo:
            unit_coef = 1024
        if mega:
            unit_coef = 1048576
        if giga:
            unit_coef = 1073741824
        json_resp: AnyDict = self._api_request({"a": "uq", "xfer": 1, "strg": 1})
        return {
            "used": json_resp["cstrg"] / unit_coef,
            "total": json_resp["mstrg"] / unit_coef,
        }

    def get_balance(self) -> int | None:
        """
        Get account monetary balance, Pro accounts only
        """
        user_data: AnyDict = self._api_request({"a": "uq", "pro": 1})
        return user_data.get("balance")

    def delete(self, public_handle: str) -> AnyDict:
        """
        Delete a file by its public handle
        """
        return self.move(public_handle, NodeType.TRASH)

    def delete_url(self, url: str) -> AnyDict:
        """
        Delete a file by its url
        """
        (public_handle,) = self._parse_url(url).split("!")
        file_id = self.get_id_from_public_handle(public_handle)
        return self.move(file_id, NodeType.TRASH)

    def destroy(self, file_id: str) -> AnyDict:
        """
        Destroy a file by its private id
        """
        return self._api_request({"a": "d", "n": file_id, "i": self.request_id})

    def destroy_url(self, url: str) -> AnyDict:
        """
        Destroy a file by its url
        """
        public_handle, *_ = self._parse_url(url).split("!")
        file_id = self.get_id_from_public_handle(public_handle)
        return self.destroy(file_id)

    def empty_trash(self) -> AnyDict | None:
        # get list of files in rubbish out
        files = self.get_files_in_node(NodeType.TRASH)

        # make a list of json
        if files != {}:
            post_list = []
            for file in files:
                post_list.append({"a": "d", "n": file, "i": self.request_id})
            return self._api_request(post_list)

    def download(
        self,
        file_or_node: FileOrFolder | None,
        dest_path: str | None = None,
        dest_filename: str | None = None,
    ) -> Path:
        """
        Download a file by it's file object
        """
        return self._download_file(
            file_handle=None,
            file_key=None,
            file=file_or_node,
            dest_path=dest_path,
            dest_filename=dest_filename,
            is_public=False,
        )

    def _export_file(self, node: FileOrFolderTuple | FileOrFolder) -> str:
        node_data = self.__get_file(node)
        self._api_request([{"a": "l", "n": node_data["h"], "i": self.request_id}])
        return self.get_link(node)

    def export(self, path: Path | str | None = None, node_id: str | None = None) -> str:
        nodes = self.get_files()
        if node_id:
            _node_id = node_id
            node: FileOrFolderTuple | FileOrFolder = nodes[_node_id]
        elif path:
            found = self.find(path)
            if not found:
                raise ValueError
            node = found
        else:
            raise ValueError

        node_data = self.__get_file(node)
        is_file_node: bool = node_data["t"] == 0
        if is_file_node:
            return self._export_file(node)
        if node:
            try:
                # If already exported
                return self.get_folder_link(node)
            except (RequestError, KeyError):
                pass

        master_key_cipher = AES.new(a32_to_bytes(self.master_key), AES.MODE_ECB)
        ha = base64_url_encode(master_key_cipher.encrypt(node_data["h"].encode("utf8") + node_data["h"].encode("utf8")))

        share_key = secrets.token_bytes(16)
        ok = base64_url_encode(master_key_cipher.encrypt(share_key))

        share_key_cipher = AES.new(share_key, AES.MODE_ECB)
        node_key = node_data["decrypted_k"]
        encrypted_node_key = base64_url_encode(share_key_cipher.encrypt(a32_to_bytes(node_key)))

        _node_id: str = node_data["h"]
        request_body = [
            {
                "a": "s2",
                "n": _node_id,
                "s": [{"u": "EXP", "r": 0}],
                "i": self.request_id,
                "ok": ok,
                "ha": ha,
                "cr": [[_node_id], [_node_id], [0, 0, encrypted_node_key]],
            }
        ]
        self._api_request(request_body)
        nodes = self.get_files()
        return self.get_folder_link(nodes[_node_id])

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

    def _download_file(
        self,
        file_handle: str | None = None,
        file_key: str | None = None,
        dest_path: str | None = None,
        dest_filename: str | None = None,
        is_public: bool = False,
        file: FileOrFolder | None = None,
    ) -> Path:
        if file is None:
            assert file_key

            if is_public:
                _file_key = base64_to_a32(file_key)

            file_data: File = self._api_request(
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
            file_data = self._api_request({"a": "g", "g": 1, "n": file["h"]})
            k = file["k"]  # type: ignore # TODO: FIXME
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

        input_file = requests.get(file_url, stream=True).raw

        if dest_path is None:
            dest_path = ""
        else:
            dest_path += "/"

        output_path = Path(dest_path + file_name)

        with self.progress, tempfile.NamedTemporaryFile(mode="w+b", prefix="megapy_", delete=False) as temp_output_file:
            task_id = self.progress.add_task(output_path.name, total=file_size)
            k_bytes = a32_to_bytes(k)
            counter = Counter.new(128, initial_value=((iv[0] << 32) + iv[1]) << 64)
            aes = AES.new(k_bytes, AES.MODE_CTR, counter=counter)

            # mega.nz improperly uses CBC as a MAC mode, so after each chunk, the computed mac_bytes are used as IV for the next chunk MAC accumulation
            mac_bytes = b"\0" * 16
            mac_encryptor = AES.new(k_bytes, AES.MODE_CBC, mac_bytes)
            iv_bytes = a32_to_bytes([iv[0], iv[1], iv[0], iv[1]])

            bytes_written: int = 0
            for _, chunk_size in get_chunks(file_size):
                chunk = input_file.read(chunk_size)
                chunk = aes.decrypt(chunk)
                actual_size = len(chunk)
                bytes_written += actual_size
                temp_output_file.write(chunk)
                self.progress.advance(task_id, actual_size)
                encryptor = AES.new(k_bytes, AES.MODE_CBC, iv_bytes)

                # take last 16-N bytes from chunk (with N between 1 and 16, including extremes)
                mem_view = memoryview(chunk)  # avoid copying memory for the entire chunk when slicing
                modchunk = actual_size % CHUNK_BLOCK_LEN
                if modchunk == 0:
                    # ensure we reserve the last 16 bytes anyway, we have to feed them into mac_encryptor
                    modchunk = CHUNK_BLOCK_LEN

                # pad last block to 16 bytes
                last_block = pad_bytes(mem_view[-modchunk:])
                rest_of_chunk = mem_view[:-modchunk]
                _ = encryptor.encrypt(rest_of_chunk)
                input_to_mac = encryptor.encrypt(last_block)
                mac_bytes = mac_encryptor.encrypt(input_to_mac)
                logger.info("%s of %s downloaded", bytes_written, file_size)

        file_mac = str_to_a32(mac_bytes)
        # check mac integrity
        if (file_mac[0] ^ file_mac[1], file_mac[2] ^ file_mac[3]) != meta_mac:
            raise RuntimeError("Mismatched mac")

        self.progress.remove_task(task_id)
        shutil.move(temp_output_file.name, output_path)
        return output_path

    def upload(self, filename: str, dest: str | None = None, dest_filename: str | None = None) -> Folder:
        # determine storage node
        if dest is None:
            # if none set, upload to cloud drive node
            if not hasattr(self, "root_id"):
                self.get_files()
            dest = self.root_id

        # request upload url, call 'u' method
        with open(filename, "rb") as input_file:
            file_size = os.path.getsize(filename)
            ul_url: str = self._api_request({"a": "u", "s": file_size})["p"]

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
                    output_file = requests.post(ul_url + "/" + str(chunk_start), data=chunk, timeout=self.timeout)
                    completion_file_handle = output_file.text
                    logger.info("%s of %s uploaded", upload_progress, file_size)
            else:
                # empty file
                output_file = requests.post(ul_url + "/0", data="", timeout=self.timeout)
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
            data: Folder = self._api_request(
                {
                    "a": "p",
                    "t": dest,
                    "i": self.request_id,
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
        data: AnyDict = self._api_request(
            {
                "a": "p",
                "t": parent_node_id,
                "n": [{"h": "xxxxxxxx", "t": 1, "a": encrypt_attribs, "k": encrypted_key}],
                "i": self.request_id,
            }
        )
        return data

    def _root_node_id(self) -> str:
        if not hasattr(self, "root_id"):
            _ = self.get_files()
        return self.root_id

    def create_folder(self, name: Path | str, dest: str | None = None) -> AnyDict:
        dirs = tuple(dir_name for dir_name in str(name).split("/") if dir_name)
        folder_node_ids = {}
        for idx, directory_name in enumerate(dirs):
            existing_node_id = self.find_path_descriptor(directory_name)
            if existing_node_id:
                folder_node_ids[idx] = existing_node_id
                continue
            if idx == 0:
                if dest is None:
                    parent_node_id = self._root_node_id()
                else:
                    parent_node_id = dest
            else:
                parent_node_id = folder_node_ids[idx - 1]
            created_node = self._mkdir(name=directory_name, parent_node_id=parent_node_id)
            node_id = created_node["f"][0]["h"]
            folder_node_ids[idx] = node_id
        return dict(zip(dirs, list(folder_node_ids.values()), strict=False))  # type: ignore

    def rename(self, file: FileOrFolderTuple | FileOrFolder, new_name: str) -> AnyDict:
        file = self.__get_file(file)
        # create new attribs
        attribs = {"n": new_name}
        # encrypt attribs
        encrypt_attribs = base64_url_encode(encrypt_attr(attribs, file["decrypted_k"]))
        encrypted_key = a32_to_base64(encrypt_key(file["key"], self.master_key))
        # update attributes
        return self._api_request(
            [{"a": "a", "attr": encrypt_attribs, "key": encrypted_key, "n": file["h"], "i": self.request_id}]
        )

    def move(self, file_id: str, target: FileOrFolderTuple | NodeType | str) -> AnyDict:
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

        # determine target_node_id
        if isinstance(target, Union[NodeType, int]):
            target_node_id = str(self.get_node_by_type(target)[0])
        elif isinstance(target, str):
            target_node_id = target
        else:
            file = target[1]
            target_node_id = file["h"]
        return self._api_request({"a": "m", "n": file_id, "t": target_node_id, "i": self.request_id})

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
            return self._api_request({"a": "ur", "u": email, "l": add_or_remove, "i": self.request_id})

    def get_public_url_info(self, url):
        """
        Get size and name from a public url, dict returned
        """
        file_handle, file_key = self._parse_url(url).split("!")
        return self.get_public_file_info(file_handle, file_key)

    def import_public_url(
        self, url: str, dest_node: FileOrFolder | None = None, dest_name: str | None = None
    ) -> AnyDict:
        """
        Import the public url into user account
        """
        file_handle, file_key = self._parse_url(url).split("!")
        return self.import_public_file(file_handle, file_key, dest_node=dest_node, dest_name=dest_name)

    def get_public_file_info(self, file_handle: str, file_key: str) -> AnyDict | None:
        """
        Get size and name of a public file
        """
        data: Folder | int = self._api_request({"a": "g", "p": file_handle, "ssm": 1})
        if isinstance(data, int):
            raise RequestError(data)

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
        file_handle: str | None,
        file_key: str,
        dest_node: FileOrFolder | None = None,
        dest_name: str | None = None,
    ):
        """
        Import the public file into user account
        """
        # Providing dest_node spare an API call to retrieve it.
        if dest_node is None:
            # Get '/Cloud Drive' folder no dest node specified
            dest_node = self.get_node_by_type(NodeType.ROOT_FOLDER)[1]

        # Providing dest_name spares an API call to retrieve it.
        if dest_name is None:
            assert file_handle
            pl_info = self.get_public_file_info(file_handle, file_key)
            assert pl_info
            dest_name = pl_info["name"]

        key = base64_to_a32(file_key)
        k: TupleArray = (key[0] ^ key[4], key[1] ^ key[5], key[2] ^ key[6], key[3] ^ key[7])

        encrypted_key: str = a32_to_base64(encrypt_key(key, self.master_key))
        encrypted_name: str = base64_url_encode(encrypt_attr({"n": dest_name}, k))
        return self._api_request(
            {"a": "p", "t": dest_node["h"], "n": [{"ph": file_handle, "t": 0, "a": encrypted_name, "k": encrypted_key}]}
        )
