from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import aiohttp
import pytest

from mega import env
from mega.api import MegaAPI
from mega.client import MegaNzClient
from mega.data_structures import AccountBalance, AccountStats, Node, NodeType, StorageQuota
from mega.errors import RequestError, RetryRequestError
from mega.filesystem import UserFileSystem
from mega.utils import setup_logger, str_utc_now

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator


TEST_CONTACT = "test@mega.nz"
TEST_PUBLIC_URL = "https://mega.nz/#!hYVmXKqL!r0d0-WRnFwulR_shhuEDwrY1Vo103-am1MyUy8oV6Ps"
TEST_FILE = Path(__file__)
MODULE = "mega.mega"

setup_logger()


@pytest.fixture
async def http_client() -> aiohttp.ClientSession:
    return aiohttp.ClientSession(loop=asyncio.get_running_loop())


@pytest.fixture()
def folder_name() -> str:
    return f"mega.py_testfolder_{str_utc_now()}"


@pytest.fixture(name="mega")
async def connect_to_mega(folder_name: str, http_client: aiohttp.ClientSession) -> AsyncGenerator[MegaNzClient]:
    async with MegaNzClient(http_client) as mega:
        await mega.login(email=env.EMAIL, password=env.PASSWORD)
        folder = await mega.create_folder(folder_name)
        yield mega
        deleted = await mega.delete(folder.id)
        assert deleted


@pytest.fixture
async def folder(mega: MegaNzClient, folder_name: str) -> AsyncGenerator[Node]:
    node = await mega.find(folder_name)
    assert node
    assert node.type is NodeType.FOLDER
    yield node


@pytest.fixture
async def uploaded_file(mega: MegaNzClient, folder_name: str, folder: Node) -> AsyncGenerator[Node]:
    await mega.upload(TEST_FILE, folder.id)
    path = f"{folder_name}/{TEST_FILE.name}"
    node = await mega.find(path)
    assert node
    yield node


def test_mega(mega: MegaNzClient) -> None:
    assert isinstance(mega, MegaNzClient)


async def test_filesystem_is_available_after_login(mega: MegaNzClient) -> None:
    assert mega.logged_in
    fs = await mega.get_filesystem()
    assert fs
    assert all((fs.root, fs.inbox, fs.trash_bin))


async def test_get_user(mega: MegaNzClient) -> None:
    resp = await mega.get_user()

    assert isinstance(resp, dict)
    assert "k" in resp
    assert isinstance(resp["since"], int)
    if env.EMAIL and env.PASSWORD:
        assert "email" in resp
        assert "name" in resp


async def test_account_stats(mega: MegaNzClient) -> None:
    resp = await mega.get_account_stats()
    assert isinstance(resp, AccountStats)
    assert isinstance(resp.balance, AccountBalance)
    assert isinstance(resp.storage, StorageQuota)


async def test_get_filesystem(mega: MegaNzClient) -> None:
    fs = await mega.get_filesystem()
    assert isinstance(fs, UserFileSystem)
    assert fs.root
    assert fs.inbox
    assert fs.trash_bin


@pytest.mark.skipif(not (env.EMAIL and env.PASSWORD), reason="Public links won't work with temp account")
async def test_get_link(mega: MegaNzClient, uploaded_file: Node) -> None:
    link = await mega.get_public_link(uploaded_file)
    assert isinstance(link, str)


@pytest.mark.skip(reason="Needs update to get node from folder_name")
@pytest.mark.skipif(not (env.EMAIL and env.PASSWORD), reason="Temp accounts can't export anything")
class TestExport:
    async def test_export_folder(self, mega: MegaNzClient, folder: Node) -> None:
        public_url = await mega.export(folder)
        assert isinstance(public_url, str)
        assert public_url.startswith("https://mega.nz/#F!")

    async def test_exporting_the_same_folder_twice_should_get_the_same_link(
        self, mega: MegaNzClient, folder: Node
    ) -> None:
        first = await mega.export(folder)
        second = await mega.export(folder)
        assert first == second

    async def test_export_folder_within_folder(self, mega: MegaNzClient, folder_name: str) -> None:
        folder_path = Path(folder_name) / "subdir" / "anothersubdir"
        node = await mega.create_folder(folder_path)
        url = await mega.export(node)
        assert url.startswith("https://mega.nz/#F!")

    async def test_export_folder_using_node_id(self, mega: MegaNzClient, folder_name: str) -> None:
        file = await mega.find(folder_name)
        assert file
        url = await mega.export(file)
        assert isinstance(url, str)
        assert url.startswith("https://mega.nz/#F!")

    async def test_export_single_file(self, mega: MegaNzClient, folder_name: str, folder: Node) -> None:
        # Upload a single file into a folder

        await mega.upload(TEST_FILE, folder.id)
        path = f"{folder_name}/{TEST_FILE.name}"
        assert await mega.find(path)

        for _ in range(2):
            result_public_share_url = await mega.export(folder)

            assert result_public_share_url.startswith("https://mega.nz/#!")


async def test_import_public_url(mega: MegaNzClient) -> None:
    public_handle, public_key = mega.parse_file_url(TEST_PUBLIC_URL)
    file = await mega.import_public_file(public_handle, public_key)
    resp = await mega.destroy(file.id)
    assert resp


async def test_create_single_folder(mega: MegaNzClient, folder_name: str) -> None:
    folder = await mega.create_folder(folder_name)
    assert isinstance(folder, Node)
    assert folder.type is NodeType.FOLDER


@pytest.mark.xfail(reason="Only one folder is created wiht the / included")
async def test_create_folder_with_sub_folders(mega: MegaNzClient, folder_name: str) -> None:
    full_path = Path(folder_name + "_w_subfolders") / "subdir" / "anothersubdir"
    _ = await mega.create_folder(full_path)

    for path in full_path.parents:
        assert await mega.find(path)


class TestFind:
    async def test_find_file(self, mega: MegaNzClient, folder_name: str, folder: Node) -> None:
        _ = await mega.upload(TEST_FILE, folder.id)
        path1 = f"{folder_name}/{TEST_FILE.name}"
        file1 = await mega.find(path1)

        new_folder = await mega.create_folder("new_folder")
        _ = await mega.upload(TEST_FILE, new_folder.id)

        path2 = f"new_folder/{TEST_FILE.name}"
        file2 = await mega.find(path2)
        assert file1.id != file2.id
        fs = await mega.get_filesystem()
        assert fs.resolve(file1.id) != fs.resolve(file2.id)
        assert str(fs.relative_path(file1.id)) == path1
        assert str(fs.relative_path(file2.id)) == path2
        assert str(fs.resolve(file1.id)) == "/" + path1
        assert str(fs.resolve(file2.id)) == "/" + path2

    async def test_path_not_found_raise_file_not_found_error(self, mega: MegaNzClient) -> None:
        with pytest.raises(FileNotFoundError):
            await mega.find(str(uuid.uuid4()))

    async def test_exclude_deleted_files(self, mega: MegaNzClient, folder_name: str, folder: Node) -> None:
        assert await mega.find(folder_name)
        _ = await mega.delete(folder.id)
        assert await mega.search(folder_name, exclude_deleted=False)
        assert not await mega.search(folder_name, exclude_deleted=True)


async def test_rename(mega: MegaNzClient, folder_name: str, folder: Node) -> None:
    assert await mega.rename(folder, folder_name + "_RENAMED")


async def test_delete_folder(mega: MegaNzClient, folder: Node) -> None:
    resp = await mega.delete(folder.id)
    assert isinstance(resp, int)


async def test_delete(mega: MegaNzClient, uploaded_file: Node) -> None:
    resp = await mega.delete(uploaded_file.id)
    assert isinstance(resp, int)


async def test_destroy(mega: MegaNzClient, uploaded_file: Node) -> None:
    resp = await mega.destroy(uploaded_file.id)
    assert isinstance(resp, int)


async def test_upload_and_download(mega: MegaNzClient, tmp_path: Path, folder_name: str, folder: Node) -> None:
    node = await mega.upload(TEST_FILE, folder.id)
    path = f"/{folder_name}/{TEST_FILE.name}"
    fs = await mega.get_filesystem()
    assert fs.find(path)
    assert str(fs.resolve(node.id)) == path
    output_path = await mega.download(node, tmp_path)
    assert output_path.parent == tmp_path
    assert output_path.is_file()
    assert output_path.read_text() == TEST_FILE.read_text()


async def test_empty_trash(mega: MegaNzClient) -> None:
    # resp None if already empty, else int
    resp = await mega.empty_trash()
    if resp is not None:
        assert isinstance(resp, int)


async def test_add_contact(mega: MegaNzClient) -> None:
    resp = await mega.add_contact(TEST_CONTACT)
    assert isinstance(resp, int)


async def test_remove_contact(mega: MegaNzClient) -> None:
    resp = await mega.remove_contact(TEST_CONTACT)
    assert isinstance(resp, int)


@pytest.mark.parametrize(
    "url, expected_file_id_and_key",
    [
        (
            "https://mega.nz/#!Ue5VRSIQ!kC2E4a4JwfWWCWYNJovGFHlbz8FN-ISsBAGPzvTjT6k",
            ("Ue5VRSIQ", "kC2E4a4JwfWWCWYNJovGFHlbz8FN-ISsBAGPzvTjT6k"),
        ),
        (
            "https://mega.nz/file/cH51DYDR#qH7QOfRcM-7N9riZWdSjsRq5VDTLfIhThx1capgVA30",
            ("cH51DYDR", "qH7QOfRcM-7N9riZWdSjsRq5VDTLfIhThx1capgVA30"),
        ),
    ],
)
def test_parse_url(url: str, expected_file_id_and_key: str) -> None:
    assert MegaNzClient.parse_file_url(url) == expected_file_id_and_key


class TestAPIRequest:
    @staticmethod
    def _fake_resp(value: Any) -> aiohttp.ClientResponse:
        fake_resp = AsyncMock()
        fake_resp.status = 200
        fake_resp.headers = {"content-type": "application/json"}
        fake_resp.json = AsyncMock(return_value=value)
        return fake_resp

    @pytest.mark.parametrize("value", [-4, -9, [-2], [-400]])
    async def test_when_api_returns_int_raises_exception(self, value: Any) -> None:
        with pytest.raises(RequestError):
            await MegaAPI._process_resp(self._fake_resp(value))

    @pytest.mark.parametrize("value", [-3, [-3]])
    async def test_when_api_returns_negative_3_raise_retry_error(self, value: Any) -> None:
        with pytest.raises(RetryRequestError):
            await MegaAPI._process_resp(self._fake_resp(value))

    @pytest.mark.parametrize(
        "value, expected",
        [
            ({"a": "b"}, {"a": "b"}),
            (["a", "b"], ["a", "b"]),
            (["a"], "a"),
        ],
    )
    async def test_when_api_returns_dict_or_list_the_response_is_valid(self, value: Any, expected: Any) -> None:
        resp = await MegaAPI._process_resp(self._fake_resp(value))
        assert resp == expected
