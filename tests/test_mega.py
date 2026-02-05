from __future__ import annotations

import asyncio
import datetime
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any, get_origin, get_type_hints
from unittest.mock import AsyncMock

import aiohttp
import pytest

from mega import env
from mega.api import MegaAPI
from mega.client import Mega
from mega.data_structures import AccountBalance, AccountStats, Node, NodeType, StorageQuota, UserResponse
from mega.errors import RequestError, RetryRequestError
from mega.filesystem import UserFileSystem
from mega.utils import setup_logger

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
    now = datetime.datetime.now().astimezone(datetime.UTC).replace(tzinfo=None).strftime("%Y%m%d_%H%M%S_%f")
    return f"mega.py_testfolder_{now}"


@pytest.fixture(name="mega")
async def connect_to_mega(folder_name: str, http_client: aiohttp.ClientSession) -> AsyncGenerator[Mega]:
    async with Mega(http_client) as mega:
        await mega.login(email=env.EMAIL, password=env.PASSWORD)
        folder = await mega.create_folder(folder_name)
        yield mega
        deleted = await mega.delete(folder.id)
        assert deleted


@pytest.fixture
async def folder(mega: Mega, folder_name: str) -> AsyncGenerator[Node]:
    node = await mega.find(folder_name)
    assert node
    assert node.type is NodeType.FOLDER
    yield node


@pytest.fixture
async def uploaded_file(mega: Mega, folder_name: str, folder: Node) -> AsyncGenerator[Node]:
    await mega.upload(TEST_FILE, dest_node=folder)
    path = f"{folder_name}/{TEST_FILE}"
    node = await mega.find(path)
    assert node
    yield node


def test_mega(mega: Mega) -> None:
    assert isinstance(mega, Mega)


async def test_filesystem_is_available_after_login(mega: Mega) -> None:
    assert mega.logged_in
    fs = mega._filesystem
    assert fs
    assert all((fs.root, fs.inbox, fs.trash_bin))


async def test_get_user(mega: Mega) -> None:
    resp = await mega.get_user()

    assert isinstance(resp, dict)
    for name, type_ in get_type_hints(UserResponse).items():
        assert name in resp
        if get_origin(type_) is None:
            assert isinstance(resp[name], type_)


async def test_account_stats(mega: Mega) -> None:
    resp = await mega.get_account_stats()
    assert isinstance(resp, AccountStats)
    assert isinstance(resp.balance, AccountBalance)
    assert isinstance(resp.storage, StorageQuota)


async def test_get_filesystem(mega: Mega, folder_name: str) -> None:
    fs = await mega.get_filesystem()
    assert isinstance(fs, UserFileSystem)
    assert fs.root
    assert fs.inbox
    assert fs.trash_bin


@pytest.mark.skipif(not (env.EMAIL and env.PASSWORD), reason="Public links won't work with temp account")
async def test_get_link(mega: Mega, uploaded_file: Node) -> None:
    link = await mega.get_public_link(uploaded_file)
    assert isinstance(link, str)


@pytest.mark.skip(reason="Needs update to get node from folder_name")
@pytest.mark.skipif(not (env.EMAIL and env.PASSWORD), reason="Temp accounts can't export anything")
class TestExport:
    async def test_export_folder(self, mega: Mega, folder_name: str) -> None:
        public_url = await mega.export(folder_name)
        assert isinstance(public_url, str)
        assert public_url.startswith("https://mega.nz/#F!")

    async def test_exporting_the_same_folder_twice_should_get_the_same_link(self, mega: Mega, folder_name: str) -> None:
        first = await mega.export(folder_name)
        second = await mega.export(folder_name)
        assert first == second

    async def test_export_folder_within_folder(self, mega: Mega, folder_name: str) -> None:
        folder_path = Path(folder_name) / "subdir" / "anothersubdir"
        node = await mega.create_folder(folder_path)
        url = await mega.export(node)
        assert url.startswith("https://mega.nz/#F!")

    async def test_export_folder_using_node_id(self, mega: Mega, folder_name: str) -> None:
        file = await mega.find(folder_name)
        assert file
        url = await mega.export(file)
        assert isinstance(url, str)
        assert url.startswith("https://mega.nz/#F!")

    async def test_export_single_file(self, mega: Mega, folder_name: str, folder: Node) -> None:
        # Upload a single file into a folder

        await mega.upload(__file__, dest_node=folder)
        path = f"{folder_name}/test.py"
        assert await mega.find(path)

        for _ in range(2):
            result_public_share_url = await mega.export(path)

            assert result_public_share_url.startswith("https://mega.nz/#!")


async def test_import_public_url(mega: Mega) -> None:
    public_handle, public_key = mega.parse_file_url(TEST_PUBLIC_URL)
    file = await mega.import_public_file(public_handle, public_key)
    resp = await mega.destroy(file.id)
    assert resp


async def test_create_single_folder(mega: Mega, folder_name: str) -> None:
    folder = await mega.create_folder(folder_name)
    assert isinstance(folder, Node)
    assert folder.type is NodeType.FOLDER


async def test_create_folder_with_sub_folders(mega: Mega, folder_name: str) -> None:
    full_path = Path(folder_name) / "subdir" / "anothersubdir"
    _ = await mega.create_folder(full_path)

    for path in full_path.parents:
        assert await mega.find(path)


class TestFind:
    async def test_find_file(self, mega: Mega, folder_name: str, folder: Node) -> None:
        _ = await mega.upload(__file__, dest_node=folder)
        file1 = await mega.find(f"{folder_name}/test.py")
        assert file1

        new_folder = await mega.create_folder("new_folder")
        _ = await mega.upload(__file__, dest_node=new_folder)

        file2 = await mega.find("new_folder/test.py")
        assert file2
        # Check that the correct test.py was found
        assert file1 != file2

    async def test_path_not_found_returns_none(self, mega: Mega) -> None:
        result = await mega.find(str(uuid.uuid4()))
        assert result is None

    async def test_exclude_deleted_files(self, mega: Mega, folder_name: str, folder: Node) -> None:
        assert await mega.find(folder_name)
        _ = await mega.delete(folder.id)
        assert await mega.search(folder_name, exclude_deleted=False)
        assert not await mega.search(folder_name, exclude_deleted=True)


async def test_rename(mega: Mega, folder_name: str, folder: Node) -> None:
    assert await mega.rename(folder, folder_name + "_RENAMED")


async def test_delete_folder(mega: Mega, folder: Node) -> None:
    resp = await mega.delete(folder.id)
    assert isinstance(resp, int)


async def test_delete(mega: Mega, uploaded_file: Node) -> None:
    resp = await mega.delete(uploaded_file.id)
    assert isinstance(resp, int)


async def test_destroy(mega: Mega, uploaded_file: Node) -> None:
    resp = await mega.destroy(uploaded_file.id)
    assert isinstance(resp, int)


async def test_download(mega: Mega, tmp_path: Path, folder_name: str, folder: Node) -> None:
    # Upload a single file into a folder
    _ = await mega.upload(
        TEST_FILE,
        dest_node=folder,
    )
    path = f"{folder_name}/test.py"
    file = await mega.find(path)
    assert file
    output_path = await mega.download(file, tmp_path)
    assert output_path.parent == tmp_path
    assert output_path.is_file()


async def test_empty_trash(mega: Mega) -> None:
    # resp None if already empty, else int
    resp = await mega.empty_trash()
    if resp is not None:
        assert isinstance(resp, int)


async def test_add_contact(mega: Mega) -> None:
    resp = await mega.add_contact(TEST_CONTACT)
    assert isinstance(resp, int)


async def test_remove_contact(mega: Mega) -> None:
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
    assert Mega.parse_file_url(url) == expected_file_id_and_key


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
