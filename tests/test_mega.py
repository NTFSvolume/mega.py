from __future__ import annotations

import asyncio
import os
import random
from pathlib import Path
from typing import TYPE_CHECKING, Literal, cast
from unittest.mock import AsyncMock

import aiohttp
import pytest

from mega.client import Mega
from mega.data_structures import NodeType, StorageQuota
from mega.errors import RequestError

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from mega.data_structures import FolderSerialized, NodeSerialized

TEST_CONTACT = "test@mega.nz"
TEST_PUBLIC_URL = "https://mega.nz/#!hYVmXKqL!r0d0-WRnFwulR_shhuEDwrY1Vo103-am1MyUy8oV6Ps"
TEST_FILE = os.path.basename(__file__)
MODULE = "mega.mega"


@pytest.fixture
async def http_client() -> aiohttp.ClientSession:
    return aiohttp.ClientSession(loop=asyncio.get_running_loop())


@pytest.fixture
def folder_name():
    return f"mega.py_testfolder_{random.random()}"


@pytest.fixture
async def mega(folder_name: str, http_client: aiohttp.ClientSession) -> AsyncGenerator[Mega]:
    mega_ = Mega(session=http_client)
    await mega_.login(email=os.getenv("EMAIL"), password=os.getenv("PASS"))
    folder = await mega_.create_folder(folder_name)
    yield mega_
    await mega_.destroy(folder["h"])
    await mega_.close()


@pytest.fixture
async def folder(mega: Mega, folder_name: str) -> AsyncGenerator[FolderSerialized]:
    node = await mega.find(folder_name)
    assert node
    assert node["t"] == NodeType.FOLDER
    folder = cast("FolderSerialized", node)
    yield folder


@pytest.fixture
async def uploaded_file(mega: Mega, folder_name: str, folder: FolderSerialized) -> AsyncGenerator[NodeSerialized]:
    await mega.upload(__file__, dest_node=folder, dest_filename="test.py")
    path = f"{folder_name}/test.py"
    node = await mega.find(path)
    yield node


def test_mega(mega: Mega) -> None:
    assert isinstance(mega, Mega)


def test_login(mega: Mega) -> None:
    assert mega.logged_in
    assert all((mega.root_id, mega.inbox_id, mega.trashbin_id))


async def test_get_user(mega: Mega) -> None:
    resp = await mega.get_user()
    assert isinstance(resp, dict)


async def test_get_quota(mega: Mega) -> None:
    resp = await mega.get_transfer_quota()
    assert isinstance(resp, int)


async def test_get_storage_space(mega: Mega) -> None:
    resp = await mega.get_storage_space()
    assert isinstance(resp, StorageQuota)


async def test_get_files(mega: Mega) -> None:
    files = await mega.get_nodes()
    assert isinstance(files, dict)


@pytest.mark.xfail(reason="Public links won't work with temp account")
async def test_get_link(mega: Mega, uploaded_file: NodeSerialized) -> None:
    link = await mega.get_public_link(uploaded_file)
    assert isinstance(link, str)


@pytest.mark.skip
class TestExport:
    async def test_export_folder(self, mega: Mega, folder_name: str) -> None:
        public_url = None
        for _ in range(2):
            result_public_share_url = await mega.export(folder_name)

            if not public_url:
                public_url = result_public_share_url
            assert result_public_share_url.startswith("https://mega.nz/#F!")
            assert result_public_share_url == public_url

    async def test_export_folder_within_folder(self, mega: Mega, folder_name: str) -> None:
        folder_path = Path(folder_name) / "subdir" / "anothersubdir"
        await mega.create_folder(folder_path)
        result_public_share_url = await mega.export(path=folder_path)
        assert result_public_share_url.startswith("https://mega.nz/#F!")

    async def test_export_folder_using_node_id(self, mega: Mega, folder_name: str) -> None:
        file = await mega.find(folder_name)
        assert file
        node_id = file["p"]
        result_public_share_url = await mega.export(node_id=node_id)
        assert result_public_share_url.startswith("https://mega.nz/#F!")

    async def test_export_single_file(self, mega: Mega, folder_name: str, folder: FolderSerialized) -> None:
        # Upload a single file into a folder

        await mega.upload(__file__, dest_node=folder, dest_filename="test.py")
        path = f"{folder_name}/test.py"
        assert await mega.find(path)

        for _ in range(2):
            result_public_share_url = await mega.export(path)

            assert result_public_share_url.startswith("https://mega.nz/#!")


async def test_import_public_url(mega: Mega) -> None:
    resp = await mega.import_public_url(TEST_PUBLIC_URL)
    file_id = mega.get_id_from_resp_obj(resp)
    assert file_id
    resp = await mega.destroy(file_id)
    assert isinstance(resp, int)


async def test_create_single_folder(mega: Mega, folder_name: str) -> None:
    folder = await mega.create_folder(folder_name)
    assert isinstance(folder, dict)
    assert folder["h"]
    assert folder["t"] == NodeType.FOLDER


async def test_create_folder_with_sub_folders(mega: Mega, folder_name: str) -> None:
    full_path = Path(folder_name) / "subdir" / "anothersubdir"
    _ = await mega.create_folder(full_path)

    for path in full_path.parents:
        assert await mega.find(path)


class TestFind:
    async def test_find_file(self, mega: Mega, folder_name: str, folder: FolderSerialized) -> None:
        _ = await mega.upload(__file__, dest_node=folder, dest_filename="test.py")
        file1 = await mega.find(f"{folder_name}/test.py")
        assert file1

        new_folder = await mega.create_folder("new_folder")
        _ = await mega.upload(__file__, dest_node=new_folder, dest_filename="test.py")

        file2 = await mega.find("new_folder/test.py")
        assert file2
        # Check that the correct test.py was found
        assert file1 != file2

    async def test_path_not_found_returns_none(self, mega: Mega) -> None:
        result = await mega.find("not_found")
        assert result is None

    async def test_exclude_deleted_files(self, mega: Mega, folder_name: str, folder: FolderSerialized) -> None:
        assert await mega.find(folder_name)
        _ = await mega.delete(folder["h"])
        assert await mega.search(folder_name)
        assert not await mega.search(folder_name, exclude_deleted=True)


async def test_rename(mega: Mega, folder_name: str, folder: FolderSerialized) -> None:
    resp = await mega.rename(folder, folder_name)
    assert resp == 0


async def test_delete_folder(mega: Mega, folder: FolderSerialized) -> None:
    resp = await mega.delete(folder["h"])
    assert isinstance(resp, int)


async def test_delete(mega: Mega, uploaded_file: NodeSerialized | FolderSerialized) -> None:
    resp = await mega.delete(uploaded_file["h"])
    assert isinstance(resp, int)


async def test_destroy(mega: Mega, uploaded_file: NodeSerialized | FolderSerialized) -> None:
    resp = await mega.destroy(uploaded_file["h"])
    assert isinstance(resp, int)


async def test_download(mega: Mega, tmp_path: Path, folder_name: str, folder: FolderSerialized) -> None:
    # Upload a single file into a folder
    _ = await mega.upload(__file__, dest_node=folder, dest_filename="test.py")
    path = f"{folder_name}/test.py"
    file = await mega.find(path)
    assert file
    output_path = await mega.download(file, tmp_path, "test.py")
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
            "Ue5VRSIQ!kC2E4a4JwfWWCWYNJovGFHlbz8FN-ISsBAGPzvTjT6k",
        ),
        (
            "https://mega.nz/file/cH51DYDR#qH7QOfRcM-7N9riZWdSjsRq5VDTLfIhThx1capgVA30",
            "cH51DYDR!qH7QOfRcM-7N9riZWdSjsRq5VDTLfIhThx1capgVA30",
        ),
    ],
)
def test_parse_url(url: str, expected_file_id_and_key: str) -> None:
    assert Mega._parse_url(url) == expected_file_id_and_key


class TestAPIRequest:
    @pytest.mark.parametrize("response", [-4, -9])
    async def test_when_api_returns_int_raises_exception(
        self,
        mega: Mega,
        response: Literal[-4, -9],
    ):
        with pytest.MonkeyPatch.context() as m:
            m.setattr(aiohttp.ClientResponse, "json", AsyncMock(return_value=response))
            with pytest.raises(RequestError):
                await mega._api.request(data={})
