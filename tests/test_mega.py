import os
import random
from collections.abc import AsyncGenerator
from pathlib import Path

import pytest
import requests_mock

from mega.client import Mega
from mega.data_structures import FileOrFolder

TEST_CONTACT = "test@mega.nz"
TEST_PUBLIC_URL = "https://mega.nz/#!hYVmXKqL!r0d0-WRnFwulR_shhuEDwrY1Vo103-am1MyUy8oV6Ps"
TEST_FILE = os.path.basename(__file__)
MODULE = "mega.mega"


@pytest.fixture
def folder_name():
    return f"mega.py_testfolder_{random.random()}"


@pytest.fixture
async def mega(folder_name: str) -> AsyncGenerator[Mega]:
    mega_ = Mega()
    await mega_.login(email=os.getenv("EMAIL"), password=os.getenv("PASS"))
    folder = await mega_.create_folder(folder_name)
    yield mega_
    node_id = folder["h"]
    await mega_.destroy(node_id)


@pytest.fixture
async def uploaded_file(mega: Mega, folder_name: str):
    folder = await mega.find(folder_name)
    assert folder
    dest_node_id = folder["h"]
    await mega.upload(__file__, dest_node=dest_node_id, dest_filename="test.py")
    path = f"{folder_name}/test.py"
    return await mega.find(path)


def test_mega(mega: Mega):
    assert isinstance(mega, Mega)


def test_login(mega: Mega):
    assert mega.logged_in


async def test_get_user(mega: Mega):
    resp = await mega.get_user()
    assert isinstance(resp, dict)


async def test_get_quota(mega: Mega):
    resp = await mega.get_quota()
    assert isinstance(int(resp), int)


async def test_get_storage_space(mega: Mega):
    resp = await mega.get_storage_space()
    assert isinstance(resp, dict)


async def test_get_files(mega: Mega):
    files = await mega.get_files()
    assert isinstance(files, dict)


async def test_get_link(mega: Mega, uploaded_file: FileOrFolder):
    link = await mega.get_link(uploaded_file)
    assert isinstance(link, str)


@pytest.mark.skip
class TestExport:
    async def test_export_folder(self, mega: Mega, folder_name: str):
        public_url = None
        for _ in range(2):
            result_public_share_url = await mega.export(folder_name)

            if not public_url:
                public_url = result_public_share_url
            assert result_public_share_url.startswith("https://mega.nz/#F!")
            assert result_public_share_url == public_url

    async def test_export_folder_within_folder(self, mega: Mega, folder_name: str):
        folder_path = Path(folder_name) / "subdir" / "anothersubdir"
        await mega.create_folder(folder_path)
        result_public_share_url = await mega.export(path=folder_path)
        assert result_public_share_url.startswith("https://mega.nz/#F!")

    async def test_export_folder_using_node_id(self, mega: Mega, folder_name: str):
        file = await mega.find(folder_name)
        assert file
        node_id = file["p"]
        result_public_share_url = await mega.export(node_id=node_id)
        assert result_public_share_url.startswith("https://mega.nz/#F!")

    async def test_export_single_file(self, mega: Mega, folder_name: str):
        # Upload a single file into a folder
        node = await mega.find(folder_name)
        assert node
        folder = node
        dest_node_id = folder["h"]
        await mega.upload(__file__, dest_node=dest_node_id, dest_filename="test.py")
        path = f"{folder_name}/test.py"
        assert await mega.find(path)

        for _ in range(2):
            result_public_share_url = await mega.export(path)

            assert result_public_share_url.startswith("https://mega.nz/#!")


async def test_import_public_url(mega: Mega):
    resp = await mega.import_public_url(TEST_PUBLIC_URL)
    file_handle = mega.get_id_from_obj(resp)
    assert file_handle
    resp = await mega.destroy(file_handle)
    assert isinstance(resp, int)


class TestCreateFolder:
    async def test_create_folder(self, mega: Mega, folder_name: str):
        folder_names_and_node_ids = await mega.create_folder(folder_name)

        assert isinstance(folder_names_and_node_ids, dict)
        assert len(folder_names_and_node_ids) == 1

    async def test_create_folder_with_sub_folders(self, mega: Mega, folder_name: str, mocker):
        folder_names_and_node_ids = await mega.create_folder(Path(folder_name) / "subdir" / "anothersubdir")

        assert len(folder_names_and_node_ids) == 3
        assert folder_names_and_node_ids == {
            folder_name: mocker.ANY,
            "subdir": mocker.ANY,
            "anothersubdir": mocker.ANY,
        }


class TestFind:
    async def test_find_file(self, mega: Mega, folder_name: str):
        folder = await mega.find(folder_name)
        assert folder
        dest_node_id = folder["h"]
        _ = await mega.upload(__file__, dest_node=dest_node_id, dest_filename="test.py")
        file1 = await mega.find(f"{folder_name}/test.py")
        assert file1

        dest_node_id2 = await mega.create_folder("new_folder")["new_folder"]
        _ = mega.upload(__file__, dest_node=dest_node_id2, dest_filename="test.py")

        file2 = await mega.find("new_folder/test.py")
        assert file2
        # Check that the correct test.py was found
        assert file1 != file2

    async def test_path_not_found_returns_none(self, mega: Mega):
        result = await mega.find("not_found")
        assert result is None

    async def test_exclude_deleted_files(self, mega: Mega, folder_name: str):
        node = await mega.find(folder_name)
        assert node
        folder_node_id = node["h"]
        assert await mega.find(folder_name)
        _ = await mega.delete(folder_node_id)
        assert await mega.find(folder_name)
        assert not await mega.find(folder_name, exclude_deleted=True)


async def test_rename(mega: Mega, folder_name: str):
    file = await mega.find(folder_name)
    assert file
    resp = await mega.rename(file, folder_name)
    assert isinstance(resp, int)


async def test_delete_folder(mega: Mega, folder_name: str):
    node = await mega.find(folder_name)
    assert node
    folder_node_id = node["h"]
    resp = await mega.delete(folder_node_id)
    assert isinstance(resp, int)


async def test_delete(mega: Mega, uploaded_file: FileOrFolder):
    resp = await mega.delete(uploaded_file["h"])
    assert isinstance(resp, int)


async def test_destroy(mega: Mega, uploaded_file: FileOrFolder):
    resp = await mega.destroy(uploaded_file["h"])
    assert isinstance(resp, int)


async def test_download(mega: Mega, tmpdir, folder_name):
    # Upload a single file into a folder
    node = await mega.find(folder_name)
    assert node
    folder = node
    dest_node_id = folder["h"]
    _ = await mega.upload(__file__, dest_node=dest_node_id, dest_filename="test.py")
    path = f"{folder_name}/test.py"
    file = await mega.find(path)
    assert file
    output_path = await mega.download(file, tmpdir, "test.py")
    assert output_path.is_file()


async def test_empty_trash(mega: Mega):
    # resp None if already empty, else int
    resp = await mega.empty_trash()
    if resp is not None:
        assert isinstance(resp, int)


async def test_add_contact(mega: Mega):
    resp = await mega.add_contact(TEST_CONTACT)
    assert isinstance(resp, int)


async def test_remove_contact(mega: Mega):
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
def test_parse_url(url: str, expected_file_id_and_key: str, mega: Mega):
    assert mega._parse_url(url) == expected_file_id_and_key


@pytest.mark.skip
class TestAPIRequest:
    @pytest.mark.parametrize("response_text", ["-3", "-9"])
    async def test_when_api_returns_int_raises_exception(
        self,
        mega: Mega,
        response_text,
    ):
        with requests_mock.Mocker() as mocker:
            mocker.post(mega.api.entrypoint, text=response_text)
            await mega.api.request(data_input={})
