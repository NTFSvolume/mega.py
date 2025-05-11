import os
import random
from collections.abc import Generator
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
def mega(folder_name: str) -> Generator[Mega]:
    mega_ = Mega()
    mega_.login(email=os.environ["EMAIL"], password=os.environ["PASS"])
    created_nodes = mega_.create_folder(folder_name)
    yield mega_
    node_id = next(iter(created_nodes.values()))
    mega_.destroy(node_id)


@pytest.fixture
def uploaded_file(mega: Mega, folder_name: str):
    folder = mega.find(folder_name)
    assert folder
    dest_node_id = folder["h"]
    mega.upload(__file__, dest_node=dest_node_id, dest_filename="test.py")
    path = f"{folder_name}/test.py"
    return mega.find(path)


def test_mega(mega: Mega):
    assert isinstance(mega, Mega)


def test_login(mega: Mega):
    assert isinstance(mega, Mega)


def test_get_user(mega: Mega):
    resp = mega.get_user()
    assert isinstance(resp, dict)


def test_get_quota(mega: Mega):
    resp = mega.get_quota()
    assert isinstance(int(resp), int)


def test_get_storage_space(mega: Mega):
    resp = mega.get_storage_space()
    assert isinstance(resp, dict)


def test_get_files(mega: Mega):
    files = mega.get_files()
    assert isinstance(files, dict)


def test_get_link(mega: Mega, uploaded_file: FileOrFolder):
    link = mega.get_link(uploaded_file)
    assert isinstance(link, str)


@pytest.mark.skip
class TestExport:
    def test_export_folder(self, mega: Mega, folder_name: str):
        public_url = None
        for _ in range(2):
            result_public_share_url = mega.export(folder_name)

            if not public_url:
                public_url = result_public_share_url
            assert result_public_share_url.startswith("https://mega.nz/#F!")
            assert result_public_share_url == public_url

    def test_export_folder_within_folder(self, mega: Mega, folder_name: str):
        folder_path = Path(folder_name) / "subdir" / "anothersubdir"
        mega.create_folder(folder_path)
        result_public_share_url = mega.export(path=folder_path)
        assert result_public_share_url.startswith("https://mega.nz/#F!")

    def test_export_folder_using_node_id(self, mega: Mega, folder_name: str):
        file = mega.find(folder_name)
        assert file
        node_id = file["p"]
        result_public_share_url = mega.export(node_id=node_id)
        assert result_public_share_url.startswith("https://mega.nz/#F!")

    def test_export_single_file(self, mega: Mega, folder_name: str):
        # Upload a single file into a folder
        node = mega.find(folder_name)
        assert node
        folder = node
        dest_node_id = folder["h"]
        mega.upload(__file__, dest_node=dest_node_id, dest_filename="test.py")
        path = f"{folder_name}/test.py"
        assert mega.find(path)

        for _ in range(2):
            result_public_share_url = mega.export(path)

            assert result_public_share_url.startswith("https://mega.nz/#!")


def test_import_public_url(mega: Mega):
    resp = mega.import_public_url(TEST_PUBLIC_URL)
    file_handle = mega.get_id_from_obj(resp)
    assert file_handle
    resp = mega.destroy(file_handle)
    assert isinstance(resp, int)


class TestCreateFolder:
    def test_create_folder(self, mega: Mega, folder_name: str):
        folder_names_and_node_ids = mega.create_folder(folder_name)

        assert isinstance(folder_names_and_node_ids, dict)
        assert len(folder_names_and_node_ids) == 1

    def test_create_folder_with_sub_folders(self, mega: Mega, folder_name: str, mocker):
        folder_names_and_node_ids = mega.create_folder(Path(folder_name) / "subdir" / "anothersubdir")

        assert len(folder_names_and_node_ids) == 3
        assert folder_names_and_node_ids == {
            folder_name: mocker.ANY,
            "subdir": mocker.ANY,
            "anothersubdir": mocker.ANY,
        }


class TestFind:
    def test_find_file(self, mega: Mega, folder_name: str):
        folder = mega.find(folder_name)
        assert folder
        dest_node_id = folder["h"]
        mega.upload(__file__, dest_node=dest_node_id, dest_filename="test.py")
        file1 = mega.find(f"{folder_name}/test.py")
        assert file1

        dest_node_id2 = mega.create_folder("new_folder")["new_folder"]
        _ = mega.upload(__file__, dest_node=dest_node_id2, dest_filename="test.py")

        file2 = mega.find("new_folder/test.py")
        assert file2
        # Check that the correct test.py was found
        assert file1 != file2

    def test_path_not_found_returns_none(self, mega: Mega):
        assert mega.find("not_found") is None

    def test_exclude_deleted_files(self, mega: Mega, folder_name: str):
        node = mega.find(folder_name)
        assert node
        folder_node_id = node["h"]
        assert mega.find(folder_name)
        _ = mega.delete(folder_node_id)
        assert mega.find(folder_name)
        assert not mega.find(folder_name, exclude_deleted=True)


def test_rename(mega: Mega, folder_name: str):
    file = mega.find(folder_name)
    if file:
        resp = mega.rename(file, folder_name)
        assert isinstance(resp, int)


def test_delete_folder(mega: Mega, folder_name: str):
    node = mega.find(folder_name)
    assert node
    folder_node_id = node["h"]
    resp = mega.delete(folder_node_id)
    assert isinstance(resp, int)


def test_delete(mega: Mega, uploaded_file: FileOrFolder):
    resp = mega.delete(uploaded_file["h"])
    assert isinstance(resp, int)


def test_destroy(mega: Mega, uploaded_file: FileOrFolder):
    resp = mega.destroy(uploaded_file["h"])
    assert isinstance(resp, int)


def test_download(mega: Mega, tmpdir, folder_name):
    # Upload a single file into a folder
    node = mega.find(folder_name)
    assert node
    folder = node
    dest_node_id = folder["h"]
    mega.upload(__file__, dest_node=dest_node_id, dest_filename="test.py")
    path = f"{folder_name}/test.py"
    file = mega.find(path)
    assert file
    output_path = mega.download(file, tmpdir, "test.py")
    assert output_path.exists()


def test_empty_trash(mega: Mega):
    # resp None if already empty, else int
    resp = mega.empty_trash()
    if resp is not None:
        assert isinstance(resp, int)


def test_add_contact(mega: Mega):
    resp = mega.add_contact(TEST_CONTACT)
    assert isinstance(resp, int)


def test_remove_contact(mega: Mega):
    resp = mega.remove_contact(TEST_CONTACT)
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
    def test_when_api_returns_int_raises_exception(
        self,
        mega: Mega,
        response_text,
    ):
        with requests_mock.Mocker() as mocker:
            mocker.post(mega.api.entrypoint, text=response_text)
            mega.api.request(data_input={})
