import asyncio
import hashlib
import itertools
import string
import tempfile
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from aiohttp import ClientResponse

from mega.client import Mega
from mega.crypto import str_to_a32


# Reference: https://github.com/Gallopsled/pwntools/blob/stable/pwnlib/util/cyclic.py#L14
def de_bruijn(n: int = 1) -> bytes:
    """de_bruijn(n = None) -> generator

    Generator for a sequence of unique substrings of length `n`. This is implemented using a
    De Bruijn Sequence over the given `alphabet`.

    The returned generator will yield up to ``len(alphabet)**n`` elements.

    Arguments:
        n(int): The length of subsequences that should be unique.
    """
    alphabet = string.ascii_lowercase.encode()
    k = len(alphabet)
    a = [0] * k * n
    def db(t, p):
        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    yield alphabet[a[j]]
        else:
            a[t] = a[t - p]
            for c in db(t + 1, p):
                yield c

            for j in range(a[t - p] + 1, k):
                a[t] = j
                for c in db(t + 1, t):
                    yield c

    return db(1,1)

@pytest.fixture(scope="session")
def test_byte_pattern() -> bytes:
    gen = itertools.repeat(de_bruijn(4), 1024)
    res = bytes(b for b in next(gen))
    return res

@pytest.fixture
def temp_dir() -> Generator[Any, Any, Path]:
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield Path(tmp_dir)


@pytest.fixture
def mock_mega():
    """Create a Mega instance with mocked API."""
    mega = Mega()
    mega.api = MagicMock()
    mega.api.request = AsyncMock()
    mega.api.request_id = "test_request_id"
    mega.master_key = [0, 0, 0, 0]
    mega.root_id = "test_root_id"
    mega.logged_in = True
    return mega


# Reference: https://discuss.python.org/t/unittest-mock-track-return-values-of-calls/78784/2
class ReturnTrackingMock(Mock):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.call_return_value_list = []

    def __call__(self, *args, **kwargs):
        value = super().__call__(*args, **kwargs)
        self.call_return_value_list.append(value)
        return value


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "file_size,expected_hash,expected_meta_mac",
    [
        (0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", (0, 0)),
        (1, "a318c24216defe206feeb73ef5be00033fa9c4a74d0b967f6532a26ca5906d3b", (2360129931, 1443558504)),
        (123, "e2b615844bd6453344e4a08451dba623a1df1d8799e0f229041440df0dcbb92f", (462268212, 1252393491)),
        (1024, "948aceaf82d2e04b36116d1a00b7cdefa8d3c52373524df4b5d41fd7b24ab0d6", (4073526748, 308179975)),  # 1KB
        (1032, "23626ca8f23f3cdad3d8920996f7c9677843afb7f1566ccabdc04a4dd9931f12", (4198782066, 3158337057)),  # 1KB + 8
        (
            16 * 1024,
            "831ec3a72b95579765d63b785fa9691cbef17de72b48cdd2bedad269f272a226",
            (1953696248, 1220347343),
        ),  # 16KB
        (16 * 1024 + 33, "6c010ca3cda4ba8289ce832a2a2605d8a5892e95c4a8e10c3901c415096d72ce", (785984491, 2524423691)),
        (
            100 * 1024,
            "03b0603db5ef5311c3b68ffe1b688ab0e087bddd5246828f1814e2b8c74eb990",
            (81635840, 609384954),
        ),  # 100KB
        (
            1024 * 1024,
            "9c8667f74fd934ff91c6b8fdcbb73229cb136859bbd64ad644dc0751a4219826",
            (398824904, 825009916),
        ),  # 1MB
        (1024 * 1024 + 6, "dd1a529fc6a8bf7c67a761a3159b3c89bbb69e24081fd9ba7ef5a9de2ad2e3be", (1835351575, 533859569)),
        (
            10 * 1024 * 1024,
            "e36591de22140c3dadc5f6dd70975158d8a9373de83f200611cac17a34829ca0",
            (2743041321, 4208803206)
        ),  # 10MB
        (
            100 * 1024 * 1024,
            "80cefbc89ae0db07e7219081f54027349ff47a09a395b8b5dfa09ae76687ace9",
            (406760838, 3135293207)
        ),  # 100MB
        (
        250 * 1024 * 1024,
            "5631fac7e4d3c85c3e17ea99740447711f2a16dc14f89911dde36a0cc00a7154",
            (2567512444, 2608475317)
        ),  # 200MB
    ],
)
@patch("mega.client.str_to_a32", new_callable=ReturnTrackingMock, wraps=str_to_a32)
@patch("mega.client.random_u32int", return_value=42)
async def test_upload_benchmark(
    random_u32int_mock: MagicMock,
    str_to_a32_mock: ReturnTrackingMock,
    test_byte_pattern: bytes,
    mock_mega: Mega,
    temp_dir: Path,
    file_size: int,
    expected_hash: str,
    expected_meta_mac: tuple[int, int],
):
    """Benchmark the upload function with different file sizes."""
    def generate_test_file(size_bytes: int, temp_dir: Path) -> Path:
        """Generate a temporary file with null data of specified size."""
        file_path = temp_dir / f"test_file_{size_bytes}.bin"
        with open(file_path, "wb") as f:
            pos = 0
            while pos < size_bytes:
                sz = min(len(test_byte_pattern), size_bytes - pos)
                f.write(test_byte_pattern[:sz])
                pos += sz
            assert f.tell() == size_bytes
        return file_path

    # Generate test file
    test_file = generate_test_file(file_size, temp_dir)

    # Mock the upload URL response
    mock_mega.api.request.return_value = {"p": "https://test-upload-url.com"}

    # Mock the session post response
    mock_response = AsyncMock(spec=ClientResponse)
    mock_response.text = AsyncMock(return_value="test_file_handle")
    mock_mega.api.session.post = AsyncMock(return_value=mock_response)

    # Mock the final request response
    mock_mega.api.request.side_effect = [
        {"p": "https://test-upload-url.com"},  # First call for upload URL
        {"f": [{"h": "test_file_handle"}]},  # Second call for completing upload
    ]

    # Record start time
    start_time = asyncio.get_event_loop().time()

    # Perform upload
    await mock_mega.upload(str(test_file))

    assert random_u32int_mock.call_count == 6
    assert str_to_a32_mock.call_count == 1

    file_mac = str_to_a32_mock.call_return_value_list[0]
    # Duplicating code from upload method here
    meta_mac = (file_mac[0] ^ file_mac[1], file_mac[2] ^ file_mac[3])
    assert meta_mac == expected_meta_mac

    # Calculate elapsed time and throughput
    end_time = asyncio.get_event_loop().time()
    elapsed_time = end_time - start_time
    throughput = file_size / elapsed_time  # bytes per second

    # Convert to MB/s for readability
    throughput_mbps = throughput / (1024 * 1024)

    # Print benchmark results
    print(f"\nFile size: {file_size / (1024 * 1024):.2f} MB")
    print(f"Elapsed time: {elapsed_time:.2f} seconds")
    print(f"Throughput: {throughput_mbps:.2f} MB/s")

    # Verify that the upload was called with correct parameters
    assert mock_mega.api.session.post.called

    # Capture and print the arguments passed to session.post
    post_call_args = mock_mega.api.session.post.call_args_list
    sent_data = b"".join([x[1]["data"] for x in post_call_args])

    assert hashlib.sha256(sent_data).hexdigest() == expected_hash

    # Clean up
    test_file.unlink()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "file_size,expected_hash,expected_mac",
    [
        (1, "18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4", (3270258764, 3331013813)),
        (123, "85d14d3bc6058d7930112f2d1347c381cd5feae5d27cc0a3e5c5afbb31333e8a", (1379992016, 1877398824)),
        (1024, "69d9117d20d5bf5b31b011f248e75156228bde731ee0b0134a16e1d2280ff313", (2063093172, 1374128230)),  # 1KB
        (1032, "8fccfb2cf673cdb1682c75403825494fd5ee1b928aa7beb1da0cf3c9e5cd7b8b", (829550120, 1730141005)),  # 1KB + 8
        (
            16 * 1024,
            "d91e0d59972c753edc47f35a08a017782fe05b12030e6ba6b069faf5419ca8f8",
            (2820609023, 1305453219),
        ),  # 16KB
        (16 * 1024 + 33, "d4cd70eebba04584c4e5cfef63493cc6cdcb57bac643d402570a4028bdcd5a88", (2627242211, 1923033912)),
        (
            100 * 1024,
            "cd52aa6a753636e2c54221a351ef2c774bd924ad7511d676b49e9eaf1f80f451",
            (1986300725, 1861989608),
        ),  # 100KB
        (
            1024 * 1024,
            "7e8bd302501c658d8b0f94cb3a2c5fd84dacf9da161e0865948d3d732f0805df",
            (1528311103, 1075726532),
        ),  # 1MB
        (1024 * 1024 + 6, "50612e023694544705f03388027558d4a429a94b2d296880b4ac97311d0026f1", (2517186247, 2707664315)),
        (
            10 * 1024 * 1024,
            "de45539d63dd5a1c9760726164a631015764351355af18bbd3da69c65f6f66b7",
            (3196706590, 2378438557),
        ),  # 10MB
        (
            100 * 1024 * 1024,
            "092538f7015dcb97e5758be4ea917b0b45856c6d8f028919f09a43cd5ef54444",
            (117580077, 1994068272),
        ),  # 100MB
        (
            250 * 1024 * 1024,
            "b9f86ab9dcacc1c14c65d8134322fd8774a7ec11bddb9da0752f41e8f8a39d58",
            (3696262973, 3878513434),
        ),  # 250MB
    ],
)
@patch("mega.client.tempfile.NamedTemporaryFile")
@patch("mega.client.str_to_a32", new_callable=ReturnTrackingMock, wraps=str_to_a32)
@patch("mega.client.asyncio.to_thread")
async def test_download_benchmark(
    to_thread_mock: MagicMock,
    str_to_a32_mock: ReturnTrackingMock,
    named_temp_file: MagicMock,
    test_byte_pattern: bytes,
    mock_mega: Mega,
    temp_dir: Path,
    file_size: int,
    expected_hash: str,
    expected_mac: tuple[int, int],
):
    """Benchmark the download function with different file sizes."""
    hash = hashlib.sha256()

    # Mock NamedTemporaryFile to receive/hash the decrypted data
    named_temp_file.return_value.__enter__.return_value = Mock()
    named_temp_file.return_value.__enter__.return_value.write = lambda x: hash.update(x)

    async def mock_content_reader(length: int):
        tmp = bytearray()
        pos = 0
        while pos < length:
            count = min(len(test_byte_pattern), length - pos)
            tmp.extend(test_byte_pattern[:count])
            pos += count
        return bytes(tmp)

    # Create a temporary file for output
    output_file = temp_dir / "output.bin"

    mock_mega.api.session.get.return_value.__aenter__.return_value.content.readexactly = AsyncMock(
        side_effect=mock_content_reader
    )

    # Record start time
    start_time = asyncio.get_event_loop().time()

    # Perform download
    await mock_mega._really_download_file(
        direct_file_url="https://test-download-url.com",
        output_path=output_file,
        file_size=file_size,
        iv=(1, 2),
        meta_mac=expected_mac,
        k_decrypted=(5, 6, 7, 8),
    )

    assert to_thread_mock.call_count == 2
    assert str_to_a32_mock.call_count == 1
    assert hash.hexdigest() == expected_hash

    file_mac = str_to_a32_mock.call_return_value_list[0]
    # Duplicating code from upload method here
    meta_mac = (file_mac[0] ^ file_mac[1], file_mac[2] ^ file_mac[3])
    assert meta_mac == expected_mac

    # Calculate elapsed time and throughput
    end_time = asyncio.get_event_loop().time()
    elapsed_time = end_time - start_time
    throughput = file_size / elapsed_time  # bytes per second

    # Convert to MB/s for readability
    throughput_mbps = throughput / (1024 * 1024)

    # Print benchmark results
    print(f"\nFile size: {file_size / (1024 * 1024):.2f} MB")
    print(f"Elapsed time: {elapsed_time:.2f} seconds")
    print(f"Throughput: {throughput_mbps:.2f} MB/s")

    # Verify that the download was called
    assert mock_mega.api.session.get.called
