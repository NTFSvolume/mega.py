import asyncio
import tempfile
import hashlib
from typing import Any, Generator
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import ClientResponse

from mega.client import Mega


def generate_random_file(size_bytes: int, temp_dir: Path) -> Path:
    """Generate a temporary file with null data of specified size."""
    file_path = temp_dir / f"test_file_{size_bytes}.bin"
    with open(file_path, "wb") as f:
        f.write(size_bytes * b"\x00")
    return file_path


@pytest.fixture
def temp_dir() -> Generator[Any,Any,Path]:
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
    #mega.master_key = [random.randint(0, 2**32 - 1) for _ in range(4)]
    mega.master_key = [0, 0, 0, 0]
    mega.root_id = "test_root_id"
    mega.logged_in = True
    return mega


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "file_size,expected_hash",
    [
        (123, "a20507fecb0a9b265eee3020f6ffaa5e0bd0c957106b97600225fe6256f20b6a"),
        (1024, "469a896e0044722b40be4a1fd6ca442d994483bc0974fe291e313ccc49f19bd2"), # 1KB
        (1032, "36a4bf611b25f48c685c279f4d1d0a7dee72946bcfab863daa806c80279c59d5"), # 1KB + 8
        (16 * 1024, "12284e2a1b298cde673d01f83b08b534a45a99a4d96606e4f57b14c9ca401d45"), # 16KB
        (16 * 1024 + 33, "d6d64588dc4bbad6d17d4f0a8dac8dc8d1e7f6aca12e5fa1403e208845456083"),
        (100 * 1024, "a7bbbc6b3a4c46dea4f95f7ae5e762ca7645a3b6bed94bdee2817c63910c6e38"),  # 100KB
        (1024 * 1024, "6edc9fa284fbd3d0176eb8bc5c23a53bf38430348ddbd134118f4f63a8192901"),  # 1MB
        (1024 * 1024 + 6, "d5747956aa773b822eead7794ca915fe279e6efb50f7179e81c89c7e63d8c119"),
        (10 * 1024 * 1024, "3e9aa285282ea64e61d7517330f11b761d15e669f1548f782be9f314e2ca8f3b"),  # 10MB
        (100 * 1024 * 1024, "64062545ca0753883a2ec2f2b82d8c9272c7585b2d989b0c8abef6763a36140a"),  # 100MB
        (1000 * 1024 * 1024, "7f835a3cd31662332c8a98abbdf543dbbff6f105ffe54f488c03993161315469")  # 1000MB
    ],
)
async def test_upload_benchmark(mock_mega: Mega, temp_dir: Path, file_size: int, expected_hash: str):
    """Benchmark the upload function with different file sizes."""
    # Generate test file
    test_file = generate_random_file(file_size, temp_dir)
    
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
    with patch("random.randint", return_value=42) as mocked_random_u32int:
        await mock_mega.upload(str(test_file))
        assert mocked_random_u32int.called

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
    
    hashdigest = hashlib.sha256(sent_data).hexdigest()
    assert hashdigest == expected_hash

    # Clean up
    test_file.unlink() 