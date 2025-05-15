import asyncio
import os
import random
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import ClientResponse

from mega.client import Mega


def generate_random_file(size_bytes: int, temp_dir: Path) -> Path:
    """Generate a temporary file with random data of specified size."""
    file_path = temp_dir / f"test_file_{size_bytes}.bin"
    with open(file_path, "wb") as f:
        f.write(os.urandom(size_bytes))
    return file_path


@pytest.fixture
def temp_dir():
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
    mega.master_key = [random.randint(0, 2**32 - 1) for _ in range(4)]
    mega.root_id = "test_root_id"
    mega.logged_in = True
    return mega


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "file_size",
    [
        123,
        1024, # 1KB
        1032, # 1KB + 8
        16 * 1024, # 16KB
        16 * 1024 + 33,
        100 * 1024,  # 100KB
        1024 * 1024,  # 1MB
        1024 * 1024 + 6,
        10 * 1024 * 1024,  # 10MB
        100 * 1024 * 1024,  # 100MB
        1000 * 1024 * 1024,  # 1000MB
    ],
)
async def test_upload_benchmark(mock_mega, temp_dir, file_size):
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
    await mock_mega.upload(str(test_file))
    
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
    
    # Clean up
    test_file.unlink() 