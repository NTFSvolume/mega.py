from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from mega import env
from mega.client import MegaNzClient
from mega.utils import setup_logger

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

logger = logging.getLogger(__name__)


async def run() -> None:
    setup_logger(__name__)

    parser = argparse.ArgumentParser(description="Download files from a Mega.nz URL.")
    parser.add_argument(
        "url",
        help="The Mega.nz URL to download from.",
        metavar="URL",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        default=Path("mega.py"),
        help="The directory to save the downloaded file. Defaults to the current directory.",
        metavar="DIR",
    )
    args = parser.parse_args()
    output: Path = args.output_dir.resolve()
    async with connect() as mega:
        await dump_fs(mega, output)
        # await download_folder(mega, args.url, args.output_dir)
        link: str = args.url
        await download_file(mega, link, output)


@contextlib.asynccontextmanager
async def connect() -> AsyncGenerator[MegaNzClient]:
    async with MegaNzClient() as mega:
        await mega.login(env.EMAIL, env.PASSWORD)
        await show_stats(mega)
        with mega.show_progress_bar():
            yield mega


async def show_stats(mega: MegaNzClient) -> None:
    stats = await mega.get_account_stats()
    logger.info(f"Account stats for {env.EMAIL or 'TEMP ACCOUNT'}:")
    logger.info(stats.storage.dump())
    logger.info(stats.balance.dump())
    fs = await mega.get_filesystem()
    metrics = {root.attributes.name: stats.metrics[root.id] for root in (fs.root, fs.inbox, fs.trash_bin)}
    logger.info(metrics)


async def dump_fs(mega: MegaNzClient, output: Path) -> None:
    import json

    fs = await mega.get_filesystem()
    out = output / "filesystem.json"
    out.parent.mkdir(exist_ok=True)
    logger.info(f"Creating filesystem dump at '{out!s}'")
    out.write_text(json.dumps(fs.dump(), indent=2, ensure_ascii=False))


async def download_file(mega: MegaNzClient, url: str, output: Path) -> None:
    public_handle, public_key = mega.parse_file_url(url)
    logger.info(f"Downloading '{url!s}'")
    path = await mega.download_public_file(public_handle, public_key, output)
    logger.info(f"Download of '{url!s}' finished. File save at '{path!s}'")


async def download_folder(mega: MegaNzClient, url: str, output: Path) -> None:
    public_handle, public_key = mega.parse_folder_url(url)
    logger.info(f"Downloading '{url!s}'")
    success, fails = await mega.download_public_folder(public_handle, public_key, output)
    logger.info(f"Download of '{url!s}' finished. Successful downloads {len(success)}, failed {len(fails)}")


async def upload(mega: MegaNzClient, path: str) -> None:
    folder = await mega.create_folder("uploaded by mega.py")
    logger.info(f"Uploading '{path!s}'")
    file = await mega.upload(path, folder.id)
    link = await mega.export(file)
    logger.info(f"Public link for {path!s}': {link}")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
