import argparse
import asyncio
import logging
from pathlib import Path
from pprint import pprint

from mega import env
from mega.client import MegaNzClient
from mega.utils import setup_logger

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
        default=Path(),
        help="The directory to save the downloaded file. Defaults to the current directory.",
        metavar="DIR",
    )
    args = parser.parse_args()

    async with MegaNzClient() as mega:
        await mega.login(env.EMAIL, env.PASSWORD)
        stats = await mega.get_account_stats()
        pprint(stats.dump())  # noqa: T203
        public_handle, public_key = mega.parse_folder_url(args.url)
        logger.info(f"Downloading {args.url}")
        with mega.show_progress_bar():
            await mega.download_public_folder(public_handle, public_key, args.output_dir)


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
