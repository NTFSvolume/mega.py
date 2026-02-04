import argparse
import asyncio
import logging
import os
from pathlib import Path
from pprint import pprint

from rich.logging import RichHandler

from mega.client import Mega


async def run() -> None:
    handler = RichHandler(show_time=False, rich_tracebacks=True)
    logger = logging.getLogger(__name__)
    logger.setLevel(10)
    logger.addHandler(handler)

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
    email = os.getenv("EMAIL")
    password = os.getenv("PASS")

    async with Mega() as mega:
        await mega.login(email, password)
        stats = await mega.get_account_stats()
        pprint(stats)  # noqa: T203
        public_handle, public_key = mega.parse_file_url(args.url)
        await mega.download_public_folder(public_handle, public_key, args.output_dir)


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
