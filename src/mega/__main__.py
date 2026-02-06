import argparse
import asyncio
from pathlib import Path
from pprint import pprint

from mega import env
from mega.client import MegaClient
from mega.utils import setup_logger


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

    async with MegaClient() as mega:
        await mega.login(env.EMAIL, env.PASSWORD)
        stats = await mega.get_account_stats()
        pprint(stats)  # noqa: T203
        public_handle, public_key = mega.parse_file_url(args.url)
        await mega.download_public_folder(public_handle, public_key, args.output_dir)


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
