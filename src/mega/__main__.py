import argparse
import asyncio
import logging
import os

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
        default=os.path.realpath("."),
        help="The directory to save the downloaded file. Defaults to the current directory.",
        metavar="DIR",
    )
    args = parser.parse_args()
    email = os.getenv("EMAIL")
    password = os.getenv("PASS")

    async with Mega() as mega:
        await mega.login(email, password)
        print(await mega.get_account_stats())  # noqa: T201
        public_handle, public_key = mega.parse_file_url(args.url)
        await mega.download_public_file(public_handle, public_key, args.output_dir)


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
