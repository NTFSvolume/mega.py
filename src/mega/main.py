import argparse
import asyncio
import logging
import os

from rich.logging import RichHandler

from mega.client import Mega


async def run():
    handler = RichHandler(show_time=False, rich_tracebacks=True)
    logger = logging.getLogger()
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
    mega = Mega()
    email = os.getenv("EMAIL")
    password = os.getenv("PASS")
    await mega.login(email, password)
    download_url: str = args.url
    output_dir: str = args.output_dir
    await mega.download_url(url=download_url, dest_path=output_dir)
    await mega.close()


def main():
    asyncio.run(run())


if __name__ == "__main__":
    main()
