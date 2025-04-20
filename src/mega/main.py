import argparse
import os

from mega import Mega


def main():
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
    mega.login()

    download_url: str = args.url
    output_dir: str = args.output_dir
    mega.download_url(url=download_url, dest_path=output_dir)


if __name__ == "__main__":
    main()
