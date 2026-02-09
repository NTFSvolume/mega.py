from __future__ import annotations

import contextlib
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer
import yarl

from mega import __version__, env, progress
from mega.api import LOG_HTTP_TRAFFIC
from mega.cli.app import CLIApp
from mega.client import MegaNzClient
from mega.transfer_it import TransferItClient
from mega.utils import Site, setup_logger

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator


logger = logging.getLogger("mega")


def verbose(
    verbose: Annotated[
        int,
        typer.Option(
            "-v",
            "--verbose",
            count=True,
            help="Increase verbosity (-v shows debug logs,  -vv shows HTTP traffic)",
        ),
    ] = 0,
) -> None:
    if verbose > 1:
        LOG_HTTP_TRAFFIC.set(True)

    level = logging.DEBUG if verbose else logging.INFO
    setup_logger(level)


app = CLIApp(
    add_completion=False,
    callback=verbose,
    help=(
        "CLI app for the [bold black]Mega.nz[/bold black] and [bold black]Transfer.it[/bold black].\n"
        f"Set [bold green]{env.NAMES.EMAIL}[/bold green] and [bold green]{env.NAMES.PASSWORD}[/bold green] enviroment variables to use them as credentials for Mega"
    ),
    epilog=f"v{__version__}",
)
CWD = Path.cwd()


@contextlib.asynccontextmanager
async def connect() -> AsyncGenerator[MegaNzClient]:
    async with MegaNzClient() as mega:
        await mega.login(env.EMAIL, env.PASSWORD)
        with mega.progress_bar:
            yield mega


async def transfer_it(url: str, output_dir: Path) -> None:
    async with TransferItClient() as client:
        with progress.new_progress():
            transfer_id = client.parse_url(url)
            logger.info(f"Downloading '{url}'")
            success, fails = await client.download_transfer(transfer_id, output_dir)
            logger.info(f"Download of '{url}' finished. Successful downloads {len(success)}, failed {len(fails)}")


@app.command()
async def download(url: str, output_dir: Path = CWD) -> None:
    """Download a public file or folder by its URL (transfer.it / mega.nz)"""
    site = Site(yarl.URL(url).origin())
    if site is Site.TRANSFER_IT:
        return await transfer_it(url, output_dir)

    async with connect() as mega:
        parsed_url = mega.parse_url(url)
        if parsed_url.is_folder:
            return await download_folder(mega, url, output_dir)
        await download_file(mega, url, output_dir)


@app.command()
async def dump(output_dir: Path = CWD) -> None:
    """Dump a copy of your filesystem to disk"""
    async with connect() as mega:
        fs = await mega.get_filesystem()
        out = output_dir / "filesystem.json"
        out.parent.mkdir(exist_ok=True)
        logger.info(f"Creating filesystem dump at '{out!s}'")
        out.write_text(json.dumps(fs.dump(), indent=2, ensure_ascii=False))


@app.command()
async def stats() -> None:
    """Show account stats"""
    async with connect() as mega:
        stats = await mega.get_account_stats()
        logger.info(f"Account stats for {env.EMAIL or 'TEMP ACCOUNT'}:")
        logger.info(stats.storage.dump())
        logger.info(stats.balance.dump())
        fs = await mega.get_filesystem()
        metrics = {root.attributes.name: stats.metrics[root.id] for root in (fs.root, fs.inbox, fs.trash_bin)}
        logger.info(metrics)


@app.command()
async def upload(file_path: Path) -> None:
    """Upload a file to your account"""
    async with connect() as mega:
        folder = await mega.create_folder("uploaded by mega.py")
        logger.info(f'Uploading "{file_path!s}"')
        file = await mega.upload(file_path, folder.id)
        link = await mega.export(file)
        logger.info(f'Public link for "{file_path!s}": {link}')


async def download_file(mega: MegaNzClient, url: str, output: Path) -> None:
    public_handle, public_key = mega.parse_file_url(url)
    logger.info(f"Downloading {url}")
    path = await mega.download_public_file(public_handle, public_key, output)
    logger.info(f'Download of {url} finished. File save at "{path!s}"')


async def download_folder(mega: MegaNzClient, url: str, output: Path) -> None:
    public_handle, public_key = mega.parse_folder_url(url)
    logger.info(f"Downloading {url}")
    success, fails = await mega.download_public_folder(public_handle, public_key, output)
    logger.info(f"Download of {url} finished. Successful downloads {len(success)}, failed {len(fails)}")


def main() -> None:
    app()
