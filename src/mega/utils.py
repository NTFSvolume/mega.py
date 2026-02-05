import logging
import re

from rich.logging import RichHandler

from mega.errors import ValidationError


def setup_logger(name: str = "mega") -> None:
    handler = RichHandler(show_time=False, rich_tracebacks=True)
    logger = logging.getLogger(name)
    logger.setLevel(10)
    logger.addHandler(handler)


def parse_file_url(url: str) -> tuple[str, str]:
    """Parse file id and key from url."""
    if "/file/" in url:
        # V2 URL structure
        # ex: https://mega.nz/file/cH51DYDR#qH7QOfRcM-7N9riZWdSjsRq
        url = url.replace(" ", "")
        file_id = re.findall(r"\W\w\w\w\w\w\w\w\w\W", url)[0][1:-1]
        match = re.search(file_id, url)
        assert match
        id_index = match.end()
        key = url[id_index + 1 :]
        return file_id, key
    elif "!" in url:
        # V1 URL structure
        # ex: https://mega.nz/#!Ue5VRSIQ!kC2E4a4JwfWWCWYNJovGFHlbz8F
        match = re.findall(r"/#!(.*)", url)
        path = match[0]
        return tuple(path.split("!"))
    else:
        raise ValueError(f"URL key missing from {url}")


def parse_folder_url(url: str) -> tuple[str, str]:
    if "/folder/" in url:
        _, parts = url.split("/folder/", 1)
    elif "#F!" in url:
        _, parts = url.split("#F!", 1)
    else:
        raise ValidationError("Not a valid folder URL")
    root_folder_id, shared_key = parts.split("#")
    return root_folder_id, shared_key
