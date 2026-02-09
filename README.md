# Async Mega.py

[![PyPI - Version](https://img.shields.io/pypi/v/async-mega-py)](https://pypi.org/project/async-mega-py/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/async-mega-py)](https://pypi.org/project/async-mega-py/)
[![linting - Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/NTFSvolume/mega.py/actions/workflows/ruff.yml)
[![GitHub License](https://img.shields.io/github/license/NTFSvolume/mega.py)](https://github.com/NTFSvolume/mega.py/blob/master/LICENSE)
[![CI](https://github.com/NTFSvolume/mega.py/actions/workflows/ci.yml/badge.svg)](https://github.com/NTFSvolume/mega.py/actions/workflows/ci.yml)

Python library and CLI app for the [Mega.nz](https://mega.nz/) and [Transfer.it](https://transfer.it/) API

- [Async Mega.py](#async-megapy)
  - [API Information](#api-information)
  - [How To Use](#how-to-use)
  - [Methods](#methods)
    - [Upload / Downloads](#upload--downloads)
  - [The filesystem object](#the-filesystem-object)
    - [What can the filesystem object do?](#what-can-the-filesystem-object-do)
    - [Read the filesystem from a file dump](#read-the-filesystem-from-a-file-dump)
  - [Transfer.it](#transferit)
  - [CLI](#cli)

## API Information

Supports:

- Login (with credentials or creating a temporary account)
- Upload
- Download (files and folders)
- Delete
- Search
- Export (public sharing)
- Import public files to your account
- Renaming
- Moving files
- Add/remove contacts
- Get account stats (storage quota, transfer quota, balance (PRO accounts only))

TODO:

- [ ] Support multifactor authentication (MFA) login

Please check [`src/mega/data_structures.py`](src/mega/data_structures.py) for details about the objects returned by the API

## How To Use

> [!TIP]
> You can run the commands bellow in an interactive python (the asyncio REPL). Try them in real time as is, using `async/await` keywords!
>
> ```uv run -p3.12 --with async-mega-py python -m asyncio```

```python
from mega.client import MegaNzClient

email = "my_email@email.com"
password = "12345"
async with MegaNzClient() as mega:
    await mega.login(email, password)

```

Login should always be the first thing you do. Almost all operations require a valid account. You can call `login` without params to create a temporary account:

```python
from mega.client import MegaNzClient

async with MegaNzClient() as mega:
    await mega.login() # login using a temporary anonymous account

# Also works without using it as a context manager,
mega = MegaNzClient()
await mega.login()
# but you have the responsability to close the session
# mega.close()  

```

## Methods

Check [`src/mega/client.py`](src/mega/client.py) and [`src/mega/data_structures.py`](src/mega/data_structures.py)to view the details of all public methods and which objects each one return.

The client deserializes the raw responses from the API and always returns `dataclasses` for objects (except for `get_user` which returns a normal `dict`)

> [!TIP]
> All dataclasses returned by the client have a `dump` method to convert them to a `dict` if required

```python
# Get user details
# Includes email, user id, history of all emails, creation timestamp, etc...
await mega.get_user()

# Get account stats
# ex: Balance, storage quota, transfer quota, usage metrics, etc...
await mega.get_account_stats()

# Add/remove contacts
contact = "test@mega.nz"
await mega.add_contact(contact)
await mega.remove_contact(contact)

# Create a folder
await mega.create_folder('new_folder')
await mega.create_folder('new_folder/sub_folder/subsub_folder')

# Rename a file or a folder
folder = await mega.find('new_folder/sub_folder/subsub_folder')
await mega.rename(folder, new_name='my_new_name')

# Delete or destroy folder

await mega.delete(folder.id) # Send this node to the trash bin (still counts towards your quota)
await mega.destroy(folder.id) # This removes it completely from your account

```

### Upload / Downloads

```python
# Upload a file, and get its public link
my_real_file = '/home/user/myfile.doc' # Change this to a real file path!
uploaded_file = await mega.upload(my_real_file) # Upload returns the Node that represents the file you just uploaded
await mega.export(uploaded_file)

# Download a file from your account
output_dir = "my downloads"
await mega.download(uploaded_file, output_dir)

# Download a public file
url = "https://mega.nz/#!hYVmXKqL!r0d0-WRnFwulR_shhuEDwrY1Vo103-am1MyUy8oV6Ps"
public_handle, public_key = mega.parse_file_url(url)  
await mega.download_public_file(public_handle, public_key, output_dir)

# Download a public folder
url = "https://mega.co.nz/#F!utYjgSTQ!OM4U3V5v_W4N5edSo0wolg1D5H0fwSrLD3oLnLuS9pc"
public_handle, public_key, selected_node = mega.parse_folder_url(url)
success, fails = await mega.download_public_folder(public_handle, public_key, output_dir, selected_node)
print(f"Download of '{url!s}' finished. Successful downloads {len(success)}, failed {len(fails)}")

# Import a file from URL
url = "https://mega.nz/#!hYVmXKqL!r0d0-WRnFwulR_shhuEDwrY1Vo103-am1MyUy8oV6Ps"
public_handle, public_key = mega.parse_file_url(url)
await mega.import_public_file(public_handle, public_key, dest_node_id=folder.id)

# How do you know if an URL is a file or folder? call the more generic parse_url method
result = mega.parse_url(url)
print (result.is_folder)
```

> [!TIP]
> You can show a progress bar on the terminal for each download/upload by calling them within the `progress_bar` context manager (needs optional dependency `rich` to be installed):

```python
url = "https://mega.co.nz/#F!utYjgSTQ!OM4U3V5v_W4N5edSo0wolg1D5H0fwSrLD3oLnLuS9pc"
public_handle, public_key = mega.parse_folder_url(url)
with mega.progress_bar:  
    success, fails = await mega.download_public_folder(public_handle, public_key, output_dir)
```

## The filesystem object

The filesystem is a read only copy of your account's file structure.

> [!IMPORTANT]  
> `mega.py` caches your filesystem until you make a request to modify it. ex: `create_dir` or `upload`
>
> That means calls to `mega.get_filesystem()` will not reflect changes made by third parties (ex: MegaNZ's website or the MegaNZ's app)
>
> You can force it to fetch current data by using `mega.get_filesystem(force=True)`

```python
# Get a read only copy of your filesystem
fs = await mega.get_filesystem()

# save a copy of your filesystem as json
import json
from pathlib import Path

dump = json.dumps(fs.dump(), indent=2, ensure_ascii=False)
Path("my_fs.json").write_text(dump)
```

### What can the filesystem object do?

We are gonna use the example filesystem found at [`tests/fake_fs.json`](tests/fake_fs.json) which has this structure:

```json
"paths": {
    "qCZrYJVK": "/",
    "FeWnQouH": "/backup.sql",
    "coJ3yMOW": "/docker-compose.yml",
    "FzL3QdIj": "/Inbox",
    "2gL2GPaJ": "/index.html",
    "msinsVCj": "/logo.png",
    "MBlNlb2P": "/styles.css",
    "7N9QiWZ9": "/tests",
    "RDJJI2lv": "/tests/logo.png",
    "pHWVIQLd": "/tests/logo.png",
    "oImwb6nN": "/tests/script.js",
    "FIXitv4F": "/tests/scripts",
    "0fPFklV3": "/tests/scripts/notes.txt",
    "l9zkz1GU": "/tests/scripts/script.js",
    "E4LqT4EF": "/tests/scripts/styles.css",
    "i6ry53xV": "/tests/setup.sh",
    "Iri7NRCx": "/tests/utils.py",
    "2Tae8amE": "/Trash Bin",
    "t8HkzBH2": "/Trash Bin/data",
    "8EwHVJna": "/Trash Bin/data/docker-compose.yml"
  }
```

### Read the filesystem from a file dump

```python
from mega.filesystem import UserFileSystem

dump = Path("tests/fake_fs.json").read_text()
fs = UserFileSystem.from_dump(json.loads(dump))

# Search for nodes
query = "tests/script"
for node_id, path in fs.search(query):
    print (node_id)
    print (path)

# or
dict(fs.search(query))
```

The output will be:

```json
{
    "oImwb6nN": "/tests/script.js",
    "FIXitv4F": "/tests/scripts",
    "0fPFklV3": "/tests/scripts/notes.txt",
    "l9zkz1GU": "/tests/scripts/script.js",
    "E4LqT4EF": "/tests/scripts/styles.css",
}
```



```python
# Get the path to a node
path = fs.absolute_path("0fPFklV3")
# Should be: /tests/scripts/notes.txt

# Find a node by its *exact* path
result = fs.find("/tests/scripts/notes.txt")
assert result.id == "0fPFklV3"

```

```python
# Get deleted files and folders (on the trash bin)
list(fs.deleted)

# List all the children of a folder (resursive)
folder = fs.find("/tests")
for node in fs.iterdir(folder.id, recursive=True):
    print(fs.absolute_path(node))

```
Output will be:

```json
[
    "/tests/logo.png",
    "/tests/logo.png",
    "/tests/script.js",
    "/tests/scripts",
    "/tests/scripts/notes.txt",
    "/tests/scripts/script.js",
    "/tests/scripts/styles.css"
]
```

> [!IMPORTANT]  
> Mega's filesystem is *not* POSIX-compliant: multiple nodes may have the same path.
>
> If 2 nodes have the same path, `find` will throw an error.

```python
fs.find("/tests/logo.png") # This will fail
# You will have to call search and choose which one you actually want
dict(fs.search("/tests/logo.png"))
```

## Transfer.it

> [!NOTE]
> The `transfer.it` client does not support uploads (yet!)

```python
from mega.transfer_it import TransferItClient

async with TransferItClient() as client:
    transfer_id = client.parse_url(url)
    # This is the same filesystem object as mega's,
    # but it does not have root, inbox or trash_bin nodes
    fs = await client.get_filesystem(transfer_id)
    output_dir = "My downloads"
    success, fails = await client.download_transfer(transfer_id, output_dir)
    logger.info(f"Download of '{url!s}' finished. Successful downloads {len(success)}, failed {len(fails)}")
```

## CLI

You can use `async-mega-py` as a stand alone CLI app! Just install it with the optional `[cli]` dependencies. The CLI offers 2 commands: `mega-py` and `async-mega-py`. Both are just aliases for the same app.

```sh
# Install it with:
uv tool install async-mega-py[cli]

#Run it
mega-py --help
```

```powershell
Usage: mega-py [OPTIONS] COMMAND [ARGS]...  

 CLI app for the Mega.nz and Transfer.it. Set MEGA_NZ_EMAIL and MEGA_NZ_PASSWORD  
 enviroment variables to use them as credentials for Mega  

╭─ Options ──────────────────────────────────────────────────────────────────────╮
│ --verbose  -v               Increase verbosity (-v shows debug logs,  -vv      │
│                             shows HTTP traffic)                                │
│ --help                      Show this message and exit.                        │
╰────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ─────────────────────────────────────────────────────────────────────╮
│ download   Download a public file or folder by its URL (transfer.it / mega.nz) │
│ dump       Dump a copy of your filesystem to disk                              │
│ stats      Show account stats                                                  │
│ upload     Upload a file to your account                                       │
╰────────────────────────────────────────────────────────────────────────────────╯
```

> [!TIP]
> The CLI app does *not* accept login credentials, but you can still use your account by setting up the `MEGA_NZ_EMAIL` and `MEGA_NZ_PASSWORD` enviroment variables
>
> It will also read them from an `.env` file (if found)
