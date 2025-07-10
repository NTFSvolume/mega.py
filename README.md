# Async Mega.py (Updated)

[![linting - Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/NTFSvolume/mega.py/actions/workflows/ruff.yml)
[![GitHub License](https://img.shields.io/github/license/NTFSvolume/mega.py)](https://github.com/NTFSvolume/mega.py/blob/master/LICENSE)
[![CI](https://github.com/NTFSvolume/mega.py/actions/workflows/ci.yml/badge.svg)](https://github.com/NTFSvolume/mega.py/actions/workflows/ci.yml)

Python library for the [Mega.nz](https://mega.nz/) API

Supports:

- login
- upload
- download
- delete
- search
- sharing
- renaming
- moving files

## API Information

Please check [`src/mega/data_structures.py`](src/mega/data_structures.py) for details about the objects returned by the API

## How To Use

### 1. Import the client

```python
from mega.client import Mega
```

### 2. Create an instance of the client

```python
mega = Mega()
```

### 3. Login to Mega

```python
await mega.login(email, password)
await mega.login() # login using a temporary anonymous account
```

## Methods

### Get user details

```python
details = await mega.get_user()
```

### Get account balance (Pro accounts only)

```python
balance = await mega.get_balance()
```

### Get account disk quota

```python
quota = await mega.get_quota()
```

### Get account storage space

```python
space = await mega.get_storage_space()
```

### Get account files

```python
files = await mega.get_files()
```

### Get files in trash bin

```python
deleted_files = await mega.get_files_in_node(4)  # Options: root(2), inbox(3), trashbin (4)
```

### Get file system

```python
fs = await mega.build_file_system()
```

### Upload a file, and get its public link

```python
file = await mega.upload('myfile.doc')
link = await mega.get_upload_link(file)
# see client.py for destination and filename options
```

### Export a file or folder

```python
public_exported_web_link = await mega.export('myfile.doc')
public_exported_web_link = await mega.export('my_mega_folder/my_sub_folder_to_share')
# e.g. https://mega.nz/#F!WlVl1CbZ!M3wmhwZDENMNUJoBsdzFng
```

### Search a file or folder (recursively)

Search returns every file/folder that contains the  search query in its path

If you have these files in your account:

```bash
├── dir1
│   ├── file1.txt
│   └── file2.md
├── dir2
│   └── subdir
│       └── file3.log
├── trash_bin
│   └── file4.mov
└── file5.txt
```

```python

result = await mega.search('file1.txt') # Returns a list with 1 element, dir1/file1.txt
result = await mega.search('file') # Returns a list with 5 elements
result = await mega.search('file', exclude_deleted=True) # Returns a list with 4 elements
result = await mega.search('.txt') # Returns a list with 2 elements
result = await mega.search('dir1/file') # Returns a list with 2 elements
```

### Find a file or folder

Like `search`, but the path must start with the search query and only returns the first element (if found)

```python
result = await mega.find('file3.log') # None
result = await mega.find('dir2/file3.log') # None
result = await mega.find('dir2/subdir/file3') # File() at dir2/subdir/file3.log'
result = await mega.find('dir2/subdir/file3.log') # File() at dir2/subdir/file3.log'
```

### Upload a file to a destination folder

```python
folder = await mega.find('dir2/subdir')
await mega.upload('myfile.doc', dest_node=folder)
```

### Download a file, optionally specify destination folder

```python
file = await mega.find('dir2/subdir/file3.log')
await mega.download(file)
await mega.download(file, dest_path='/home/john-smith/Desktop')
await mega.download(file, dest_path='/home/john-smith/Desktop', dest_filename='my_logs.log')
```

Download will show a progress bar on the terminal. To disable it, create an instance of the mega client with the progress bar disabled

```python
mega = Mega(use_progress_bar=False)
```

You can also disable the progress bar on an existing instance

```python
mega.use_progress_bar = False
```

### Download a file from an URL

```python
url = 'https://mega.co.nz/#!utYjgSTQ!OM4U3V5v_W4N5edSo0wolg1D5H0fwSrLD3oLnLuS9pc'
await mega.download_url(url, dest_filename='my_file.zip')
```

### Download a public folder

```python
url = 'https://mega.co.nz/#F!utYjgSTQ!OM4U3V5v_W4N5edSo0wolg1D5H0fwSrLD3oLnLuS9pc'
await mega.download_folder_url(url, dest_path ="downloads/my_music")
```

### Import a file from URL, optionally specify destination folder

```python
url = 'https://mega.co.nz/#!utYjgSTQ!OM4U3V5v_W4N5edSo0wolg1D5H0fwSrLD3oLnLuS9pc'
await mega.import_public_url(url)
folder = await mega.find('dir2')
await mega.import_public_url(url, dest_node=folder)
```

### Create a folder

```python
await mega.create_folder('new_folder')
await mega.create_folder('new_folder/sub_folder/subsub_folder')
```

### Rename a file or a folder

```python
file = await mega.find('dir2/subdir/file3.log')
await mega.rename(file, new_name='dir2/subdir/old_logs.log')
```
