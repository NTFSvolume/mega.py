Async Mega.py (Updated)
=======

Python library for the [Mega.co.nz](https://mega.nz/)
API, currently supporting:

-   login
-   uploading
-   downloading (files and folders)
-   deleting
-   searching
-   sharing
-   renaming
-   moving files


How To Use
----------

### Import mega.py

```python
from mega.client import Mega
```

### Create an instance of Mega.py

```python
mega = Mega()
```

### Login to Mega

```python
m = await mega.login(email, password)
# login using a temporary anonymous account
m = await mega.login()
```

### Get user details

```python
details = await m.get_user()
```

### Get account balance (Pro accounts only)

```python
balance = await m.get_balance()
```

### Get account disk quota

```python
quota = await m.get_quota()
```

### Get account storage space

```python
space = await m.get_storage_space()
```

### Get account files

```python
files = await m.get_files()
```

### Get file system

```python
fs = await m.build_file_system()
```

### Upload a file, and get its public link

```python
file = await m.upload('myfile.doc')
await m.get_upload_link(file)
# see client.py for destination and filename options
```

### Export a file or folder

```python
public_exported_web_link = await m.export('myfile.doc')
public_exported_web_link = await m.export('my_mega_folder/my_sub_folder_to_share')
# e.g. https://mega.nz/#F!WlVl1CbZ!M3wmhwZDENMNUJoBsdzFng
```

### Search a file or folder (recursively)

```python
folder = await m.search('my_mega_folder')
# Excludes results which are in the Trash folder (i.e. deleted)
folder = await m.search('my_mega_folder', exclude_deleted=True)
```

### Find a file or folder (path match exactly)

```python
file = await m.search('foldel1/folder2/my_file') # None
file = await m.search('foldel1/other_folder2/my_file.') # File()
```

### Upload a file to a destination folder

```python
folders = await m.search('my_mega_folder')
await m.upload('myfile.doc', folders[0])
```

### Download a file from URL or file obj, optionally specify destination folder

```python
file = await m.find('myfile.doc')
await m.download(file, progress_bar = True)
await m.download_url('https://mega.co.nz/#!utYjgSTQ!OM4U3V5v_W4N5edSo0wolg1D5H0fwSrLD3oLnLuS9pc')
await m.download(file, '/home/john-smith/Desktop')
# specify optional download filename (download_url() supports this also)
await m.download(file, '/home/john-smith/Desktop', 'myfile.zip')
```

### Download a public folder

```python
await m.download_folder_url('https://mega.co.nz/#F!utYjgSTQ!OM4U3V5v_W4N5edSo0wolg1D5H0fwSrLD3oLnLuS9pc')

```

### Import a file from URL, optionally specify destination folder

```python
await m.import_public_url('https://mega.co.nz/#!utYjgSTQ!OM4U3V5v_W4N5edSo0wolg1D5H0fwSrLD3oLnLuS9pc')
folder = await m.search('Documents')
await m.import_public_url('https://mega.co.nz/#!utYjgSTQ!OM4U3V5v_W4N5edSo0wolg1D5H0fwSrLD3oLnLuS9pc', dest_node=folder)
```

### Create a folder

```python
await m.create_folder('new_folder')
await m.create_folder('new_folder/sub_folder/subsub_folder')
```


### Rename a file or a folder

```python
file = await m.find('folder1/myfile.doc')
await m.rename(file, 'my_file.doc')
```
