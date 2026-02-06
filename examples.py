# ruff: noqa: T201
import asyncio
import os
import uuid

from mega.client import MegaNzClient


async def test():
    """
    Enter your account details to begin
    comment/uncomment lines to test various parts of the API
    see readme.md for more information
    """
    unique = str(uuid.uuid4())
    # user details
    email = os.environ["EMAIL"]
    password = os.environ["PASS"]

    mega = MegaNzClient()
    # mega = Mega({'verbose': True})  # verbose option for print output

    # login
    m = await mega.login(email, password)

    # get user details
    details = await m.get_user()
    print(details)

    # get account files
    files = await m.get_files()

    # get account disk quota in bytes
    quota = await m.get_quota()
    print(f"{quota = }")
    # get account storage space
    storage = await m.get_storage_space()
    print(f"{storage = }")

    # example iterate over files
    for file in files.values():
        print(file)

    # upload file
    print(await m.upload(file_path="examples.py", dest_filename=f"examples_{unique}.py"))

    # search for a file in account
    file = await m.find(f"examples_{unique}.py")

    if file:
        # get public link
        link = await m.get_link(file)
        print(link)

        # download file. by file object or url
        print(await m.download(file, "/tmp"))
        # m.download_url(link)

        # delete or destroy file. by id or url
        print(await m.delete(file["h"]))
        # print(m.destroy(file[0]))
        # print(m.delete_url(link))
        # print(m.destroy_url(link))

    # empty trash
    print(await m.empty_trash())


if __name__ == "__main__":
    asyncio.run(test())
