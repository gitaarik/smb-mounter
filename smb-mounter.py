#!/usr/bin/env python3

import argparse
import configparser
import os
import sys
import uuid
import asyncio
import pyfuse3
import errno
import stat
from getpass import getpass
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import (
    CreateDisposition,
    CreateOptions,
    FileAttributes,
    FilePipePrinterAccessMask,
    ImpersonationLevel,
    Open,
    ShareAccess,
)
from smbprotocol.exceptions import SMBException, LogonFailure
import secretstorage


class SmbFS(pyfuse3.Operations):
    def __init__(self, smb_server, smb_share, smb_username, smb_password):
        super().__init__()
        self.smb_server = smb_server
        self.smb_share = smb_share
        self.smb_username = smb_username
        self.smb_password = smb_password
        self.connection = None
        self.session = None
        self.tree = None

    async def init(self):
        self.connection = Connection(uuid.uuid4(), self.smb_server, 445)
        self.connection.connect()
        self.session = Session(self.connection, self.smb_username, self.smb_password)
        self.session.connect()
        self.tree = TreeConnect(self.session, self.smb_share)
        self.tree.connect()

    def open_path(self, path):

        class OpenContextManager:

            def __init__(self, tree, path):
                self.tree = tree
                self.path = path
                self.file_obj = None

            def __enter__(self):
                self.file_obj = Open(self.tree, self.path)
                self.file_obj.create(
                    ImpersonationLevel.Impersonation,
                    FilePipePrinterAccessMask.GENERIC_READ
                    | FilePipePrinterAccessMask.GENERIC_WRITE,
                    FileAttributes.FILE_ATTRIBUTE_NORMAL,
                    ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                    CreateDisposition.FILE_OVERWRITE_IF,
                    CreateOptions.FILE_NON_DIRECTORY_FILE,
                )
                return self.file_obj

            def __exit__(self, exc_type, exc_value, traceback):
                if exc_type is not None:
                    print(
                        f"An exception of type {exc_type} occurred with value {exc_value}"
                    )

                self.file_obj.close()

        return OpenContextManager(self.tree, path)

    async def lookup(self, parent_inode, name, ctx=None):
        path = os.path.join(str(parent_inode), name)
        with self.open_path(path) as file_obj:
            attrs = file_obj.get_attributes()
        return self._getattr(attrs)

        try:
            file_obj = Open(self.tree, path)
            file_obj.create(ImpersonationLevel.Impersonation)
            attrs = file_obj.get_attributes()
            file_obj.close()
            return self._getattr(attrs)
        except SMBException:
            raise pyfuse3.FUSEError(errno.ENOENT)

    async def getattr(self, inode, ctx=None):
        if inode == pyfuse3.ROOT_INODE:
            return {"st_mode": (stat.S_IFDIR | 0o755), "st_nlink": 2}
        path = str(inode)

        with self.open_path(path) as file_obj:
            attrs = file_obj.get_attributes()

        return self._getattr(attrs)

        try:
            file_obj = Open(self.tree, path)
            file_obj.create(ImpersonationLevel.Impersonation)
            attrs = file_obj.get_attributes()
            file_obj.close()
            return self._getattr(attrs)
        except SMBException:
            raise pyfuse3.FUSEError(errno.ENOENT)

    def _getattr(self, attrs):
        mode = stat.S_IFREG | 0o644
        if attrs["file_attributes"] & 0x10:  # Directory
            mode = stat.S_IFDIR | 0o755
        return {
            "st_mode": mode,
            "st_nlink": 1,
            "st_size": attrs["end_of_file"],
            "st_ctime": attrs["creation_time"].timestamp(),
            "st_mtime": attrs["last_write_time"].timestamp(),
            "st_atime": attrs["last_access_time"].timestamp(),
        }

    async def read(self, inode, off, size):
        path = str(inode)

        with self.open_path(path) as file_obj:
            data = file_obj.read(off, size)

        return data

        try:
            file_obj = Open(self.tree, path)
            file_obj.create(
                ImpersonationLevel.Impersonation, desired_access=0x80000000
            )  # FILE_READ_DATA
            data = file_obj.read(off, size)
            file_obj.close()
            return data
        except SMBException:
            raise pyfuse3.FUSEError(errno.EIO)

    async def write(self, inode, off, buf):
        path = str(inode)

        with self.open_path(path) as file_obj:
            bytes_written = file_obj.write(buf, off)

        return bytes_written

        try:
            file_obj = Open(self.tree, path)
            file_obj.create(
                ImpersonationLevel.Impersonation, desired_access=0x40000000
            )  # FILE_WRITE_DATA
            bytes_written = file_obj.write(buf, off)
            file_obj.close()
            return bytes_written
        except SMBException:
            raise pyfuse3.FUSEError(errno.EIO)


def read_config():
    config = configparser.ConfigParser()
    config.read("config.ini")
    return config


def list_shares(config):
    for section in config.sections():
        print(f"{section}")
        for key, value in config[section].items():
            print(f"    {key}:    {value}")
        print()


def get_password(share_name):
    conn = secretstorage.dbus_init()
    collection = secretstorage.get_default_collection(conn)
    for item in collection.get_all_items():
        if item.get_label() == f"SMB Mount {share_name}":
            return item.get_secret().decode("utf-8")
    return None


def save_password(share_name, password):
    conn = secretstorage.dbus_init()
    collection = secretstorage.get_default_collection(conn)
    collection.create_item(
        f"SMB Mount {share_name}", {"share": share_name}, password.encode("utf-8")
    )


def forget_password(share_name):
    conn = secretstorage.dbus_init()
    collection = secretstorage.get_default_collection(conn)
    for item in collection.get_all_items():
        if item.get_label() == f"SMB Mount {share_name}":
            item.delete()
            print(f"Password for {share_name} has been forgotten.")
            return
    print(f"No saved password found for {share_name}.")


async def main():
    parser = argparse.ArgumentParser(
        prog="smb-mounter",
        description="Mounts SMB shares to a local directory like a regular file system",
    )
    parser.add_argument(
        "-l", "--list", action="store_true", help="List all configured SMB shares"
    )
    parser.add_argument("-m", "--mount", help="Mount the given share")
    parser.add_argument(
        "-f", "--forget", help="Forget the password for a previously mounted share"
    )
    args = parser.parse_args()

    config = read_config()

    if args.list:
        list_shares(config)
        return

    if args.forget:
        forget_password(args.forget)
        return

    if args.mount:
        if args.mount not in config:
            print(f"Share {args.mount} not found in config.")
            return

        share_config = config[args.mount]
        mount_path = share_config["mount_path"]
        smb_server = share_config["smb_server"]
        smb_share = share_config["smb_share"]
        smb_username = share_config["smb_username"]

        password = get_password(args.mount)
        if not password:
            while True:
                try:
                    password = getpass(f"Enter password for {args.mount}: ")
                except KeyboardInterrupt:
                    print()
                    sys.exit()

                try:
                    # Try to connect and list root directory
                    conn = Connection(uuid.uuid4(), smb_server, 445)
                    conn.connect()
                    session = Session(conn, smb_username, password)
                    session.connect()
                    tree = TreeConnect(session, smb_share)
                    tree.connect()
                    root = Open(tree, "")
                    root.create(
                        ImpersonationLevel.Impersonation,
                        FilePipePrinterAccessMask.GENERIC_READ
                        | FilePipePrinterAccessMask.GENERIC_WRITE,
                        FileAttributes.FILE_ATTRIBUTE_NORMAL,
                        ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                        CreateDisposition.FILE_OVERWRITE_IF,
                        CreateOptions.FILE_NON_DIRECTORY_FILE,
                    )
                    root.query_directory("*")
                    root.close()
                    tree.disconnect()
                    session.disconnect()
                    conn.disconnect()

                    # If we get here, the password is correct
                    save_password(args.mount, password)
                    break
                except LogonFailure:
                    print("Incorrect password. Please try again.")

        fs = SmbFS(smb_server, smb_share, smb_username, password)
        fuse_options = set(pyfuse3.default_options)
        fuse_options.add("fsname=smbfs")
        pyfuse3.init(fs, mount_path, fuse_options)

        try:
            await pyfuse3.main()
        except KeyboardInterrupt:
            pass
        finally:
            pyfuse3.close()


if __name__ == "__main__":
    asyncio.run(main())
