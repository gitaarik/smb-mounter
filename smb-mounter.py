#!/usr/bin/env python3

import os
import stat
import errno
import asyncio
import argparse
import configparser
from getpass import getpass

from fuse import FUSE, FuseOSError, Operations
from smb.SMBConnection import SMBConnection
import secretstorage
import gi

gi.require_version("Secret", "1")
from gi.repository import Secret


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
        mount(args, config)


class SMBMount(Operations):

    def __init__(self, server, share, username, password):

        self.server = server
        self.share = share
        self.username = username
        self.password = password
        self.conn = SMBConnection(username, password, "python", server)

        if not self.conn.connect(server, 139):
            raise Exception("Failed to connect to SMB server")

        try:
            self.readdir("/")
        except Exception:
            raise Exception("Auth failed")

    def getattr(self, path, fh=None):
        try:
            if path == "/":
                st = os.stat(".")
                return {
                    key: getattr(st, key)
                    for key in (
                        "st_atime",
                        "st_ctime",
                        "st_gid",
                        "st_mode",
                        "st_mtime",
                        "st_nlink",
                        "st_size",
                        "st_uid",
                    )
                }

            file_info = self.conn.getAttributes(self.share, path[1:])
            return {
                "st_atime": int(file_info.last_access_time),
                "st_mtime": int(file_info.last_write_time),
                "st_ctime": int(file_info.create_time),
                "st_mode": (
                    stat.S_IFDIR | 0o755
                    if file_info.isDirectory
                    else stat.S_IFREG | 0o644
                ),
                "st_nlink": 2 if file_info.isDirectory else 1,
                "st_size": file_info.file_size,
                "st_uid": 0,
                "st_gid": 0,
            }
        except Exception:
            raise FuseOSError(errno.ENOENT)

    def readdir(self, path, fh=None):

        dirents = [".", ".."]

        if path == "/":
            path = ""
        else:
            path = path[1:]

        for entry in self.conn.listPath(self.share, path):
            if entry.filename not in [".", ".."]:
                dirents.append(entry.filename)

        return dirents

    def read(self, path, size, offset, fh=None):
        file_obj = self.conn.retrieveFile(self.share, path[1:])
        file_obj.seek(offset)
        return file_obj.read(size)


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


def mount(args, config):

    if args.mount not in config:
        print(f"Share {args.mount} not found in config.")
        return

    share_config = config[args.mount]
    mount_path = share_config["mount_path"]
    smb_server = share_config["smb_server"]
    smb_share = share_config["smb_share"]
    smb_username = share_config["smb_username"]

    # Try to get password from GNOME Keyring
    password = get_password_from_keyring(smb_server, smb_share, smb_username)
    store_new_pass = False
    success = False

    while not success:

        if password is None:
            # If password is not in keyring, prompt for it
            try:
                password = getpass("Enter SMB password: ")
            except KeyboardInterrupt:
                print()
                sys.exit()

            store_new_pass = True

        try:
            mount_smb(mount_path, smb_server, smb_share, smb_username, password)
            success = True
        except Exception as e:
            print(f"Error: {e}")
            password = None

    if success and store_new_pass:
        # Store the password in GNOME Keyring
        print("Password has been stored in GNOME Keyring.")
        store_password_in_keyring(smb_server, smb_share, smb_username, password)


def mount_smb(mountpoint, server, share, username, password):
    FUSE(
        SMBMount(server, share, username, password),
        mountpoint,
        nothreads=True,
        foreground=True,
    )


def get_password_from_keyring(server, share, username):
    # collection = Secret.Collection.for_alias_sync(
    #     Secret.COLLECTION_DEFAULT, Secret.COLLECTION_DEFAULT, None
    # )
    schema = Secret.Schema.new(
        "org.example.SMBMount",
        Secret.SchemaFlags.NONE,
        {
            "server": Secret.SchemaAttributeType.STRING,
            "share": Secret.SchemaAttributeType.STRING,
            "username": Secret.SchemaAttributeType.STRING,
        },
    )
    attributes = {"server": server, "share": share, "username": username}
    password = Secret.password_lookup_sync(schema, attributes, None)
    return password


def store_password_in_keyring(server, share, username, password):
    schema = Secret.Schema.new(
        "org.example.SMBMount",
        Secret.SchemaFlags.NONE,
        {
            "server": Secret.SchemaAttributeType.STRING,
            "share": Secret.SchemaAttributeType.STRING,
            "username": Secret.SchemaAttributeType.STRING,
        },
    )
    attributes = {"server": server, "share": share, "username": username}
    Secret.password_store_sync(
        schema,
        attributes,
        Secret.COLLECTION_DEFAULT,
        f"SMB Mount Password for {server}/{share}",
        password,
        None,
    )


if __name__ == "__main__":
    asyncio.run(main())
