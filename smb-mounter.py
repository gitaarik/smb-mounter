#!/usr/bin/env python3

import os
import stat
import asyncio
import argparse
import configparser
from getpass import getpass
# import pyfuse3
from fuse import FUSE, FuseOSError, Operations
from smb.SMBConnection import SMBConnection
import smbclient
import smbprotocol
import secretstorage.exceptions


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

# class SmbFS(pyfuse3.Operations):
#     def __init__(self, smb_server, smb_share, smb_username, smb_password):
#         super().__init__()
#         self.smb_url = f"\\\\{smb_server}\\{smb_share}"
#         self.smb_username = smb_username
#         self.smb_password = smb_password
#         smbclient.ClientConfig(username=smb_username, password=smb_password)
#
#     async def init(self):
#         # No need for explicit connection with smbclient
#         pass
#
#     async def lookup(self, parent_inode, name, ctx=None):
#         path = os.path.join(str(parent_inode), name)
#         attrs = smbclient.stat(f"{self.smb_url}\\{path}")
#         return self._getattr(attrs)
#
#     async def getattr(self, inode, ctx=None):
#         if inode == pyfuse3.ROOT_INODE:
#             return {"st_mode": (stat.S_IFDIR | 0o755), "st_nlink": 2}
#         path = str(inode)
#         attrs = smbclient.stat(f"{self.smb_url}\\{path}")
#         return self._getattr(attrs)
#
#     def _getattr(self, attrs):
#         mode = stat.S_IFREG | 0o644
#         if stat.S_ISDIR(attrs.st_mode):
#             mode = stat.S_IFDIR | 0o755
#         return {
#             "st_mode": mode,
#             "st_nlink": 1,
#             "st_size": attrs.st_size,
#             "st_ctime": attrs.st_ctime,
#             "st_mtime": attrs.st_mtime,
#             "st_atime": attrs.st_atime,
#         }
#
#     async def read(self, inode, off, size):
#         path = str(inode)
#         with smbclient.open_file(f"{self.smb_url}\\{path}", mode="rb") as f:
#             f.seek(off)
#             return f.read(size)
#
#     async def write(self, inode, off, buf):
#         path = str(inode)
#         with smbclient.open_file(f"{self.smb_url}\\{path}", mode="r+b") as f:
#             f.seek(off)
#             return f.write(buf)


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


def mount_smb(mountpoint, server, share, username, password):
    FUSE(
        SMBMount(server, share, username, password),
        mountpoint,
        nothreads=True,
        foreground=True,
    )

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
                password = getpass(f"Enter password for {args.mount}: ")
                # Try to connect and list root directory
                smbclient.ClientConfig(username=smb_username, password=password)

                try:
                    smbclient.listdir(f"\\\\{smb_server}\\{smb_share}")
                except smbprotocol.exceptions.LogonFailure as error:
                    print("Authentication error:")
                    print(error)
                    continue
                except Exception as error:
                    print("Unknown error:")
                    print(error)
                    continue

                # If we get here, the password is correct
                remember_password = "no_save_pass" not in share_config or share_config[
                    "no_save_pass"
                ] in ["false", "no"]

                if remember_password:
                    save_password(args.mount, password)

                break

        # fs = SmbFS(smb_server, smb_share, smb_username, password)
        # fuse_options = set(pyfuse3.default_options)
        # fuse_options.add("fsname=smbfs")
        #
        # print(fs, mount_path, fuse_options)
        #
        # print('hello')
        # await asyncio.sleep(1)
        # print('world')
        #
        # pyfuse3.init(fs, mount_path, fuse_options)
        # await pyfuse3.main()

        # try:
        #     await pyfuse3.main()
        # except KeyboardInterrupt:
        #     print("Keyboard interrupt")
        #     sys.exit()
        # finally:
        #     pyfuse3.close()


if __name__ == "__main__":
    asyncio.run(main())
