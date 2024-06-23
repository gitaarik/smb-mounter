Write a python program that can mount SMB shares to a local directory like a
regular filesystem using FUSE. Make sure you can read and write to the SMB
share. The SMB shares are defined in a config.ini file with this format:

```
[myshare]
mount_path = /home/myuser/SmbMount
smb_server = nas.my-domain.com
smb_share = SmbShare
smb_username = myuser

[myshare2]
mount_path = /home/myuser/SmbMount2
smb_server = nas.my-domain2.com
smb_share = SmbShare2
smb_username = myuser2
```

The arguments parsed by the program are as followed:

```python
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
```

The `-l` option should, for the `config.ini` in our case, output:

```
myshare
    mount_path:    /home/myuser/SmbMount
    smb_server:    nas.my-domain.com
    smb_share:     SmbShare
    smb_username:  myuser

myshare2
    mount_path:    /home/myuser/SmbMount2
    smb_server:    nas.my-domain2.com
    smb_share:     SmbShare2
    smb_username:  myuser2
```

When you execute:

```sh
./smb-mount.py -m myshare
```

It should mount the share `myshare` in interactive CLI mode. You can then stop
the program with Ctrl + C and then the mount disappears.

If the SMB share is not reachable, the program should exit with an appropriate
error message.

If the SMB share requires a password, the program should prompt the user for a
password. Then the password should be verified by trying to list the root of
the share. If the password is correct, it should be saved in GNOME Keyring, and
retrieved from GNOME Keyring the next time the share is being mounted, so the
user is not prompted for a password again.

If the password is incorrect, the user should be prompted again until the
password is correct. The user can abort the process with Ctrl + C.

When you execute:

```sh
./smb-mount.py -f myshare
```

It should remove the previously saved password for the `myshare` share from
GNOME Keyring.
