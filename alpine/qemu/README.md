# Setup

From this directory within host:

```
$ make setup
```

From within guest:

```
localhost login: root
...
localhost:~# export BOOTFS=ext2
localhost:~# export ROOTFS=ext3
localhost:~# setup-alpine
...
New password: ????????
Retype password: ????????
...
Which disk(s) would you like to use? (or '?' for help or 'none') [none] sda
...
How would you like to use it? ('sys', 'data', 'lvm' or '?' for help) [?]
...
WARNING: Erase the above disk(s) and continue? (y/n) [n] y
...
Add 'nomodeset' right after 'quiet' in the edited files below:
...
localhost:~# ( mkdir /boot; mount /dev/sda1 /boot; mount /dev/sda3 /mnt )
localhost:~# vi /mnt/etc/update-extlinux.conf /boot/extlinux.conf
localhost:~# ( umount /mnt; umount /boot; sync; poweroff )
```
# Booting:

$ make boot

# Installing GCC:

```
# apk add build-base
```

# References

```
https://wiki.alpinelinux.org/wiki/Qemu
```
