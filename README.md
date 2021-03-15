# update-ssh-keys

![minimum rust 1.43](https://img.shields.io/badge/rust-1.43%2B-orange.svg)

## ⚠ This crate is deprecated and unmaintained ⚠

`update-ssh-keys` is no longer maintained; the recommended replacement is
[ssh-key-dir](https://github.com/coreos/ssh-key-dir).

`update-ssh-keys` implements `authorized_keys.d` by providing a program and
library to merge keys from `authorized_keys.d/*` into `authorized_keys` so
`sshd` can find them.  This manual process can cause confusion if the
directory gets out of sync with the `authorized_keys` file.

ssh-key-dir solves this problem by providing a helper program that `sshd`
can run at authentication time to read `authorized_keys.d` files directly.
In this model, `authorized_keys` is simply an additional source of keys, and
no longer needs to be kept in sync.

## About `update-ssh-keys`

`update-ssh-keys` is a command line tool and a library for managing openssh
authorized public keys. It keeps track of sets of keys with names, allows for
adding additional keys, as well as deleting and disabling them. For usage
information, see `update-ssh-keys -h` or run `cargo doc` to read the
documentation on the library api. 

The `update-ssh-keys` command line tool is included in Container Linux, so there
should be no reason to install it. If you would like to use this on a
non-Container Linux machine, you can build the project with `cargo build
--release`. The rust toolchain is required to build it. You can install `rustup`
to manage your rust toolchain - https://www.rustup.rs. 

`test/test_update_ssh_keys.py` is a python script which tests the functionality
of the `update-ssh-keys` command line tool. If changes are made to
`update-ssh-keys`, that script should be run.
