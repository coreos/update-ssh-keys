# update-ssh-keys

[![Build Status](https://travis-ci.org/coreos/update-ssh-keys.svg?branch=master)](https://travis-ci.org/coreos/update-ssh-keys)
![minimum rust 1.31](https://img.shields.io/badge/rust-1.31%2B-orange.svg)

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
