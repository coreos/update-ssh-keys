# `update-ssh-keys`

`update-ssh-keys` fulfills two purposes. One, it is a library which performs the
same function as the `authorized_keys_d` library in
`github.com/coreos/update-ssh-keys`, except for rust instead. Two, it aims to
replace the shell script called `update-ssh-keys` which exists in Container
Linux currently with a rust binary that respects the lock files. It needs to
play nice with the existing go implementation, which is currently used in
ignition and the golang coreos-metadata.
