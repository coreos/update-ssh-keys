// Copyright 2017 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! update-ssh-keys library
//!
//! this library is meant to replace github.com/coreos/update-ssh-keys
//! it will provide the functionality for:
//! * listing authorized keys
//! * adding authorized keys
//! * removing an authorized key by name
//! * disabling an authorized key by name
//!
//! the library will take care of the file locking that is expected from users
//! of the authorized_keys.d directory.

#[macro_use]
extern crate error_chain;
extern crate fs2;
extern crate openssh_keys;
extern crate users;

#[allow(unused_doc_comment)]
pub mod errors {
    error_chain!{
        foreign_links {
            Io(::std::io::Error);
        }
        errors {
            KeysDisabled(name: String) {
                description("keys are disabled")
                display("keys with name '{}' are disabled", name)
            }
            KeysExist(name: String) {
                description("keys already exist")
                display("keys with name '{}' already exist", name)
            }
        }
    }
}

use errors::*;
use users::{User, switch};
use users::os::unix::UserExt;
use openssh_keys::PublicKey;
use std::fs::{File, self};
use fs2::FileExt;
use std::path::{Path, PathBuf};
use std::io::{BufReader, BufRead, Read, Write};
use std::collections::HashMap;

const SSH_DIR: &'static str = ".ssh";
const AUTHORIZED_KEYS_DIR: &'static str = "authorized_keys.d";
const AUTHORIZED_KEYS_FILE: &'static str = "authorized_keys";
const PRESERVED_KEYS_FILE: &'static str = "orig_authorized_keys";
const LOCK_FILE: &'static str = ".authorized_keys.d.lock";
const STAGE_FILE: &'static str = ".authorized_keys.d.stage_file";
const STAGE_DIR: &'static str = ".authorized_keys.d.stage_dir";

fn lock_file(user: &User) -> PathBuf {
    user.home_dir().join(LOCK_FILE)
}

fn ssh_dir(user: &User) -> PathBuf {
    user.home_dir().join(SSH_DIR)
}

fn authorized_keys_dir(user: &User) -> PathBuf {
    ssh_dir(user).join(AUTHORIZED_KEYS_DIR)
}

fn authorized_keys_file(user: &User) -> PathBuf {
    ssh_dir(user).join(AUTHORIZED_KEYS_FILE)
}

fn stage_dir(user: &User) -> PathBuf {
    ssh_dir(user).join(STAGE_DIR)
}

fn stage_file(user: &User) -> PathBuf {
    ssh_dir(user).join(STAGE_FILE)
}

fn switch_user(user: &User) -> Result<switch::SwitchUserGuard> {
    switch::switch_user_group(user.uid(), user.primary_group_id())
        .chain_err(|| format!("failed to switch to user '{}' with uid '{}'", user.name(), user.uid()))
}

#[derive(Debug)]
struct FileLock {
    pub lock: File,
}

impl Drop for FileLock {
    fn drop(&mut self) {
        self.unlock().unwrap();
    }
}

impl FileLock {
    fn new(path: &Path) -> Result<Self> {
        Ok(FileLock {
            lock: File::create(path)
                .chain_err(|| format!("failed to create lock file: {:?}", path))?,
        })
    }

    fn lock(&self) -> Result<()> {
        self.lock.lock_exclusive()
            .chain_err(|| "failed to lock file")
    }

    fn unlock(&self) -> Result<()> {
        self.lock.unlock()
            .chain_err(|| "failed to unlock file")
    }
}

#[derive(Debug)]
pub struct AuthorizedKeys {
    pub file: PathBuf,
    pub folder: PathBuf,
    pub keys: HashMap<String, AuthorizedKeySet>,
    pub user: User,
    lock: FileLock,
}

impl Drop for AuthorizedKeys {
    fn drop(&mut self) {}
}

#[derive(Clone, Debug)]
pub struct AuthorizedKeySet {
    pub filename: String,
    pub disabled: bool,
    pub keys: Vec<PublicKey>,
}

impl AuthorizedKeys {
    /// write writes all authorized_keys.d changes onto disk. it writes the
    /// current state to a staging directory and then moves that staging
    /// directory to the authorized_keys.d path.
    pub fn write(&self) -> Result<()> {
        // switch users
        let _guard = switch_user(&self.user)?;

        // get our staging directory
        let stage_dir = stage_dir(&self.user);
        if stage_dir.exists() {
            fs::remove_dir_all(&stage_dir)
                .chain_err(|| format!("failed to remove staging directory '{:?}'", stage_dir))?;
        }
        fs::create_dir(&stage_dir)
            .chain_err(|| format!("failed to create staging directory '{:?}'", stage_dir))?;

        // write all the keys to the staging directory
        for (_, keyset) in &self.keys {
            let keyfilename = stage_dir.join(&keyset.filename);
            let mut keyfile = File::create(&keyfilename)
                .chain_err(|| format!("failed to create file '{:?}'", keyfilename))?;
            // if the keyset is disabled, skip it. we still want to have a
            // zero-sized file with it's name though to signal that it's
            // disabled.
            if keyset.disabled {
                continue
            }
            for key in &keyset.keys {
                write!(keyfile, "{}\n", key)
                    .chain_err(|| format!("failed to write to file '{:?}'", keyfilename))?;
            }
        }

        // destroy the old authorized keys directory and move the staging one to
        // that location. rename expects an existing, empty directory
        fs::remove_dir_all(&self.folder)
            .chain_err(|| format!("failed to remove directory '{:?}'", stage_dir))?;
        fs::create_dir(&self.folder)
            .chain_err(|| format!("failed to create directory '{:?}'", stage_dir))?;
        fs::rename(&stage_dir, &self.folder)
            .chain_err(|| format!("failed to move '{:?}' to '{:?}'", stage_dir, self.folder))
    }

    /// sync writes all the keys we have to authorized_keys. it writes the
    /// current state to a staging file and then moves that staging file to the
    /// authorized_keys path
    pub fn sync(&self) -> Result<()> {
        // switch users
        let _guard = switch_user(&self.user)?;

        // get our staging directory
        let stage_filename = stage_file(&self.user);
        let mut stage_file = File::create(&stage_filename)
            .chain_err(|| format!("failed to create or truncate staging file '{:?}'", stage_filename))?;

        // write all the keys to the staging file
        for (_, keyset) in &self.keys {
            // if the keyset is disabled, skip it
            if keyset.disabled {
                continue
            }
            for key in &keyset.keys {
                write!(stage_file, "{}\n", key)
                    .chain_err(|| format!("failed to write to file '{:?}'", stage_filename))?;
            }
        }

        // destroy the old authorized keys file and move the staging one to that
        // location
        fs::rename(&stage_filename, &self.file)
            .chain_err(|| format!("failed to move '{:?}' to '{:?}'", stage_filename, self.file))
    }

    /// read_all_keys reads all of the authorized keys files in a given
    /// directory. it returns an error if there is a nested directory, if any
    /// file operations fail, or if it can't parse any of the authorized_keys
    /// files
    fn read_all_keys(dir: &Path) -> Result<HashMap<String, AuthorizedKeySet>> {
        let dir_contents = fs::read_dir(&dir)
            .chain_err(|| format!("failed to read from directory {:?}", dir))?;
        let mut keys = HashMap::new();
        for entry in dir_contents {
            let entry = entry.chain_err(|| format!("failed to read entry in directory {:?}", dir))?;
            let path = entry.path();
            if path.is_dir() {
                // if it's a directory, we don't know what to do
                return Err(format!("'{:?}' is a directory", path).into());
            } else {
                let name = path.file_name()
                    .ok_or_else(|| format!("failed to get filename for '{:?}'", path))?
                    .to_str()
                    .ok_or_else(|| format!("failed to convert filename '{:?}' to string", path))?;
                let from = File::open(&path)
                    .chain_err(|| format!("failed to open file {:?}", path))?;
                let keyset = AuthorizedKeys::read_keys(from)?;
                keys.insert(name.to_string(), AuthorizedKeySet {
                    filename: name.to_string(),
                    disabled: keyset.is_empty(),
                    keys: keyset,
                });
            }
        }
        Ok(keys)
    }

    /// read_keys reads a list of public keys from a reader. it returns an error
    /// of it can't read or parse any of the public keys in the list.
    pub fn read_keys<R>(r: R) -> Result<Vec<PublicKey>>
        where R: Read
    {
        let keybuf = BufReader::new(r);
        // authorized_keys files are newline-separated lists of public keys
        let mut keys = vec![];
        for key in keybuf.lines() {
            let key = key.chain_err(|| "failed to read public key")?;
            // skip any empty lines and any comment lines (prefixed with '#')
            if !key.is_empty() && !(key.trim().starts_with('#')) {
                keys.push(PublicKey::parse(&key)
                          .chain_err(|| "failed to parse public key")?);
            }
        }
        Ok(keys)
    }

    /// open creates a new authorized_keys object. if there is an existing
    /// authorized_keys directory on disk it reads all the keys from that. if
    /// there is no directory already and we are told to create it, we add the
    /// existing authorized keys file as an entry, if it exists.
    /// /// before open actually does any of that, it switches it's uid for the span
    /// of the function and then switched back. it also opens a file lock on the
    /// directory that other instances of `update-ssh-keys` will respect. the
    /// file lock will automatically close when this structure goes out of
    /// scope. you can make sure it is unlocked by calling `drop` yourself in
    /// cases where you think the memory may leak (like if you are tossing boxes
    /// around etc).
    ///
    /// open blocks until it can grab the file lock.
    ///
    /// open returns an error if any file operations fail, if it failes to parse
    /// any of the public keys in the existing files, if it failes to change
    /// users, if it failes to grab the lock, or if create is false but the
    /// directory doesn't exist.
    pub fn open(user: User, create: bool) -> Result<Self> {
        // switch users
        let _guard = switch_user(&user)?;
        // make a new file lock and lock it
        let lock = FileLock::new(&lock_file(&user))?;
        lock.lock()?;

        let akd = authorized_keys_dir(&user);

        let keys = if akd.is_dir() {
            // read the existing keysets from the dir
            AuthorizedKeys::read_all_keys(&akd)?
        } else if !akd.exists() && create {
            // read the existing keyset from the file
            let filename = authorized_keys_file(&user);
            if filename.exists() {
                let file = File::open(&filename)
                    .chain_err(|| format!("failed to open authorized keys file: '{:?}'", filename))?;
                let mut keys = HashMap::new();
                keys.insert(PRESERVED_KEYS_FILE.to_string(), AuthorizedKeySet {
                    filename: PRESERVED_KEYS_FILE.to_string(),
                    disabled: false,
                    keys: AuthorizedKeys::read_keys(file)?,
                });
                keys
            } else {
                // if the authorized_keys file doesn't exist, we don't start
                // with any keys
                HashMap::new()
            }
        } else {
            // either the akd doesn't exist and create is false, or it exists
            // and is not a directory
            return Err(format!("'{:?}' doesn't exist or is not a directory", akd).into())
        };

        Ok(AuthorizedKeys {
            file: authorized_keys_file(&user),
            folder: akd,
            user: user,
            keys: keys,
            lock: lock,
        })
    }

    /// get_keys gets the authorized keyset with the provided name
    pub fn get_keys(&self, name: &str) -> Option<&AuthorizedKeySet> {
        self.keys.get(name)
    }

    /// get_all_keys returns the hashmap from name to keyset containing all the
    /// keys we know about
    pub fn get_all_keys(&self) -> &HashMap<String, AuthorizedKeySet> {
        &self.keys
    }

    /// add_keys adds a list of public keys with the provide name. if replace is
    /// true, it will replace existing keys. if force is true, it will replace
    /// disabled keys.
    ///
    /// add_keys returns an error if the key already exists and replace is
    /// false, or if the key is disabled and force is false
    pub fn add_keys(&mut self, name: &str, keys: Vec<PublicKey>, replace: bool, force: bool) -> Result<()> {
        if let Some(keyset) = self.keys.get(name) {
            if keyset.disabled && !force {
                return Err(ErrorKind::KeysDisabled(name.to_string()).into());
            } else if !replace {
                return Err(ErrorKind::KeysExist(name.to_string()).into());
            }
        }
        self.keys.insert(name.to_string(), AuthorizedKeySet {
            filename: name.to_string(),
            disabled: false,
            keys: keys,
        });
        Ok(())
    }

    /// remove_keys removes the keyset with the given name.
    pub fn remove_keys(&mut self, name: &str) {
        self.keys.remove(name);
    }

    /// disable_keys disables keys with the given name. they can't be added
    /// again unless force is set to true when adding the set. disable_keys will
    /// succeed in disabling the key even if the key doesn't currently exist.
    pub fn disable_keys(&mut self, name: &str) {
        if let Some(keyset) = self.keys.get_mut(name) {
            keyset.disabled = true;
            return;
        }
        self.keys.insert(name.to_string(), AuthorizedKeySet {
            filename: name.to_string(),
            disabled: true,
            keys: vec![],
        });
    }
}
