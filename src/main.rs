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

//! update-ssh-keys
//!
//! this command allows users of container linux to administer ssh keys

#[macro_use]
extern crate clap;
#[macro_use]
extern crate error_chain;
extern crate openssh_keys;
extern crate users;

extern crate update_ssh_keys;

use clap::{Arg, App};
use std::fs::File;
use std::path::PathBuf;
use update_ssh_keys::*;
use update_ssh_keys::errors::*;
use users::get_current_username;

#[derive(Clone, Debug)]
struct Config {
    user: String,
    ssh_dir: Option<PathBuf>,
    command: Command,
}

#[derive(Clone, Debug)]
enum Command {
    Add {
        name: String,
        force: bool,
        replace: bool,
        stdin: bool,
        keyfiles: Vec<String>,
    },
    Delete { name: String },
    Disable { name: String },
    List,
    Sync,
}

quick_main!(run);

fn run() -> Result<()> {
    let config = config()
        .chain_err(|| "command line configuration")?;

    let user = users::get_user_by_name(&config.user)
        .ok_or_else(|| format!("failed to find user with name '{}'", config.user))?;

    let mut aks =  AuthorizedKeys::open(user, true, config.ssh_dir.clone())
        .chain_err(|| format!("failed to open authorized keys directory for user '{}'", config.user))?;

    match config.command {
        Command::Add{name, force, replace, stdin, keyfiles} => {
            let keys = if stdin {
                // read the keys from stdin
                AuthorizedKeys::read_keys(std::io::stdin())?
            } else {
                // keys are in provided files
                let mut keys = vec![];
                for keyfile in keyfiles {
                    let file = File::open(&keyfile)
                        .chain_err(|| format!("failed to open keyfile '{:?}'", keyfile))?;
                    keys.append(&mut AuthorizedKeys::read_keys(file)?);
                }
                keys
            };
            let res = aks.add_keys(&name, keys, replace, force);
            match res {
                Ok(keys) => {
                    println!("Adding/updating {}:", name);
                    for key in &keys {
                        if let AuthorizedKeyEntry::Valid{ref key} = *key {
                            println!("{}", key.to_fingerprint_string());
                        }
                    }
                },
                Err(Error(ErrorKind::KeysDisabled(name), _)) => println!("Skipping add {} for {}, disabled.", name, config.user),
                Err(Error(ErrorKind::KeysExist(_), _)) => println!("Skipping add {} for {}, already exists.", name, config.user),
                _ => {
                    res.chain_err(|| "failed to add keys")?;
                },
            }
        },
        Command::Delete{name} => {
            println!("Removing {}:", name);
            for key in aks.remove_keys(&name) {
                if let AuthorizedKeyEntry::Valid{ref key} = key {
                    println!("{}", key.to_fingerprint_string());
                }
            }
        },
        Command::Disable{name} => {
            println!("Disabling {}:", name);
            for key in aks.disable_keys(&name) {
                if let AuthorizedKeyEntry::Valid{ref key} = key {
                    println!("{}", key.to_fingerprint_string());
                }
            }
        },
        Command::List => {
            let keys = aks.get_all_keys();
            println!("All keys for {}:", config.user);
            for (name, keyset) in keys {
                println!("{}:", name);
                for key in &keyset.keys {
                    if let AuthorizedKeyEntry::Valid{ref key} = *key {
                        println!("{}", key.to_fingerprint_string())
                    }
                }
            }
        },
        Command::Sync => {},
    }

    aks.write()
        .chain_err(|| "failed to update authorized keys directory")?;
    aks.sync()
        .chain_err(|| "failed to update authorized keys")?;

    println!("Updated {:?}", aks.authorized_keys_file());

    Ok(())
}

fn config() -> Result<Config> {
    // get the default user by figuring out the current user if the current user
    // is root (or doesn't exist) then use core
    let default_user = get_current_username().map_or("core".into(), |u| {
        if u == "root" {
            "core".into()
        } else {
            u
        }
    });

    // setup cli
    let matches = App::new("update-ssh-keys")
        .version(crate_version!())
        .help(format!(
r#"Usage: update-ssh-keys [-l] [-u user] [-a name file1... | -d name]
Options:
    -u USER     Update the given user's authorized_keys file [{0}]
    -a NAME     Add the given keys, using the given name to identify them.
    -A NAME     Add the given keys, even if it was disabled with '-D'
    -n          When adding, don't replace an existing key with the given name.
    -d NAME     Delete keys identified by the given name.
    -D NAME     Disable the given set from being added with '-a'
    -l          List the names and number of keys currently installed.
    -h          This ;-)

This tool provides a consistent way for different systems to add ssh public
keys to a given user account, usually the default current user.
If -a, -A, -d, nor -D are provided then the authorized_keys file is simply
regenerated using the existing keys.

With the -a option keys may be provided as files on the command line. If no
files are provided with the -a option the keys will be read from stdin."#, default_user).as_ref())
        .arg(Arg::with_name("user")
             .short("u")
             .help("Update the given user's authorized_keys file.")
             .takes_value(true))
        .arg(Arg::with_name("no-replace")
             .short("n")
             .help("When adding, don't replace an existing key with the given name."))
        .arg(Arg::with_name("list")
             .short("l")
             .help("List the names and number of keys currently installed."))
        .arg(Arg::with_name("add")
             .short("a")
             .help("Add the given keys, using the given name to identify them.")
             .takes_value(true))
        .arg(Arg::with_name("add-force")
             .short("A")
             .help("Add the given keys, even if it was disabled with '-D'.")
             .takes_value(true))
        .arg(Arg::with_name("delete")
             .short("d")
             .help("Delete keys identified by the given name.")
             .takes_value(true))
        .arg(Arg::with_name("disable")
             .short("D")
             .help("Disable the given set from being added with '-a'.")
             .takes_value(true))
        .arg(Arg::with_name("ssh_dir")
             .short("s")
             .long("ssh-dir")
             .takes_value(true)
             .help("location of the ssh configuration directory (defaults to ~/.ssh)"))
        .arg(Arg::with_name("keys")
             .multiple(true))
        .get_matches();

    let command = matches.value_of("add").map(|name| Command::Add{
            name: name.into(),
            force: false,
            replace: !matches.is_present("no-replace"),
            stdin: !matches.is_present("keys"),
            keyfiles: matches.values_of("keys").map(|vals| vals.map(|s| s.into()).collect::<Vec<_>>()).unwrap_or_default(),
        })
        .or_else(|| matches.value_of("add-force").map(|name| Command::Add{
            name: name.into(),
            force: true,
            replace: !matches.is_present("no-replace"),
            stdin: !matches.is_present("keys"),
            keyfiles: matches.values_of("keys").map(|vals| vals.map(|s| s.into()).collect::<Vec<_>>()).unwrap_or_default(),
        }))
        .or_else(|| matches.value_of("delete").map(|name| Command::Delete{name: name.into()}))
        .or_else(|| matches.value_of("disable").map(|name| Command::Disable{name: name.into()}))
        .unwrap_or(if matches.is_present("list") { Command::List } else { Command::Sync });

    let user = matches.value_of("user")
        .map_or(default_user, String::from);

    let ssh_dir = matches.value_of("ssh_dir")
        .map(PathBuf::from);

    Ok(Config {
        user,
        ssh_dir,
        command,
    })
}
