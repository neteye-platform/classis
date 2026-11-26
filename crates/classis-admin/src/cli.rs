//! The command tree of `classis-cli` and what each command prints. Results go
//! to `out` and everything else to `err`.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::client;
use crate::protocol::{Request, Response, DEFAULT_SOCKET};
use crate::render::{self, Os};

#[derive(Parser)]
#[command(
    name = "classis-cli",
    about = "Administer the Spaces of a running Classis Server",
    // Never clap's default, which reports the static crate version.
    version = classis_core::version::current()
)]
struct Cli {
    /// The Server's admin socket.
    #[arg(long, value_name = "PATH", default_value = DEFAULT_SOCKET)]
    socket: PathBuf,
    #[command(subcommand)]
    tree: Tree,
}

#[derive(Subcommand)]
enum Tree {
    /// Commands on Spaces.
    #[command(subcommand)]
    Space(SpaceCommand),
    /// Print the command that installs the Client on a host and enrols it into a Space.
    EnrolCommand {
        /// The Space the host joins.
        #[arg(long, value_name = "NAME")]
        space: String,
        /// The operating system of the host.
        #[arg(long)]
        os: OsArg,
        /// Print the Space's key alone on the line before the command.
        #[arg(long)]
        with_key: bool,
    },
}

#[derive(Subcommand)]
enum SpaceCommand {
    /// Create a Space and print its enrolment key.
    Create {
        /// The Space's name.
        name: String,
    },
    /// Print the names of the Spaces.
    List,
    /// Replace a Space's enrolment key and print the new one.
    RotateKey {
        /// The Space's name.
        name: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum OsArg {
    Linux,
    Windows,
}

impl From<OsArg> for Os {
    fn from(os: OsArg) -> Self {
        match os {
            OsArg::Linux => Os::Linux,
            OsArg::Windows => Os::Windows,
        }
    }
}

/// What a command prints when the Server answers it.
enum Shows {
    Key,
    Names,
    Install { os: Os, with_key: bool },
}

/// Runs the command `args` name, as `std::env::args_os()` would give them, and returns the exit
/// code.
pub fn run<I, T>(args: I, out: &mut dyn Write, err: &mut dyn Write) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(e) => {
            if e.use_stderr() {
                let _ = write!(err, "{e}");
                return 2;
            }
            let _ = write!(out, "{e}");
            return 0;
        }
    };
    let (request, shows) = match cli.tree {
        Tree::Space(SpaceCommand::Create { name }) => (Request::SpaceCreate { name }, Shows::Key),
        Tree::Space(SpaceCommand::List) => (Request::SpaceList, Shows::Names),
        Tree::Space(SpaceCommand::RotateKey { name }) => {
            (Request::SpaceRotateKey { name }, Shows::Key)
        }
        Tree::EnrolCommand {
            space,
            os,
            with_key,
        } => (
            Request::EnrolCommand { space },
            Shows::Install {
                os: os.into(),
                with_key,
            },
        ),
    };
    let response = match client::request(&cli.socket, &request) {
        Ok(response) => response,
        Err(e) if e.kind() == io::ErrorKind::InvalidData => {
            let _ = writeln!(
                err,
                "classis-cli: the Server's answer is not understood: {e}"
            );
            return 1;
        }
        Err(e) => {
            let _ = writeln!(
                err,
                "classis-cli: cannot reach the Server at {}: {e}",
                cli.socket.display()
            );
            return 1;
        }
    };
    let shown = match (shows, response) {
        (_, Response::Refused { message }) => {
            let _ = writeln!(err, "classis-cli: {message}");
            return 1;
        }
        (Shows::Key, Response::Key { key }) => writeln!(out, "{key}"),
        (Shows::Names, Response::Names { names }) => {
            names.iter().try_for_each(|name| writeln!(out, "{name}"))
        }
        (Shows::Install { os, with_key }, Response::Enrol { endpoint, key }) => {
            let command = render::install_command(&endpoint, &key, os);
            if with_key {
                writeln!(out, "{key}").and_then(|()| writeln!(out, "{command}"))
            } else {
                writeln!(out, "{command}")
            }
        }
        _ => {
            let _ = writeln!(err, "classis-cli: the Server gave an unexpected answer");
            return 1;
        }
    };
    match shown {
        Ok(()) => 0,
        Err(e) => {
            let _ = writeln!(err, "classis-cli: cannot write the result: {e}");
            1
        }
    }
}
