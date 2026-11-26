//! What the end-to-end tests share: an in-memory `Spaces`, the socket server around it, and the
//! real command tree run against it.

// Each test binary uses a part of this module.
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use classis_admin::spaces::{Refusal, Spaces};
use classis_admin::{cli, server};

pub const ENDPOINT: &str = "https://neteye.example/neteye/classis/";

#[derive(Default)]
pub struct Fake(pub Mutex<HashMap<String, String>>);

fn missing(name: &str) -> Refusal {
    Refusal(format!("the space {name} does not exist"))
}

impl Spaces for Fake {
    fn create(&self, name: &str) -> Result<String, Refusal> {
        let mut spaces = self.0.lock().unwrap();
        if spaces.contains_key(name) {
            return Err(Refusal(format!("the space {name} exists already")));
        }
        let key = format!("cle1_{name}_{}", "A".repeat(43));
        spaces.insert(name.to_owned(), key.clone());
        Ok(key)
    }

    fn list(&self) -> Result<Vec<String>, Refusal> {
        let mut names: Vec<String> = self.0.lock().unwrap().keys().cloned().collect();
        names.sort();
        Ok(names)
    }

    fn rotate_key(&self, name: &str) -> Result<String, Refusal> {
        let mut spaces = self.0.lock().unwrap();
        let slot = spaces.get_mut(name).ok_or_else(|| missing(name))?;
        *slot = format!("cle1_{name}_{}", "B".repeat(43));
        Ok(slot.clone())
    }

    fn key(&self, name: &str) -> Result<String, Refusal> {
        self.0
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .ok_or_else(|| missing(name))
    }

    fn endpoint(&self) -> Result<String, Refusal> {
        Ok(ENDPOINT.to_owned())
    }
}

pub struct Outcome {
    pub code: u8,
    pub out: String,
    pub err: String,
}

pub fn start(socket: &Path) -> Arc<Fake> {
    let fake = Arc::new(Fake::default());
    let listener = server::bind(socket).unwrap();
    tokio::spawn(server::serve(listener, fake.clone()));
    fake
}

/// Runs `classis-cli --socket <socket> <args…>` off the async runtime, so the socket server can
/// answer it.
pub async fn run_cli(socket: &Path, args: &[&str]) -> Outcome {
    let mut argv = vec!["classis-cli".to_owned()];
    argv.push("--socket".to_owned());
    argv.push(socket.to_str().unwrap().to_owned());
    argv.extend(args.iter().map(|arg| (*arg).to_owned()));
    tokio::task::spawn_blocking(move || {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = cli::run(argv, &mut out, &mut err);
        Outcome {
            code,
            out: String::from_utf8(out).unwrap(),
            err: String::from_utf8(err).unwrap(),
        }
    })
    .await
    .unwrap()
}
