//! The OAuth-client records on the filesystem: the default adapter behind
//! [`ClientStore`](crate::client_store::ClientStore).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::client_store::{ActiveToken, Admitted, ClientRecord, ClientStore, Hash, TokenReplaced};

/// One JSON file per client under `<data_dir>/clients/`, owner-only, replaced in one step and
/// synced before the act that changed it is answered. The file holds the hashes
/// of the client secret and of the access token, and nothing that could be presented.
///
/// Every client is read when the store opens and kept in memory with an index of the token hashes:
/// admission asks who holds a token on every request, and the answer never touches the disk. A
/// write goes to the file first and to memory after it, so a write that fails changes neither.
pub struct FsClientStore {
    dir: PathBuf,
    index: Mutex<Index>,
}

#[derive(Default)]
struct Index {
    clients: HashMap<String, ClientRecord>,
    /// The client that holds each active token's hash.
    by_token: HashMap<Hash, String>,
}

impl Index {
    fn insert(&mut self, client: ClientRecord) {
        if let Some(token) = &client.token {
            self.by_token.insert(token.hash, client.client_id.clone());
        }
        self.clients.insert(client.client_id.clone(), client);
    }

    /// Whether `hash` is held by a client other than `client_id`.
    fn held_by_another(&self, hash: &Hash, client_id: &str) -> bool {
        self.by_token
            .get(hash)
            .is_some_and(|holder| holder != client_id)
    }
}

/// The on-disk document — this adapter's format, not the port's. Hashes are lowercase hex.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    client_id: String,
    space: String,
    secret_hash: String,
    client_id_issued_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token_expires_at: Option<u64>,
}

fn hash_of(text: &str, what: &str) -> Result<Hash, String> {
    hex::decode(text)
        .ok()
        .and_then(|bytes| Hash::try_from(bytes).ok())
        .ok_or_else(|| format!("{what} is not a SHA-256 hash in hex"))
}

impl Document {
    fn from_record(record: &ClientRecord) -> Self {
        Document {
            client_id: record.client_id.clone(),
            space: record.space.clone(),
            secret_hash: hex::encode(record.secret_hash),
            client_id_issued_at: record.issued_at,
            token_hash: record.token.map(|token| hex::encode(token.hash)),
            token_expires_at: record.token.and_then(|token| token.expires_at),
        }
    }

    fn into_record(self) -> Result<ClientRecord, String> {
        let token = match (self.token_hash, self.token_expires_at) {
            (Some(hash), expires_at) => Some(ActiveToken {
                hash: hash_of(&hash, "token_hash")?,
                expires_at,
            }),
            (None, None) => None,
            (None, Some(_)) => return Err("token_expires_at without a token_hash".to_string()),
        };
        let record = ClientRecord {
            client_id: self.client_id,
            space: self.space,
            secret_hash: hash_of(&self.secret_hash, "secret_hash")?,
            issued_at: self.client_id_issued_at,
            token,
        };
        record.check()?;
        Ok(record)
    }
}

impl FsClientStore {
    /// Opens the store in the data directory `root`, creating `clients/` owner-only and reading
    /// every client into memory.
    ///
    /// # Errors
    /// Returns an error naming the path when the directory cannot be created, a file in it is not
    /// a client or is not named for its client, or two clients hold one token.
    pub fn open(root: &Path) -> Result<Self, String> {
        let dir = root.join(super::CLIENTS);
        super::create_private_dir(&dir)?;
        let mut index = Index::default();
        for (stem, path) in super::json_files(&dir)? {
            let text =
                std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            let document: Document = serde_json::from_slice(&text)
                .map_err(|e| format!("cannot parse {}: {e}", path.display()))?;
            let record = document
                .into_record()
                .map_err(|e| format!("cannot restore {}: {e}", path.display()))?;
            if record.client_id != stem {
                return Err(super::misnamed(&path, "client"));
            }
            if let Some(token) = &record.token {
                if index.held_by_another(&token.hash, &record.client_id) {
                    return Err(format!(
                        "{} holds a token another client holds",
                        path.display()
                    ));
                }
            }
            index.insert(record);
        }
        Ok(FsClientStore {
            dir,
            index: Mutex::new(index),
        })
    }

    fn path(&self, client_id: &str) -> PathBuf {
        self.dir.join(format!("{client_id}.json"))
    }

    fn write(&self, record: &ClientRecord) -> Result<(), String> {
        let json =
            serde_json::to_vec_pretty(&Document::from_record(record)).expect("a client serializes");
        super::replace_owner_only(&self.path(&record.client_id), &json)
    }
}

impl ClientStore for FsClientStore {
    fn load(&self) -> Result<Vec<ClientRecord>, String> {
        let index = self.index.lock().expect("clients lock");
        let mut clients: Vec<_> = index.clients.values().cloned().collect();
        clients.sort_by(|a, b| a.client_id.cmp(&b.client_id));
        Ok(clients)
    }

    fn insert(&self, client: &ClientRecord) -> Result<bool, String> {
        client.check()?;
        let mut index = self.index.lock().expect("clients lock");
        if index.clients.contains_key(&client.client_id) {
            return Ok(false);
        }
        if let Some(token) = &client.token {
            if index.held_by_another(&token.hash, &client.client_id) {
                return Err("the token is held by another client".to_string());
            }
        }
        self.write(client)?;
        index.insert(client.clone());
        Ok(true)
    }

    fn secret_hash(&self, client_id: &str) -> Result<Option<Hash>, String> {
        let index = self.index.lock().expect("clients lock");
        Ok(index
            .clients
            .get(client_id)
            .map(|client| client.secret_hash))
    }

    fn replace_token(&self, client_id: &str, token: &ActiveToken) -> Result<TokenReplaced, String> {
        let mut index = self.index.lock().expect("clients lock");
        let Some(current) = index.clients.get(client_id) else {
            return Ok(TokenReplaced::NoSuchClient);
        };
        if index.held_by_another(&token.hash, client_id) {
            return Err("the token is held by another client".to_string());
        }
        let previous = current.token.map(|token| token.hash);
        let mut replaced = current.clone();
        replaced.token = Some(*token);
        self.write(&replaced)?;
        if let Some(previous) = previous {
            index.by_token.remove(&previous);
        }
        index.insert(replaced);
        Ok(TokenReplaced::Replaced { previous })
    }

    fn find_by_token(&self, token_hash: &Hash) -> Result<Option<Admitted>, String> {
        let index = self.index.lock().expect("clients lock");
        Ok(index
            .by_token
            .get(token_hash)
            .and_then(|client_id| index.clients.get(client_id))
            .map(|client| Admitted {
                client_id: client.client_id.clone(),
                space: client.space.clone(),
                expires_at: client.token.and_then(|token| token.expires_at),
            }))
    }
}
