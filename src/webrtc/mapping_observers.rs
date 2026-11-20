//! Short-lived observer configuration bound to the locally selected rendezvous server
//! and its verified public key. Concurrent sessions may read the same signed policy.
use super::WebRTCStream;
use crate::config::Config;
use std::{
    net::SocketAddrV4,
    sync::Mutex,
    time::{Duration, Instant},
};

struct Entry {
    authority: String,
    key: String,
    expires: Instant,
    addresses: Vec<SocketAddrV4>,
}

static LAST: Mutex<Option<Entry>> = Mutex::new(None);

pub(super) fn remember(key: &str, observers: &[String]) {
    let authority = Config::get_option("custom-rendezvous-server");
    if authority.is_empty() || key.is_empty() || Config::get_option("key") != key {
        return;
    }
    let mut addresses = Vec::new();
    for value in observers.iter().take(4) {
        if let Ok(ep) = value.parse::<SocketAddrV4>() {
            if ep.port() != 0 && WebRTCStream::is_public_v4(*ep.ip()) && !addresses.contains(&ep) {
                addresses.push(ep);
            }
        }
    }
    *LAST.lock().unwrap() = Some(Entry {
        authority,
        key: key.to_owned(),
        addresses,
        expires: Instant::now() + Duration::from_secs(600),
    });
}

pub(super) fn current() -> Vec<SocketAddrV4> {
    let authority = Config::get_option("custom-rendezvous-server");
    let key = Config::get_option("key");
    LAST.lock()
        .unwrap()
        .as_ref()
        .filter(|entry| {
            entry.expires > Instant::now() && entry.authority == authority && entry.key == key
        })
        .map(|entry| entry.addresses.clone())
        .unwrap_or_default()
}
