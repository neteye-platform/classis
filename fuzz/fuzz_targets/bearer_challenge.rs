//! What a client reads out of a `WWW-Authenticate` value, and what a server reads out of an
//! `Authorization` header and a query string: both parsers of header grammar, fed bytes the peer
//! chose. Neither may panic, and what they return must keep the grammar's promises. Verifies: Q-2
#![no_main]

use http::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use http::Uri;
use libfuzzer_sys::fuzz_target;
use oauth_token::bearer::{parse_challenges, presented, Presented};

fuzz_target!(|data: &[u8]| {
    let Some((&split, rest)) = data.split_first() else {
        return;
    };
    let (authorization, query) = rest.split_at(usize::from(split).min(rest.len()));
    let query = String::from_utf8_lossy(query);

    for challenge in parse_challenges(&query) {
        assert!(!challenge.scheme.is_empty(), "a challenge without a scheme");
        for (name, _) in &challenge.params {
            assert!(!name.is_empty(), "a parameter without a name");
        }
    }

    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_bytes(authorization) {
        headers.insert(AUTHORIZATION, value);
    }
    let Ok(uri) = format!("/?{query}").parse::<Uri>() else {
        return;
    };
    if let Presented::Token(token) = presented(&headers, &uri) {
        assert!(!token.is_empty() && token.is_ascii(), "a token outside the b64token syntax");
    }
});
