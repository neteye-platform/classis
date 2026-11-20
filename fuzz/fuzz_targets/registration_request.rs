//! A client registration request as the endpoint receives it: a `Content-Type` header and a JSON
//! body, both attacker-chosen, judged by the parser the endpoint itself runs. Whatever the bytes,
//! the parser must neither panic nor accept a body over its limit, and a request it accepts is the
//! one registration of the profile. Verifies: Q-2
#![no_main]

use http::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use libfuzzer_sys::fuzz_target;
use oauth_registration::server::{parse_request, Metadata, RequestError, MAX_BODY};

fuzz_target!(|data: &[u8]| {
    let Some((&split, rest)) = data.split_first() else {
        return;
    };
    let (content_type, body) = rest.split_at(usize::from(split).min(rest.len()));
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_bytes(content_type) {
        headers.insert(CONTENT_TYPE, value);
    }
    match parse_request(&headers, body) {
        Ok(metadata) => {
            assert!(body.len() <= MAX_BODY, "parse_request accepted a body over its limit");
            assert_eq!(metadata, Metadata::REGISTERED);
        }
        Err(RequestError::TooLarge) => {
            assert!(body.len() > MAX_BODY, "a body within its limit was called too large");
        }
        Err(RequestError::InvalidMetadata) => {}
    }
});
