//! A token request as the endpoint receives it: an `Authorization` header and a form body, both
//! attacker-chosen, judged by the parser the endpoint itself runs. Whatever the bytes, the parser
//! must neither panic nor accept a request without a grant type. Verifies: Q-2
#![no_main]

use http::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use libfuzzer_sys::fuzz_target;
use oauth_token::server::{parse_request, MAX_BODY};

fuzz_target!(|data: &[u8]| {
    let Some((&split, rest)) = data.split_first() else {
        return;
    };
    let (authorization, body) = rest.split_at(usize::from(split).min(rest.len()));
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/x-www-form-urlencoded"));
    if !authorization.is_empty() {
        if let Ok(value) = HeaderValue::from_bytes(authorization) {
            headers.insert(AUTHORIZATION, value);
        }
    }
    if let Ok(request) = parse_request(&headers, body) {
        assert!(body.len() <= MAX_BODY, "parse_request accepted a body over its limit");
        assert!(!request.grant_type.is_empty(), "a request without a grant type was accepted");
    }
});
