//! Bearer token usage, RFC 6750: reading the credential a request presents, the challenges that
//! answer a refusal, and reading a challenge back on the client's side.
//!
//! Only the `Authorization` request header is supported as a transmission method (§2.1). A token in
//! the URL (§2.3) is not (§5.3 advises against it), and a form-encoded body (§2.2) is never read.
//! This module depends on `http` alone.

use http::header::{HeaderMap, HeaderValue, InvalidHeaderValue, AUTHORIZATION};
use http::{StatusCode, Uri};

/// What a request presents as its Bearer credential.
#[derive(Debug, PartialEq, Eq)]
pub enum Presented<'a> {
    /// No `Authorization` header. A token in the query alone counts as this: tokens in URLs are not
    /// supported.
    Absent,
    /// An `Authorization` header whose scheme is not Bearer. A caller answers it as [`Absent`].
    ///
    /// [`Absent`]: Presented::Absent
    Unsupported,
    /// `Bearer <token>`, the token in the `b64token` syntax of §2.1.
    Token(&'a str),
    /// `Bearer` with a missing token or one outside the `b64token` syntax.
    InvalidToken,
    /// More than one `Authorization` header, or a Bearer header together with an `access_token`
    /// query parameter: more than one transmission method (§2, §3.1).
    InvalidRequest,
}

impl<'a> Presented<'a> {
    /// The token, or how to refuse the request: absent and unsupported credentials are refused alike.
    pub fn token(self) -> Result<&'a str, Refusal> {
        match self {
            Presented::Token(token) => Ok(token),
            Presented::Absent | Presented::Unsupported => Err(Refusal::Unauthenticated),
            Presented::InvalidToken => Err(Refusal::InvalidToken),
            Presented::InvalidRequest => Err(Refusal::InvalidRequest),
        }
    }
}

/// Reads the Bearer credential of a request from its headers and URI.
pub fn presented<'a>(headers: &'a HeaderMap, uri: &Uri) -> Presented<'a> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Presented::Absent;
    };
    if values.next().is_some() {
        return Presented::InvalidRequest;
    }
    let value = value.as_bytes();
    let (scheme, rest) = match value.iter().position(|&b| b == b' ') {
        Some(end) => value.split_at(end),
        None => (value, &[][..]),
    };
    if !scheme.eq_ignore_ascii_case(b"Bearer") {
        return Presented::Unsupported;
    }
    if query_has_access_token(uri) {
        return Presented::InvalidRequest;
    }
    let token = &rest[rest.iter().position(|&b| b != b' ').unwrap_or(rest.len())..];
    match std::str::from_utf8(token) {
        Ok(token) if is_b64token(token) => Presented::Token(token),
        _ => Presented::InvalidToken,
    }
}

fn query_has_access_token(uri: &Uri) -> bool {
    uri.query().is_some_and(|query| {
        form_urlencoded::parse(query.as_bytes()).any(|(name, _)| name == "access_token")
    })
}

/// `b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="` (§2.1).
fn is_b64token(token: &str) -> bool {
    let body = token.trim_end_matches('=');
    !body.is_empty()
        && body.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
}

/// Why a request is refused, and with what answer (§3, §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// No credential, or one of another scheme: `401`, a challenge without an error code.
    Unauthenticated,
    /// A token that is wrong, malformed, replaced or expired: `401`, `error="invalid_token"`.
    InvalidToken,
    /// A malformed request: `400`, `error="invalid_request"`.
    InvalidRequest,
}

impl Refusal {
    pub fn status(self) -> StatusCode {
        match self {
            Refusal::Unauthenticated | Refusal::InvalidToken => StatusCode::UNAUTHORIZED,
            Refusal::InvalidRequest => StatusCode::BAD_REQUEST,
        }
    }

    /// The `WWW-Authenticate` value. The realm is only part of the challenge that carries no error
    /// code; it fails when the realm cannot be written into a header.
    pub fn challenge(self, realm: &str) -> Result<HeaderValue, InvalidHeaderValue> {
        match self {
            Refusal::Unauthenticated => {
                let realm = realm.replace('\\', "\\\\").replace('"', "\\\"");
                HeaderValue::from_str(&format!("Bearer realm=\"{realm}\""))
            }
            Refusal::InvalidToken => Ok(HeaderValue::from_static("Bearer error=\"invalid_token\"")),
            Refusal::InvalidRequest => {
                Ok(HeaderValue::from_static("Bearer error=\"invalid_request\""))
            }
        }
    }
}

/// One challenge of a `WWW-Authenticate` value: an authentication scheme and its parameters
/// (RFC 9110 §11.6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub scheme: String,
    /// Parameter names in lower case, values unquoted, in the order sent.
    pub params: Vec<(String, String)>,
}

impl Challenge {
    pub fn is_bearer(&self) -> bool {
        self.scheme.eq_ignore_ascii_case("Bearer")
    }

    /// The first parameter of that name (names are case-insensitive).
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The `error` parameter of RFC 6750 §3.
    pub fn error(&self) -> Option<&str> {
        self.param("error")
    }
}

/// Reads the challenges of one `WWW-Authenticate` value:
///
/// ```text
/// challenge   = auth-scheme [ 1*SP #auth-param ]
/// auth-param  = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// A `token68` argument (`Negotiate YII=`) is skipped, as it is not a parameter. Parsing stops at
/// the first thing that is not this grammar and returns the challenges read before it, so garbage
/// yields nothing and never an error.
pub fn parse_challenges(value: &str) -> Vec<Challenge> {
    let mut cursor = Cursor {
        bytes: value.as_bytes(),
        at: 0,
    };
    let mut challenges: Vec<Challenge> = Vec::new();
    loop {
        cursor.skip(|b| matches!(b, b' ' | b'\t' | b','));
        if cursor.peek().is_none() {
            break;
        }
        let Some(name) = cursor.token() else { break };
        cursor.skip(is_blank);
        if cursor.peek() != Some(b'=') {
            challenges.push(Challenge {
                scheme: name.to_owned(),
                params: Vec::new(),
            });
            continue;
        }
        cursor.at += 1;
        cursor.skip(is_blank);
        if matches!(cursor.peek(), None | Some(b',' | b'=')) {
            cursor.skip(|b| b != b',');
            continue;
        }
        let (Some(last), Some(parameter)) = (challenges.last_mut(), cursor.value()) else {
            break;
        };
        last.params.push((name.to_ascii_lowercase(), parameter));
    }
    challenges
}

fn is_blank(b: u8) -> bool {
    matches!(b, b' ' | b'\t')
}

pub(crate) fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn skip(&mut self, skipped: impl Fn(u8) -> bool) {
        while self.peek().is_some_and(&skipped) {
            self.at += 1;
        }
    }

    fn token(&mut self) -> Option<&'a str> {
        let start = self.at;
        self.skip(is_tchar);
        std::str::from_utf8(&self.bytes[start..self.at])
            .ok()
            .filter(|t| !t.is_empty())
    }

    /// A `token` or a `quoted-string`, whose `quoted-pair`s are unescaped.
    fn value(&mut self) -> Option<String> {
        if self.peek() != Some(b'"') {
            return self.token().map(str::to_owned);
        }
        self.at += 1;
        let mut value = Vec::new();
        loop {
            let byte = self.peek()?;
            self.at += 1;
            match byte {
                b'"' => return String::from_utf8(value).ok(),
                b'\\' => {
                    value.push(self.peek()?);
                    self.at += 1;
                }
                other => value.push(other),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(authorization: &[&[u8]], uri: &str) -> (HeaderMap, Uri) {
        let mut headers = HeaderMap::new();
        for value in authorization {
            headers.append(AUTHORIZATION, HeaderValue::from_bytes(value).unwrap());
        }
        (headers, uri.parse().unwrap())
    }

    fn read(authorization: &[&[u8]], uri: &str) -> Presentation {
        let (headers, uri) = request(authorization, uri);
        match presented(&headers, &uri) {
            Presented::Absent => Presentation::Absent,
            Presented::Unsupported => Presentation::Unsupported,
            Presented::Token(t) => Presentation::Token(t.to_owned()),
            Presented::InvalidToken => Presentation::InvalidToken,
            Presented::InvalidRequest => Presentation::InvalidRequest,
        }
    }

    #[derive(Debug, PartialEq)]
    enum Presentation {
        Absent,
        Unsupported,
        Token(String),
        InvalidToken,
        InvalidRequest,
    }
    use Presentation::*;

    /// RFC 6750 §2.1: `Authorization: Bearer mF_9.B5f-4.1JqM` is the header form.
    #[test]
    fn a_bearer_header_yields_its_token() {
        assert_eq!(
            read(&[b"Bearer mF_9.B5f-4.1JqM"], "/"),
            Token("mF_9.B5f-4.1JqM".into())
        );
    }

    /// RFC 6750 §2.1 (`b64token`): the alphabet is ALPHA, DIGIT and `-._~+/`, then any `=`.
    #[test]
    fn the_whole_b64token_alphabet_is_accepted() {
        assert_eq!(
            read(&[b"Bearer aZ09-._~+/=="], "/"),
            Token("aZ09-._~+/==".into())
        );
    }

    /// RFC 6750 §2.1: `b64token` has at least one character before the padding, and `=` only at
    /// the end; nothing outside its alphabet.
    #[test]
    fn a_token_outside_the_b64token_syntax_is_invalid() {
        for header in [
            &b"Bearer"[..],
            b"Bearer ",
            b"Bearer =",
            b"Bearer a=b",
            b"Bearer a b",
            b"Bearer a,b",
            b"Bearer \"abc\"",
            b"Bearer \xc3\xa9",
        ] {
            assert_eq!(read(&[header], "/"), InvalidToken, "{header:?}");
        }
    }

    /// RFC 7235 §2.1 (`auth-scheme` is case-insensitive), RFC 6750 §2.1 (`b64token` is not
    /// altered): the scheme matches in any case, the token is kept as sent.
    #[test]
    fn the_scheme_is_case_insensitive_and_the_token_is_not() {
        assert_eq!(read(&[b"bEaReR AbCd"], "/"), Token("AbCd".into()));
        assert_eq!(read(&[b"BEARER AbCd"], "/"), Token("AbCd".into()));
    }

    /// RFC 9110 §11.6.2: the scheme and the token are separated by one or more spaces.
    #[test]
    fn several_spaces_separate_the_scheme_and_the_token() {
        assert_eq!(read(&[b"Bearer    abc"], "/"), Token("abc".into()));
    }

    /// No authentication, or another scheme, is answered as no authentication.
    #[test]
    fn no_header_is_absent_and_another_scheme_is_unsupported() {
        assert_eq!(read(&[], "/"), Absent);
        assert_eq!(read(&[b"Basic dXNlcjpwYXNz"], "/"), Unsupported);
        assert_eq!(read(&[b"Bearerx abc"], "/"), Unsupported);
        assert_eq!(read(&[b""], "/"), Unsupported);
        assert_eq!(
            Presented::Unsupported.token(),
            Err(Refusal::Unauthenticated)
        );
        assert_eq!(Presented::Absent.token(), Err(Refusal::Unauthenticated));
    }

    /// RFC 6750 §2 and §3.1: more than one method of transmitting the token is `invalid_request`.
    #[test]
    fn two_authorization_headers_are_an_invalid_request() {
        assert_eq!(read(&[b"Bearer a", b"Bearer b"], "/"), InvalidRequest);
        assert_eq!(
            read(&[b"Bearer a", b"Basic Zm9vOmJhcg=="], "/"),
            InvalidRequest
        );
    }

    /// RFC 6750 §2 and §3.1: the header and the `access_token` query parameter together are two
    /// methods, whatever the token in the header.
    #[test]
    fn a_header_together_with_a_query_token_is_an_invalid_request() {
        assert_eq!(read(&[b"Bearer a"], "/x?access_token=b"), InvalidRequest);
        assert_eq!(read(&[b"Bearer"], "/x?y=1&access_token=b"), InvalidRequest);
        assert_eq!(read(&[b"Bearer a"], "/x?access%5Ftoken=b"), InvalidRequest);
    }

    /// RFC 6750 §5.3: a token in the URL alone is not supported, so it is no
    /// credential at all; a header of another scheme is not a second token transmission.
    #[test]
    fn a_query_token_alone_is_absent() {
        assert_eq!(read(&[], "/x?access_token=b"), Absent);
        assert_eq!(read(&[], "/x?access_token=a&access_token=b"), Absent);
        assert_eq!(
            read(&[b"Basic Zm9vOmJhcg=="], "/x?access_token=b"),
            Unsupported
        );
    }

    /// Other query parameters do not matter.
    #[test]
    fn other_query_parameters_are_ignored() {
        assert_eq!(
            read(&[b"Bearer a"], "/x?access_tokens=b&k=v"),
            Token("a".into())
        );
    }

    /// The three challenges, with the statuses RFC 6750 §3.1 gives them: 401, 401, 400.
    #[test]
    fn the_challenges_and_statuses_are_those_of_rfc_6750() {
        assert_eq!(
            Refusal::Unauthenticated.challenge("fleet").unwrap(),
            "Bearer realm=\"fleet\""
        );
        assert_eq!(
            Refusal::InvalidToken.challenge("fleet").unwrap(),
            "Bearer error=\"invalid_token\""
        );
        assert_eq!(
            Refusal::InvalidRequest.challenge("fleet").unwrap(),
            "Bearer error=\"invalid_request\""
        );
        assert_eq!(Refusal::Unauthenticated.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(Refusal::InvalidToken.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(Refusal::InvalidRequest.status(), StatusCode::BAD_REQUEST);
    }

    /// RFC 9110 §5.6.4: `"` and `\` in a realm are written as quoted pairs.
    #[test]
    fn a_realm_is_quoted() {
        assert_eq!(
            Refusal::Unauthenticated.challenge("a\"b\\c").unwrap(),
            "Bearer realm=\"a\\\"b\\\\c\""
        );
        assert!(Refusal::Unauthenticated.challenge("a\nb").is_err());
    }

    fn only(value: &str) -> Challenge {
        let mut all = parse_challenges(value);
        assert_eq!(all.len(), 1, "{value:?} parsed to {all:?}");
        all.remove(0)
    }

    /// RFC 6750 §3.1: `Bearer realm="example", error="invalid_token", error_description="…"`.
    #[test]
    fn a_bearer_challenge_with_an_error_is_read() {
        let challenge = only(
            "Bearer realm=\"example\", error=\"invalid_token\", error_description=\"The access token expired\"",
        );
        assert!(challenge.is_bearer());
        assert_eq!(challenge.error(), Some("invalid_token"));
        assert_eq!(challenge.param("realm"), Some("example"));
        assert_eq!(
            challenge.param("error_description"),
            Some("The access token expired")
        );
    }

    /// RFC 6750 §3: the challenge `Bearer realm="example"` carries no error code.
    #[test]
    fn a_bare_bearer_challenge_has_no_error() {
        let challenge = only("Bearer realm=\"fleet\"");
        assert!(challenge.is_bearer());
        assert_eq!(challenge.error(), None);
        assert_eq!(only("Bearer").params, vec![]);
    }

    /// RFC 9110 §11.1 and §5.6.4: the scheme and parameter names are case-insensitive; a quoted
    /// string's quoted pairs are unescaped, a token value needs no quotes, and blanks may surround `=`.
    #[test]
    fn names_are_case_insensitive_and_values_are_unquoted() {
        let challenge =
            only("bEaReR ERROR = invalid_request, realm=\"a \\\"quoted\\\" \\\\ realm\"");
        assert!(challenge.is_bearer());
        assert_eq!(challenge.error(), Some("invalid_request"));
        assert_eq!(challenge.param("REALM"), Some("a \"quoted\" \\ realm"));
    }

    /// RFC 6750 §3: a comma inside a quoted string is not a separator.
    #[test]
    fn a_comma_in_a_quoted_string_stays_in_the_value() {
        let challenge = only("Bearer error_description=\"a, b=c\", error=\"invalid_token\"");
        assert_eq!(challenge.param("error_description"), Some("a, b=c"));
        assert_eq!(challenge.error(), Some("invalid_token"));
    }

    /// RFC 6749 §5.2: a client sees `Basic realm="token"`, which is not a Bearer challenge.
    #[test]
    fn a_basic_challenge_is_not_bearer() {
        let challenge = only("Basic realm=\"token\", charset=\"UTF-8\"");
        assert!(!challenge.is_bearer());
        assert_eq!(challenge.scheme, "Basic");
        assert_eq!(challenge.param("charset"), Some("UTF-8"));
    }

    /// RFC 9110 §11.6.1: one value may carry several challenges; each parameter belongs to the
    /// challenge before it.
    #[test]
    fn several_challenges_in_one_value_are_separated() {
        let all =
            parse_challenges("Basic realm=\"token\", Bearer error=\"invalid_token\", Negotiate");
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].param("realm"), Some("token"));
        assert!(all[1].is_bearer());
        assert_eq!(all[1].error(), Some("invalid_token"));
        assert_eq!(all[2].scheme, "Negotiate");
        assert!(all[2].params.is_empty());
    }

    /// RFC 9110 §11.6.1: a `token68` argument is no parameter, and a challenge after it is still read.
    #[test]
    fn a_token68_argument_is_skipped() {
        let all = parse_challenges("Negotiate YII=, Bearer error=\"invalid_token\"");
        assert_eq!(all.len(), 2);
        assert!(all[0].params.is_empty());
        assert_eq!(all[1].error(), Some("invalid_token"));
        assert_eq!(parse_challenges("Negotiate YIIB==").len(), 1);
    }

    #[test]
    fn garbage_yields_what_came_before_it() {
        assert!(parse_challenges("").is_empty());
        assert!(parse_challenges(" , ,").is_empty());
        assert!(parse_challenges("\"quoted\"").is_empty());
        assert!(parse_challenges("=x").is_empty());
        assert!(parse_challenges("realm=\"x\"").is_empty());
        let unterminated = parse_challenges("Bearer realm=\"x");
        assert_eq!(unterminated.len(), 1);
        assert!(unterminated[0].params.is_empty());
        let trailing_escape = parse_challenges("Bearer realm=\"x\\");
        assert!(trailing_escape[0].params.is_empty());
        let after = parse_challenges("Bearer error=invalid_token ; junk");
        assert_eq!(after[0].error(), Some("invalid_token"));
    }
}
