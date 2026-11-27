//! The enrolment key and the name of the space it belongs to.
//!
//! A space's name is 1 to 32 letters, digits and underscores that starts and ends with a letter or
//! a digit. Its key is `cle1_<space>_<secret>`: the fixed prefix, the name, `_`, and a secret of
//! 256 random bits written as 43 characters of base64url without padding (RFC 4648 §5). A name may
//! contain `_` and the secret may contain `_` and `-`, so a key is read from both ends.
//!
//! This module only checks and splits text. It makes no secret, and it owns none: a key borrows
//! the text it was read from, so the caller holds that text in the buffer its secrets belong in
//! and nothing here leaves a copy behind. Neither the error nor `Debug` shows a secret.

use std::fmt;

/// What starts every enrolment key, so that secret scanners and log redaction recognise one.
pub const PREFIX: &str = "cle1_";

/// The most characters a space's name has.
pub const MAX_SPACE_LEN: usize = 32;

/// The length of a secret: 256 bits in base64url without padding.
pub const SECRET_LEN: usize = 43;

/// Why a name or a key is refused. The text never repeats what was read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// The space's name is outside the pattern.
    InvalidSpace,
    /// The text does not start with [`PREFIX`].
    WrongPrefix,
    /// The text is too short to hold a space, its separator and a secret.
    WrongLength,
    /// The secret is not [`SECRET_LEN`] characters of the base64url alphabet.
    InvalidSecret,
    /// There is no `_` between the space and the secret.
    MissingSeparator,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KeyError::InvalidSpace => {
                "a space name is 1 to 32 letters, digits and underscores, starting and ending \
                 with a letter or a digit"
            }
            KeyError::WrongPrefix => "an enrolment key starts with cle1_",
            KeyError::WrongLength => "an enrolment key is too short",
            KeyError::InvalidSecret => {
                "an enrolment key ends in a secret of 43 characters of letters, digits, - and _"
            }
            KeyError::MissingSeparator => "an enrolment key has no _ before its secret",
        })
    }
}

impl std::error::Error for KeyError {}

/// Whether `name` matches `^[A-Za-z0-9]([A-Za-z0-9_]{0,30}[A-Za-z0-9])?$`.
#[must_use]
pub fn is_valid_space_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    bytes.len() <= MAX_SPACE_LEN
        && first.is_ascii_alphanumeric()
        && last.is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

/// Checks a space's name.
///
/// # Errors
/// [`KeyError::InvalidSpace`] when it is outside the pattern.
pub fn validate_space_name(name: &str) -> Result<(), KeyError> {
    if is_valid_space_name(name) {
        Ok(())
    } else {
        Err(KeyError::InvalidSpace)
    }
}

fn is_valid_secret(secret: &str) -> bool {
    secret.len() == SECRET_LEN
        && secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A space's name and the secret of its key, both borrowed.
#[derive(Clone, Copy)]
pub struct EnrolmentKey<'a> {
    space: &'a str,
    secret: &'a str,
}

impl<'a> EnrolmentKey<'a> {
    /// The key of `space` with `secret`.
    ///
    /// # Errors
    /// [`KeyError::InvalidSpace`] or [`KeyError::InvalidSecret`].
    pub fn new(space: &'a str, secret: &'a str) -> Result<Self, KeyError> {
        validate_space_name(space)?;
        if !is_valid_secret(secret) {
            return Err(KeyError::InvalidSecret);
        }
        Ok(EnrolmentKey { space, secret })
    }

    /// Reads a key from both ends: the prefix, then the last [`SECRET_LEN`] characters as the
    /// secret, then the `_` before them; what lies between is the space.
    ///
    /// # Errors
    /// The [`KeyError`] that says which part is wrong.
    pub fn parse(text: &'a str) -> Result<Self, KeyError> {
        let rest = text.strip_prefix(PREFIX).ok_or(KeyError::WrongPrefix)?;
        // At least one character of space, the separator and the secret.
        if rest.len() < SECRET_LEN + 2 {
            return Err(KeyError::WrongLength);
        }
        let split = rest.len() - SECRET_LEN;
        if !rest.is_char_boundary(split) {
            return Err(KeyError::InvalidSecret);
        }
        let (head, secret) = rest.split_at(split);
        let space = head.strip_suffix('_').ok_or(KeyError::MissingSeparator)?;
        EnrolmentKey::new(space, secret)
    }

    /// The space's name.
    #[must_use]
    pub fn space(&self) -> &'a str {
        self.space
    }

    /// The secret: 43 characters of base64url.
    #[must_use]
    pub fn secret(&self) -> &'a str {
        self.secret
    }

    /// How many bytes the key's text takes, so a buffer for it is sized once and never grown.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        PREFIX.len() + self.space.len() + 1 + SECRET_LEN
    }
}

impl fmt::Display for EnrolmentKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{PREFIX}{}_{}", self.space, self.secret)
    }
}

impl fmt::Debug for EnrolmentKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrolmentKey")
            .field("space", &self.space)
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";

    #[test]
    fn the_fixture_secret_is_43_characters() {
        assert_eq!(SECRET.len(), SECRET_LEN);
    }

    /// 1 to 32 letters, digits and underscores, starting and ending with a letter or a
    /// digit; an inner `_` is fine.
    #[test]
    fn space_names_inside_the_pattern() {
        for name in [
            "a",
            "Z",
            "7",
            "ab",
            "a_b",
            "A__9",
            "production",
            "Prod_EU_1",
            &"a".repeat(32),
            &format!("a{}b", "_".repeat(30)),
        ] {
            assert!(is_valid_space_name(name), "{name:?}");
            assert_eq!(validate_space_name(name), Ok(()));
        }
    }

    #[test]
    fn space_names_outside_the_pattern() {
        for name in [
            "",
            "_",
            "__",
            "_a",
            "a_",
            "_a_",
            &"a".repeat(33),
            &format!("a{}b", "_".repeat(31)),
            "a-b",
            "a b",
            "a.b",
            "a/b",
            "é",
            "aé",
            "aéa",
            "日本語",
            "a\n",
            "a\0b",
        ] {
            assert!(!is_valid_space_name(name), "{name:?}");
            assert_eq!(validate_space_name(name), Err(KeyError::InvalidSpace));
        }
    }

    #[test]
    fn a_key_is_the_prefix_the_space_and_the_secret() {
        let key = EnrolmentKey::new("prod", SECRET).expect("key");
        assert_eq!(key.to_string(), format!("cle1_prod_{SECRET}"));
        assert_eq!(key.encoded_len(), key.to_string().len());
        let text = key.to_string();
        let read = EnrolmentKey::parse(&text).expect("parse");
        assert_eq!((read.space(), read.secret()), ("prod", SECRET));
    }

    /// A space with `_` in it and a secret with `_` and `-` in it split at the right
    /// places, since the key is read from both ends.
    #[test]
    fn a_key_with_underscores_in_both_parts_splits_from_both_ends() {
        let secret = "_-".repeat(21) + "_";
        assert_eq!(secret.len(), SECRET_LEN);
        for space in ["a_b", "a__b", "x_y_z_1", "a_cle1_b", "7"] {
            let text = format!("cle1_{space}_{secret}");
            let key = EnrolmentKey::parse(&text).expect("parse");
            assert_eq!(key.space(), space, "{text}");
            assert_eq!(key.secret(), secret, "{text}");
        }
        let longest = "a".repeat(MAX_SPACE_LEN);
        let text = format!("cle1_{longest}_{secret}");
        assert_eq!(EnrolmentKey::parse(&text).expect("parse").space(), longest);
    }

    #[test]
    fn a_key_is_refused_for_what_is_wrong_with_it() {
        let wrong = |text: &str| EnrolmentKey::parse(text).expect_err(text);
        assert_eq!(wrong(&format!("cle2_prod_{SECRET}")), KeyError::WrongPrefix);
        assert_eq!(wrong(&format!("CLE1_prod_{SECRET}")), KeyError::WrongPrefix);
        assert_eq!(wrong(&format!("prod_{SECRET}")), KeyError::WrongPrefix);
        assert_eq!(wrong(""), KeyError::WrongPrefix);

        assert_eq!(wrong("cle1_"), KeyError::WrongLength);
        assert_eq!(wrong("cle1_a"), KeyError::WrongLength);
        assert_eq!(wrong(&format!("cle1_{SECRET}")), KeyError::WrongLength);
        // A space of nothing: the separator and the secret alone.
        assert_eq!(wrong(&format!("cle1__{SECRET}")), KeyError::WrongLength);

        // No separator between the space and the secret.
        assert_eq!(
            wrong(&format!("cle1_prod{SECRET}")),
            KeyError::MissingSeparator
        );
        // A short secret reads a character of the space as its first, and leaves no separator.
        let short = &SECRET[1..];
        assert!(EnrolmentKey::parse(&format!("cle1_prod_{short}")).is_err());
        // A long one: the separator is read as a character of the secret.
        assert!(EnrolmentKey::parse(&format!("cle1_prod_{SECRET}x")).is_err());

        // Characters outside base64url, '=' padding and non-ASCII in the secret.
        for bad in ['+', '/', '=', ' ', '.', '\n'] {
            let secret = format!("{}{bad}", &SECRET[..SECRET_LEN - 1]);
            assert_eq!(
                wrong(&format!("cle1_prod_{secret}")),
                KeyError::InvalidSecret,
                "{bad:?}"
            );
        }
        let non_ascii = format!("{}é", &SECRET[..SECRET_LEN - 2]);
        assert_eq!(
            wrong(&format!("cle1_prod_{non_ascii}")),
            KeyError::InvalidSecret
        );
        let split_inside = format!("cle1_prod_é{}", &SECRET[..SECRET_LEN - 1]);
        assert_eq!(wrong(&split_inside), KeyError::InvalidSecret);

        // The space of a key is checked as a name is.
        for space in ["_a", "a_", "a-b", "é", &"a".repeat(33)] {
            assert_eq!(
                wrong(&format!("cle1_{space}_{SECRET}")),
                KeyError::InvalidSpace,
                "{space:?}"
            );
        }
    }

    #[test]
    fn a_key_is_built_only_from_a_valid_space_and_secret() {
        assert_eq!(
            EnrolmentKey::new("_a", SECRET).expect_err("space"),
            KeyError::InvalidSpace
        );
        assert_eq!(
            EnrolmentKey::new("a", &SECRET[1..]).expect_err("short"),
            KeyError::InvalidSecret
        );
        assert_eq!(
            EnrolmentKey::new("a", &format!("{SECRET}x")).expect_err("long"),
            KeyError::InvalidSecret
        );
    }

    /// Neither `Debug` nor an error shows the secret.
    #[test]
    fn nothing_shows_the_secret() {
        let key = EnrolmentKey::new("prod", SECRET).expect("key");
        let shown = format!("{key:?}");
        assert!(shown.contains("prod"), "{shown}");
        assert!(!shown.contains(SECRET), "{shown}");
        assert!(!shown.contains(&SECRET[..10]), "{shown}");
        let error = EnrolmentKey::parse(&format!("cle1_prod_{SECRET}!")).expect_err("bad");
        assert!(!error.to_string().contains(&SECRET[..10]));
    }
}
