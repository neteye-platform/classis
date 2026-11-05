//! A file's DACL as SDDL text, and the changes the Client makes to it (ADR-0059 clauses 6 and 10):
//! an explicit grant to one account in place of the one it had, and the ACEs a child inherits
//! from its parent.
//!
//! The Client sets a DACL on one handle at a time and propagates nothing through the system
//! ([`super::files`]): what a directory passes on to what it already holds, the Client applies
//! itself while it walks the tree, never through a link or into what the process account owns.
//! That walk needs the inheritance rules spelled out, which is what this module does, on text,
//! so that the rules are tested on every platform. It reads the ACE strings the system writes
//! (Security Descriptor String Format); a conditional ACE, whose string nests parentheses, is
//! refused rather than guessed at.

/// `FILE_GENERIC_READ | FILE_GENERIC_EXECUTE`: what `icacls` calls `RX`.
pub const READ_EXECUTE: u32 = 0x0012_00a9;

/// `FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE`: what `icacls` calls
/// `M`.
pub const MODIFY: u32 = 0x0013_01bf;

/// `DELETE`: removing the object itself.
pub const DELETE: u32 = 0x0001_0000;

/// `WRITE_DAC`: changing the object's DACL.
pub const WRITE_DAC: u32 = 0x0004_0000;

/// A DACL: its flags (`P`, `AI`, `AR`) and its ACEs, each as the system writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dacl {
    pub flags: String,
    pub aces: Vec<String>,
}

impl Dacl {
    /// Reads the `D:` part of an SDDL string, as `ConvertSecurityDescriptorToStringSecurityDescriptorW`
    /// writes it for `DACL_SECURITY_INFORMATION` alone.
    ///
    /// # Errors
    /// Returns why the text is no DACL this module reads: none at all, a null DACL, or a
    /// conditional ACE.
    pub fn parse(text: &str) -> Result<Dacl, String> {
        let refused = |why: &str| format!("{text:?}: {why}");
        let body = text.strip_prefix("D:").ok_or_else(|| refused("no DACL"))?;
        if body.starts_with("NO_ACCESS_CONTROL") {
            return Err(refused("a null DACL"));
        }
        let start = body.find('(').unwrap_or(body.len());
        let flags = body[..start].to_string();
        let mut aces = Vec::new();
        let mut rest = &body[start..];
        while !rest.is_empty() {
            let inner = rest
                .strip_prefix('(')
                .ok_or_else(|| refused("text between ACEs"))?;
            let end = inner
                .find(')')
                .ok_or_else(|| refused("an unterminated ACE"))?;
            let ace = &inner[..end];
            if ace.contains('(') {
                return Err(refused("a conditional ACE"));
            }
            aces.push(format!("({ace})"));
            rest = &inner[end + 1..];
        }
        Ok(Dacl { flags, aces })
    }

    /// The DACL as SDDL text.
    #[must_use]
    pub fn text(&self) -> String {
        format!("D:{}{}", self.flags, self.aces.concat())
    }

    /// Whether the DACL is protected from what its parent passes on.
    #[must_use]
    pub fn protected(&self) -> bool {
        self.flags.contains('P')
    }

    /// The DACL with the explicit allow ACEs of `sid` replaced by `new`, placed after the other
    /// explicit ACEs and before the inherited ones, as the order of an ACL wants them: what
    /// `icacls /grant:r` does.
    #[must_use]
    pub fn granting(&self, sid: &str, new: &[String]) -> Dacl {
        let mut kept: Vec<String> = self
            .aces
            .iter()
            .filter(|ace| inherited(ace) || !(allows(ace) && trustee_is(ace, sid)))
            .cloned()
            .collect();
        let at = kept
            .iter()
            .position(|ace| inherited(ace))
            .unwrap_or(kept.len());
        kept.splice(at..at, new.iter().cloned());
        Dacl {
            flags: self.flags.clone(),
            aces: kept,
        }
    }

    /// The DACL without an ACE that allows `sid` anything, explicit or inherited; one that denies
    /// it stays.
    #[must_use]
    pub fn without(&self, sid: &str) -> Dacl {
        Dacl {
            flags: self.flags.clone(),
            aces: self
                .aces
                .iter()
                .filter(|ace| !(allows(ace) && trustee_is(ace, sid)))
                .cloned()
                .collect(),
        }
    }

    /// The DACL with its explicit ACEs alone.
    #[must_use]
    pub fn explicit(&self) -> Dacl {
        Dacl {
            flags: self.flags.clone(),
            aces: self
                .aces
                .iter()
                .filter(|ace| !inherited(ace))
                .cloned()
                .collect(),
        }
    }

    /// Whether the DACL holds `ace` as it is, its trustee written as a SID or as the alias the
    /// system writes for it.
    #[must_use]
    pub fn holds(&self, ace: &str) -> bool {
        self.aces.iter().any(|held| same_ace(held, ace))
    }

    /// The explicit ACEs of the DACL, and those a child — a directory where `dir` — inherits
    /// from `parent` after them, under the rules of ACE inheritance: where the parent is
    /// protected or not, the child keeps its own flags, and a child that is protected keeps its
    /// DACL as it is. What `icacls /inheritance:r` on the parent makes of a child.
    #[must_use]
    pub fn inheriting(&self, parent: &Dacl, dir: bool) -> Dacl {
        if self.protected() {
            return self.clone();
        }
        let mut aces: Vec<String> = self
            .aces
            .iter()
            .filter(|ace| !inherited(ace))
            .cloned()
            .collect();
        aces.extend(parent.passed_on(dir));
        Dacl {
            flags: self.flags.clone(),
            aces,
        }
    }

    /// The ACEs a child — a directory where `dir` — inherits from this DACL, each marked
    /// inherited (`ID`): an ACE for containers (`CI`) to a directory, with its flags unless it
    /// propagates no further (`NP`); an ACE for objects (`OI`) to a file, and to a directory as
    /// inherit-only, passed on to its files; nothing else. An ACE of `CREATOR OWNER` or
    /// `CREATOR GROUP`, for which the system would grant the child's owner, is passed on to a
    /// directory as inherit-only and to a file not at all: it grants no one access here. A mask
    /// of generic rights is passed on as it is, never mapped to the file rights the system would
    /// split it into for an effective ACE: an ACE so passed on grants at most less than the
    /// system's would.
    #[must_use]
    pub fn passed_on(&self, dir: bool) -> Vec<String> {
        self.aces
            .iter()
            .filter_map(|ace| {
                let fields: Vec<&str> = ace[1..ace.len() - 1].split(';').collect();
                let flags = fields.get(1)?;
                let has = |flag: &str| tokens(flags).any(|token| token == flag);
                let (oi, ci, np) = (has("OI"), has("CI"), has("NP"));
                let creator = trustee_is(ace, "S-1-3-0") || trustee_is(ace, "S-1-3-1");
                if creator {
                    if !dir || np || !(oi || ci) {
                        return None;
                    }
                    let mut fields: Vec<String> = fields.iter().map(|f| (*f).to_string()).collect();
                    fields[1] = format!(
                        "{}{}IOID",
                        if oi { "OI" } else { "" },
                        if ci { "CI" } else { "" }
                    );
                    return Some(format!("({})", fields.join(";")));
                }
                let new_flags = match (dir, oi, ci, np) {
                    (true, _, true, true) | (false, true, _, _) => "ID".to_string(),
                    (true, _, true, false) => {
                        format!("{}{}ID", if oi { "OI" } else { "" }, "CI")
                    }
                    (true, true, false, false) => "OIIOID".to_string(),
                    _ => return None,
                };
                let mut fields: Vec<String> = fields.iter().map(|f| (*f).to_string()).collect();
                fields[1] = new_flags;
                Some(format!("({})", fields.join(";")))
            })
            .fold(Vec::new(), |mut passed: Vec<String>, ace| {
                // An explicit ACE and an inherited one alike are passed on alike, once: the
                // system holds no ACE twice.
                if !passed.contains(&ace) {
                    passed.push(ace);
                }
                passed
            })
    }
}

/// Whether two ACEs are the same however the system writes them: the same type, the same flags in
/// any order, the same rights as a hex mask or as their aliases, and the same trustee as a SID or
/// as its alias.
fn same_ace(held: &str, ace: &str) -> bool {
    fn flags(ace: &str) -> Vec<&str> {
        let mut flags: Vec<&str> = field(ace, 1)
            .map(|f| tokens(f).collect())
            .unwrap_or_default();
        flags.sort_unstable();
        flags
    }
    let Some(trustee) = field(ace, 5) else {
        return false;
    };
    field(held, 0) == field(ace, 0)
        && flags(held) == flags(ace)
        && field(held, 2).and_then(mask) == field(ace, 2).and_then(mask)
        && field(held, 2).and_then(mask).is_some()
        && (3..5).all(|i| field(held, i) == field(ace, i))
        && trustee_is(held, trustee)
}

/// The rights an ACE's mask field names: a hex number, or the aliases the system writes for file
/// rights.
fn mask(text: &str) -> Option<u32> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).ok();
    }
    const ALIASES: [(&str, u32); 12] = [
        ("FA", 0x001f_01ff),
        ("FR", 0x0012_0089),
        ("FW", 0x0012_0116),
        ("FX", 0x0012_00a0),
        ("GA", 0x1000_0000),
        ("GR", 0x8000_0000),
        ("GW", 0x4000_0000),
        ("GX", 0x2000_0000),
        ("SD", 0x0001_0000),
        ("RC", 0x0002_0000),
        ("WD", 0x0004_0000),
        ("WO", 0x0008_0000),
    ];
    if text.is_empty() {
        return None;
    }
    tokens(text).try_fold(0u32, |sum, token| {
        ALIASES
            .iter()
            .find(|(alias, _)| *alias == token)
            .map(|(_, bits)| sum | bits)
    })
}

/// An allow ACE of `mask` for `sid`, with the inheritance flags `flags` (`OICI`, `OICIIO`, …).
#[must_use]
pub fn allow(sid: &str, mask: u32, flags: &str) -> String {
    format!("(A;{flags};0x{mask:x};;;{sid})")
}

/// The two-letter tokens of an ACE's flags field.
fn tokens(flags: &str) -> impl Iterator<Item = &str> {
    flags
        .as_bytes()
        .chunks(2)
        .filter_map(|pair| std::str::from_utf8(pair).ok())
}

fn field(ace: &str, index: usize) -> Option<&str> {
    ace.get(1..ace.len().saturating_sub(1))?
        .split(';')
        .nth(index)
}

/// Whether the ACE was inherited (`ID`).
fn inherited(ace: &str) -> bool {
    field(ace, 1).is_some_and(|flags| tokens(flags).any(|token| token == "ID"))
}

/// Whether the ACE allows.
fn allows(ace: &str) -> bool {
    field(ace, 0) == Some("A")
}

/// Whether the ACE's trustee is `sid`, written as a SID or as the alias the system writes for a
/// well-known one.
fn trustee_is(ace: &str, sid: &str) -> bool {
    const ALIASES: [(&str, &str); 9] = [
        ("CG", "S-1-3-1"),
        ("SY", "S-1-5-18"),
        ("LS", "S-1-5-19"),
        ("NS", "S-1-5-20"),
        ("BA", "S-1-5-32-544"),
        ("BU", "S-1-5-32-545"),
        ("WD", "S-1-1-0"),
        ("AU", "S-1-5-11"),
        ("CO", "S-1-3-0"),
    ];
    let Some(trustee) = field(ace, 5) else {
        return false;
    };
    let trustee = ALIASES
        .iter()
        .find(|(alias, _)| *alias == trustee)
        .map_or(trustee, |(_, sid)| *sid);
    trustee.eq_ignore_ascii_case(sid)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROCESS: &str = "S-1-5-80-1-2-3-4-5";

    /// A DACL is read as the system writes it, and one this module cannot read is refused.
    /// Verifies: ADR-0059
    #[test]
    fn a_dacl_is_read_as_the_system_writes_it() {
        let text = "D:PAI(A;OICI;FA;;;SY)(A;OICIID;0x1200a9;;;BU)";
        let dacl = Dacl::parse(text).expect("dacl");
        assert_eq!(dacl.flags, "PAI");
        assert_eq!(dacl.aces.len(), 2);
        assert!(dacl.protected());
        assert_eq!(dacl.text(), text);
        assert_eq!(Dacl::parse("D:").expect("empty").aces.len(), 0);
        for refused in [
            "",
            "O:BA",
            "D:NO_ACCESS_CONTROL",
            "D:(A;;FA;;;SY",
            "D:(XA;;FA;;;WD;(x))",
        ] {
            assert!(Dacl::parse(refused).is_err(), "{refused}");
        }
    }

    /// A grant replaces the explicit allow ACEs of its account, alias or SID alike, keeps every
    /// other ACE and every inherited one, and goes before the inherited ones.
    /// Verifies: ADR-0059
    #[test]
    fn a_grant_replaces_the_accounts_explicit_ace_in_order() {
        let dacl = Dacl::parse(&format!(
            "D:AI(D;;FA;;;{PROCESS})(A;OICI;FA;;;LS)(A;;0x1;;;{PROCESS})(A;OICIID;FA;;;SY)(A;ID;0x1;;;{PROCESS})"
        ))
        .expect("dacl");
        let ace = allow(PROCESS, READ_EXECUTE, "OICI");
        let granted = dacl.granting(PROCESS, std::slice::from_ref(&ace));
        assert_eq!(
            granted.text(),
            format!(
                "D:AI(D;;FA;;;{PROCESS})(A;OICI;FA;;;LS){ace}(A;OICIID;FA;;;SY)(A;ID;0x1;;;{PROCESS})"
            )
        );
        assert!(granted.holds(&ace));
        let aliased = Dacl::parse("D:(A;;0x1200a9;;;LS)").expect("dacl");
        assert!(
            aliased.holds("(A;;0x1200a9;;;S-1-5-19)"),
            "the alias is the SID"
        );
        assert!(!aliased.holds("(A;OICI;0x1200a9;;;S-1-5-19)"));

        let local_service = dacl.granting("S-1-5-19", &[]);
        assert!(
            !local_service.text().contains(";;;LS)"),
            "the alias is the SID"
        );
    }

    /// What a parent passes on follows the rules of ACE inheritance: to a directory what is for
    /// containers, and what is for objects as inherit-only; to a file what is for objects; nothing
    /// past `NP`, and nothing that is for neither.
    /// Verifies: ADR-0059
    #[test]
    fn a_child_inherits_by_the_rules_of_ace_inheritance() {
        let parent = Dacl::parse(
            "D:PAI(A;OICI;FA;;;SY)(A;CI;0x1;;;BA)(A;OI;0x2;;;BU)(A;CINP;0x4;;;WD)(A;;0x8;;;AU)(A;OICIIO;0x10;;;CO)",
        )
        .expect("dacl");
        assert_eq!(
            parent.passed_on(true),
            [
                "(A;OICIID;FA;;;SY)",
                "(A;CIID;0x1;;;BA)",
                "(A;OIIOID;0x2;;;BU)",
                "(A;ID;0x4;;;WD)",
                "(A;OICIIOID;0x10;;;CO)",
            ]
        );
        assert_eq!(
            parent.passed_on(false),
            ["(A;ID;FA;;;SY)", "(A;ID;0x2;;;BU)"]
        );
        let child = Dacl::parse("D:AI(A;;0x1;;;LS)(A;OICIID;FA;;;WD)").expect("child");
        assert_eq!(
            child.inheriting(&parent, false).text(),
            "D:AI(A;;0x1;;;LS)(A;ID;FA;;;SY)(A;ID;0x2;;;BU)"
        );
        let protected = Dacl::parse("D:P(A;;0x1;;;LS)").expect("protected");
        assert_eq!(protected.inheriting(&parent, true), protected);

        // A withdrawal takes every ACE that allows the account, explicit or inherited, alias or
        // SID, and leaves one that denies it and every other account's.
        let granted = Dacl::parse(
            "D:AI(D;;0x2;;;LS)(A;OICI;0x1200a9;;;LS)(A;;FA;;;SY)(A;OICIID;0x1301bf;;;S-1-5-19)",
        )
        .expect("granted");
        assert_eq!(
            granted.without("S-1-5-19").text(),
            "D:AI(D;;0x2;;;LS)(A;;FA;;;SY)"
        );

        // A parent holding the same ACE as explicit and as inherited passes it on once, and a
        // child holding explicit and inherited ACEs keeps the explicit ones and gets what the
        // parent passes on in place of what it inherited before — as the CI saw a file under a
        // directory whose ACEs a DACL set on a handle had left explicit.
        let sub = Dacl::parse(
            "D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LA)(A;OICI;0x1200a9;;;BU)\
             (A;OICI;0x1200a9;;;WD)(A;OICIID;FA;;;LA)(A;OICIID;0x1200a9;;;BU)\
             (A;OICIID;0x1200a9;;;WD)(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)",
        )
        .expect("sub");
        let file = Dacl::parse(
            "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LA)(A;;0x1200a9;;;BU)(A;;0x1200a9;;;WD)\
             (A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;LA)(A;ID;0x1200a9;;;BU)(A;ID;0x1200a9;;;WD)",
        )
        .expect("file");
        assert_eq!(
            file.inheriting(&sub, false).text(),
            "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LA)(A;;0x1200a9;;;BU)(A;;0x1200a9;;;WD)\
             (A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;LA)(A;ID;0x1200a9;;;BU)(A;ID;0x1200a9;;;WD)",
            "no ACE twice"
        );
    }
}
