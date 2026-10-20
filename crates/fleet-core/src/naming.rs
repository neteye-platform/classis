//! What a certificate is called (ADR-0028): one rule, so the operator tool and the Server name a
//! leaf alike. Each program reads its CA's common name itself; this module only derives from it.

/// The longest common name a certificate may carry (RFC 5280 Appendix A.1).
pub const MAX_COMMON_NAME: usize = 64;

/// The longest value of an organization or an organizational unit (RFC 5280 Appendix A.1).
pub const MAX_ORGANIZATION: usize = 64;

/// The longest product name, so `<product> Bootstrap Certificate` stays within
/// [`MAX_COMMON_NAME`].
pub const MAX_PRODUCT: usize = 40;

/// The product a fleet's certificates are named for unless told otherwise (ADR-0028 clause 26).
pub const DEFAULT_PRODUCT: &str = "OpAMP Fleet";

/// A leaf's common name from the common name of the CA that signs it (ADR-0028 clause 28): a
/// trailing ` CA` becomes ` Certificate`, and without one ` Certificate` is appended.
#[must_use]
pub fn leaf_common_name(ca_common_name: &str) -> String {
    let stem = ca_common_name.strip_suffix(" CA").unwrap_or(ca_common_name);
    format!("{stem} Certificate")
}

/// A product name (ADR-0028 clause 26): letters, digits, space, `.` and `-`, 1 to
/// [`MAX_PRODUCT`] characters, no leading or trailing space.
///
/// # Errors
/// Returns what is wrong with it.
pub fn check_product(product: &str) -> Result<(), String> {
    let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '-');
    if product.is_empty()
        || product.len() > MAX_PRODUCT
        || product.trim() != product
        || !product.chars().all(allowed)
    {
        return Err(format!(
            "{product:?}: letters, digits, space, '.' and '-', 1 to {MAX_PRODUCT} characters, no \
             leading or trailing space"
        ));
    }
    Ok(())
}

/// An organization or organizational unit (ADR-0028 clause 27): 1 to [`MAX_ORGANIZATION`]
/// characters of UTF-8 without control characters.
///
/// # Errors
/// Returns what is wrong with it.
pub fn check_organization(value: &str) -> Result<(), String> {
    let length = value.chars().count();
    if length == 0 || length > MAX_ORGANIZATION || value.chars().any(char::is_control) {
        return Err(format!(
            "{value:?}: 1 to {MAX_ORGANIZATION} characters without control characters"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verifies: ADR-0028
    #[test]
    fn a_leaf_is_named_for_its_ca_with_ca_turned_into_certificate() {
        assert_eq!(
            leaf_common_name("Acme Fleet Client CA"),
            "Acme Fleet Client Certificate"
        );
        assert_eq!(
            leaf_common_name("opamp-fleet bootstrap CA"),
            "opamp-fleet bootstrap Certificate"
        );
        assert_eq!(leaf_common_name("Corp Root"), "Corp Root Certificate");
        let longest = "x".repeat(MAX_PRODUCT);
        assert!(leaf_common_name(&format!("{longest} Bootstrap CA")).len() <= MAX_COMMON_NAME);
    }

    // Verifies: ADR-0028
    #[test]
    fn a_product_and_an_organization_keep_to_their_grammar() {
        assert!(check_product("OpAMP Fleet Dev").is_ok());
        for bad in ["", " lead", "trail ", "a/b", &"x".repeat(MAX_PRODUCT + 1)] {
            assert!(check_product(bad).is_err(), "{bad:?}");
        }
        assert!(check_organization("Würth IT GmbH").is_ok());
        for bad in ["", "a\nb", &"ü".repeat(MAX_ORGANIZATION + 1)] {
            assert!(check_organization(bad).is_err(), "{bad:?}");
        }
    }
}
