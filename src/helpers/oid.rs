use crate::{Oid, Result, Error};

/// Parse an OID from dot-notation string (e.g., "1.3.6.1.2.1.1.1.0" or ".1.3.6.1.2.1.1.1.0")
///
/// Leading dots are optional and will be stripped.
///
/// # Examples
/// ```
/// use snmp2::helpers::parse_oid;
///
/// let oid = parse_oid("1.3.6.1.2.1.1.1.0")?;
/// let oid_with_dot = parse_oid(".1.3.6.1.2.1.1.1.0")?;
/// assert_eq!(oid, oid_with_dot);
/// # Ok::<(), snmp2::Error>(())
/// ```
///
/// # Errors
/// Returns `Error::AsnParse` if the string contains non-numeric components
pub fn parse_oid(s: &str) -> Result<Oid<'static>> {
    let parts: Vec<u32> = s
        .trim_start_matches('.')
        .split('.')
        .map(|p| p.parse().map_err(|_| Error::AsnParse))
        .collect::<Result<Vec<_>>>()?;
    
    Oid::from(&parts[..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_oid() {
        let oid = parse_oid("1.3.6.1.2.1.1.1.0").unwrap();
        assert_eq!(oid.to_string(), "1.3.6.1.2.1.1.1.0");
    }
    
    #[test]
    fn test_parse_oid_with_leading_dot() {
        let oid = parse_oid(".1.3.6.1.2.1.1.1.0").unwrap();
        assert_eq!(oid.to_string(), "1.3.6.1.2.1.1.1.0");
    }
    
    #[test]
    fn test_parse_oid_invalid() {
        assert!(parse_oid("1.3.6.abc.1").is_err());
        assert!(parse_oid("").is_err());
    }
    
    #[test]
    fn test_parse_oid_equivalence() {
        let oid1 = parse_oid("1.3.6.1.2.1.1.1.0").unwrap();
        let oid2 = parse_oid(".1.3.6.1.2.1.1.1.0").unwrap();
        assert_eq!(oid1.to_string(), oid2.to_string());
    }
}
