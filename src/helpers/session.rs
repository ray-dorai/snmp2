use crate::{Oid, Result, SyncSession};

use super::value::{value_to_string, OwnedValue};

/// Extension trait for SyncSession providing convenience methods
///
/// This trait adds higher-level operations on top of the basic SNMP operations,
/// including walk variants that preserve type information.
pub trait SessionExt {
    /// Walk an SNMP tree, returning owned (OID, Value) pairs.
    ///
    /// Unlike `walk()` which returns strings, this preserves the original SNMP types
    /// so you can extract raw bytes (for MACs), integers, IP addresses, etc.
    ///
    /// # Examples
    /// ```no_run
    /// use snmp2::{SyncSession, helpers::{SessionExt, parse_oid, OwnedValue}};
    ///
    /// let mut session = SyncSession::new_v2c("192.168.1.1:161", b"public", None, 0)?;
    /// let oid = parse_oid("1.3.6.1.4.1.41112.1.4.7.1.1")?; // MAC table
    ///
    /// let results = session.walk_values(&oid)?;
    /// for (oid, value) in &results {
    ///     if let Some(bytes) = value.as_bytes() {
    ///         println!("{}: {:02x?}", oid, bytes);
    ///     }
    /// }
    /// # Ok::<(), snmp2::Error>(())
    /// ```
    fn walk_values(&mut self, oid: &Oid) -> Result<Vec<(Oid<'static>, OwnedValue)>>;

    /// Walk an SNMP tree and return raw byte vectors for each value.
    ///
    /// This is the most useful variant for table walks where you need the raw
    /// SNMP octet strings (e.g., MAC addresses). Non-OctetString values are
    /// converted to their string representation as bytes.
    ///
    /// # Examples
    /// ```no_run
    /// use snmp2::{SyncSession, helpers::{SessionExt, parse_oid}};
    ///
    /// let mut session = SyncSession::new_v2c("192.168.1.1:161", b"public", None, 0)?;
    /// let mac_oid = parse_oid("1.3.6.1.4.1.41112.1.4.7.1.1")?;
    ///
    /// let mac_bytes = session.walk_bytes(&mac_oid)?;
    /// for mac in &mac_bytes {
    ///     if mac.len() == 6 {
    ///         let formatted = mac.iter()
    ///             .map(|b| format!("{:02x}", b))
    ///             .collect::<Vec<_>>()
    ///             .join(":");
    ///         println!("MAC: {}", formatted);
    ///     }
    /// }
    /// # Ok::<(), snmp2::Error>(())
    /// ```
    fn walk_bytes(&mut self, oid: &Oid) -> Result<Vec<Vec<u8>>>;

    /// Walk an SNMP tree starting at the specified OID, returning (OID, String) pairs.
    ///
    /// This performs multiple GETNEXT operations until the returned OID is no longer
    /// a descendant of the base OID.
    ///
    /// **Note:** This performs lossy UTF-8 conversion on OctetString values. If you
    /// need raw binary data (e.g., MAC addresses), use `walk_values()` or `walk_bytes()`.
    fn walk(&mut self, oid: &Oid) -> Result<Vec<(Oid<'static>, String)>>;

    /// Walk an SNMP tree and return only the values as strings.
    ///
    /// **Note:** Lossy conversion. Use `walk_bytes()` for binary data.
    fn walk_strings(&mut self, oid: &Oid) -> Result<Vec<String>>;

    /// Get a single value and convert to string.
    fn get_string(&mut self, oid: &Oid) -> Result<String>;

    /// Get a single value as an OwnedValue, preserving type information.
    ///
    /// # Examples
    /// ```no_run
    /// use snmp2::{SyncSession, helpers::{SessionExt, parse_oid}};
    ///
    /// let mut session = SyncSession::new_v2c("192.168.1.1:161", b"public", None, 0)?;
    /// let oid = parse_oid("1.3.6.1.4.1.161.19.3.1.1.2.0")?; // frequency
    ///
    /// let value = session.get_value(&oid)?;
    /// if let Some(freq) = value.as_i64() {
    ///     println!("Frequency: {} MHz", freq);
    /// }
    /// # Ok::<(), snmp2::Error>(())
    /// ```
    fn get_value(&mut self, oid: &Oid) -> Result<OwnedValue>;
}

/// Check if `candidate` is a child OID of `base`.
///
/// Subtree check that avoids the string prefix bug where
/// "1.3.6.1.4.1.411" would incorrectly match as a prefix of "1.3.6.1.4.1.41112".
fn is_subtree(base: &str, candidate: &str) -> bool {
    if candidate == base {
        return true;
    }
    if candidate.len() > base.len() {
        // Must start with base AND the next character must be '.'
        candidate.starts_with(base) && candidate.as_bytes()[base.len()] == b'.'
    } else {
        false
    }
}

impl SessionExt for SyncSession {
    fn walk_values(&mut self, oid: &Oid) -> Result<Vec<(Oid<'static>, OwnedValue)>> {
        let mut results = Vec::new();
        let mut current_oid = oid.clone();
        let base_str = oid.to_string();

        loop {
            let response = self.getnext(&current_oid)?;

            if let Some((next_oid, value)) = response.varbinds.next() {
                let next_oid_str = next_oid.to_string();

                if !is_subtree(&base_str, &next_oid_str) {
                    break;
                }

                let owned = OwnedValue::from_value(&value);

                // EndOfMibView means we've exhausted the subtree
                if owned.is_error() {
                    break;
                }

                let owned_oid = next_oid.to_owned();
                results.push((owned_oid, owned));
                current_oid = Oid::from(
                    &next_oid_str
                        .split('.')
                        .map(|p| p.parse::<u32>().unwrap_or(0))
                        .collect::<Vec<_>>()[..],
                )
                .unwrap_or_else(|_| oid.clone());
            } else {
                break;
            }
        }

        Ok(results)
    }

    fn walk_bytes(&mut self, oid: &Oid) -> Result<Vec<Vec<u8>>> {
        Ok(self
            .walk_values(oid)?
            .into_iter()
            .map(|(_, v)| match v {
                OwnedValue::OctetString(bytes) => bytes,
                OwnedValue::Opaque(bytes) => bytes,
                OwnedValue::IpAddress(ip) => {
                    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]).into_bytes()
                }
                other => other.to_string_lossy().into_bytes(),
            })
            .collect())
    }

    fn walk(&mut self, oid: &Oid) -> Result<Vec<(Oid<'static>, String)>> {
        Ok(self
            .walk_values(oid)?
            .into_iter()
            .map(|(oid, v)| (oid, v.to_string_lossy()))
            .collect())
    }

    fn walk_strings(&mut self, oid: &Oid) -> Result<Vec<String>> {
        Ok(self
            .walk_values(oid)?
            .into_iter()
            .map(|(_, v)| v.to_string_lossy())
            .collect())
    }

    fn get_string(&mut self, oid: &Oid) -> Result<String> {
        let response = self.get(oid)?;

        if let Some((_, value)) = response.varbinds.next() {
            Ok(value_to_string(&value))
        } else {
            Ok(String::new())
        }
    }

    fn get_value(&mut self, oid: &Oid) -> Result<OwnedValue> {
        let response = self.get(oid)?;

        if let Some((_, value)) = response.varbinds.next() {
            Ok(OwnedValue::from_value(&value))
        } else {
            Ok(OwnedValue::Null)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_subtree_exact_match() {
        assert!(is_subtree("1.3.6.1.4.1.41112", "1.3.6.1.4.1.41112"));
    }

    #[test]
    fn test_is_subtree_child() {
        assert!(is_subtree(
            "1.3.6.1.4.1.41112",
            "1.3.6.1.4.1.41112.1.4.7"
        ));
    }

    #[test]
    fn test_is_subtree_not_prefix_collision() {
        // This is the bug the old string prefix check had
        // "1.3.6.1.4.1.411" is a string prefix of "1.3.6.1.4.1.41112"
        // but not OID subtree parent
        assert!(!is_subtree(
            "1.3.6.1.4.1.41112",
            "1.3.6.1.4.1.411"
        ));
    }

    #[test]
    fn test_is_subtree_different_tree() {
        assert!(!is_subtree(
            "1.3.6.1.4.1.41112",
            "1.3.6.1.4.1.17713"
        ));
    }

    #[test]
    fn test_is_subtree_shorter() {
        assert!(!is_subtree(
            "1.3.6.1.4.1.41112.1.4.7.1.10",
            "1.3.6.1.4.1.41112"
        ));
    }

    #[test]
    #[ignore]
    fn test_walk_values_integration() {
        // Requires a live SNMP agent
    }
}
