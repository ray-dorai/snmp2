use crate::{Oid, Result, SyncSession};
use super::value::value_to_string;

/// Extension trait for SyncSession providing convenience methods
///
/// This trait adds higher-level operations on top of the basic SNMP operations.
pub trait SessionExt {
    /// Walk an SNMP tree starting at the specified OID, returning (OID, Value) pairs
    ///
    /// This performs multiple GETNEXT operations until the returned OID is no longer
    /// a descendant of the base OID.
    ///
    /// # Examples
    /// ```no_run
    /// use snmp2::{SyncSession, helpers::{SessionExt, parse_oid}};
    ///
    /// let mut session = SyncSession::new_v2c("192.168.1.1:161", b"public", None, 0)?;
    /// let oid = parse_oid("1.3.6.1.2.1.2.2.1")?; // ifTable
    ///
    /// let results = session.walk(&oid)?;
    /// for (oid, value) in results {
    ///     println!("{} = {}", oid, value);
    /// }
    /// # Ok::<(), snmp2::Error>(())
    /// ```
    fn walk(&mut self, oid: &Oid) -> Result<Vec<(Oid<'static>, String)>>;
    
    /// Walk an SNMP tree and return only the values as strings
    ///
    /// This is a convenience method that returns just the values without OIDs.
    ///
    /// # Examples
    /// ```no_run
    /// use snmp2::{SyncSession, helpers::{SessionExt, parse_oid}};
    ///
    /// let mut session = SyncSession::new_v2c("192.168.1.1:161", b"public", None, 0)?;
    /// let oid = parse_oid("1.3.6.1.4.1.41112.1.4.7.1.10")?; // IP addresses
    ///
    /// let ips = session.walk_strings(&oid)?;
    /// for ip in ips {
    ///     println!("IP: {}", ip);
    /// }
    /// # Ok::<(), snmp2::Error>(())
    /// ```
    fn walk_strings(&mut self, oid: &Oid) -> Result<Vec<String>>;
    
    /// Get a single value and convert to string
    ///
    /// This is a convenience method that combines `get()` with string conversion.
    ///
    /// # Examples
    /// ```no_run
    /// use snmp2::{SyncSession, helpers::{SessionExt, parse_oid}};
    ///
    /// let mut session = SyncSession::new_v2c("192.168.1.1:161", b"public", None, 0)?;
    /// let oid = parse_oid("1.3.6.1.2.1.1.1.0")?; // sysDescr
    ///
    /// let sys_descr = session.get_string(&oid)?;
    /// println!("System Description: {}", sys_descr);
    /// # Ok::<(), snmp2::Error>(())
    /// ```
    fn get_string(&mut self, oid: &Oid) -> Result<String>;
}

impl SessionExt for SyncSession {
    fn walk(&mut self, oid: &Oid) -> Result<Vec<(Oid<'static>, String)>> {
        let mut results = Vec::new();
        let mut current_oid = oid.clone();
        let base_str = oid.to_string();
        
        loop {
            let response = self.getnext(&current_oid)?;
            
            if let Some((next_oid, value)) = response.varbinds.next() {
                let next_oid_str = next_oid.to_string();
                
                // Check if still in subtree
                if !next_oid_str.starts_with(&base_str) {
                    break;
                }
                
                results.push((next_oid.to_owned(), value_to_string(&value)));
                current_oid = next_oid.to_owned();
            } else {
                break;
            }
        }
        
        Ok(results)
    }
    
    fn walk_strings(&mut self, oid: &Oid) -> Result<Vec<String>> {
        Ok(self.walk(oid)?
            .into_iter()
            .map(|(_, v)| v)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Note: These would need actual SNMP agents to test properly
    // For now, they're marked as integration tests
    
    #[test]
    #[ignore]
    fn test_walk_integration() {
        // This would require a test SNMP agent
        // Left as an exercise for integration testing
    }
}
