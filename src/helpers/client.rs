use crate::{Oid, Result, SyncSession};
use super::session::SessionExt;
use std::time::Duration;

/// SNMP client with automatic version fallback (v2c -> v1)
///
/// This client simplifies SNMP operations by automatically trying SNMPv2c first,
/// and falling back to SNMPv1 if the device doesn't support v2c.
///
/// # Examples
/// ```no_run
/// use snmp2::helpers::{SnmpClient, parse_oid};
///
/// let client = SnmpClient::new("192.168.1.1:161", b"public")
///     .with_timeout(std::time::Duration::from_secs(5));
///
/// let oid = parse_oid("1.3.6.1.2.1.1.1.0")?; // sysDescr
///
/// // Automatically tries v2c, falls back to v1 on error
/// let value = client.get(&oid)?;
/// println!("sysDescr: {}", value);
/// # Ok::<(), snmp2::Error>(())
/// ```
pub struct SnmpClient {
    host: String,
    community: Vec<u8>,
    timeout: Option<Duration>,
    starting_req_id: i32,
}

impl SnmpClient {
    /// Create a new SNMP client with default timeout (2 seconds)
    ///
    /// # Arguments
    /// * `host` - Target host address (e.g., "192.168.1.1:161")
    /// * `community` - SNMP community string (e.g., b"public")
    ///
    /// # Examples
    /// ```
    /// use snmp2::helpers::SnmpClient;
    ///
    /// let client = SnmpClient::new("192.168.1.1:161", b"public");
    /// ```
    pub fn new(host: &str, community: &[u8]) -> Self {
        Self {
            host: host.to_string(),
            community: community.to_vec(),
            timeout: Some(Duration::from_secs(2)),
            starting_req_id: 0,
        }
    }
    
    /// Set a custom timeout
    ///
    /// # Examples
    /// ```
    /// use snmp2::helpers::SnmpClient;
    /// use std::time::Duration;
    ///
    /// let client = SnmpClient::new("192.168.1.1:161", b"public")
    ///     .with_timeout(Duration::from_secs(5));
    /// ```
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
    
    /// Set a custom starting request ID
    ///
    /// This can be useful for debugging or when you need specific request IDs.
    pub fn with_req_id(mut self, req_id: i32) -> Self {
        self.starting_req_id = req_id;
        self
    }
    
    /// Establish a session, trying v2c first, falling back to v1
    ///
    /// This method is useful if you want to reuse the session for multiple operations.
    /// For single operations, consider using `get()` or `walk()` directly.
    ///
    /// # Examples
    /// ```no_run
    /// use snmp2::helpers::{SnmpClient, SessionExt, parse_oid};
    ///
    /// let client = SnmpClient::new("192.168.1.1:161", b"public");
    /// let mut session = client.connect()?;
    ///
    /// let oid = parse_oid("1.3.6.1.2.1.1.1.0")?;
    /// let value = session.get_string(&oid)?;
    /// # Ok::<(), snmp2::Error>(())
    /// ```
    pub fn connect(&self) -> Result<SyncSession> {
        // Try v2c first
        match SyncSession::new_v2c(
            &self.host,
            &self.community,
            self.timeout,
            self.starting_req_id,
        ) {
            Ok(session) => Ok(session),
            Err(_) => {
                // Fall back to v1
                SyncSession::new_v1(
                    &self.host,
                    &self.community,
                    self.timeout,
                    self.starting_req_id,
                )
            }
        }
    }
    
    /// Get a single value with automatic version fallback
    ///
    /// # Examples
    /// ```no_run
    /// use snmp2::helpers::{SnmpClient, parse_oid};
    ///
    /// let client = SnmpClient::new("192.168.1.1:161", b"public");
    /// let oid = parse_oid("1.3.6.1.2.1.1.1.0")?;
    /// let value = client.get(&oid)?;
    /// println!("Value: {}", value);
    /// # Ok::<(), snmp2::Error>(())
    /// ```
    pub fn get(&self, oid: &Oid) -> Result<String> {
        let mut session = self.connect()?;
        session.get_string(oid)
    }
    
    /// Walk an OID tree with automatic version fallback
    ///
    /// # Examples
    /// ```no_run
    /// use snmp2::helpers::{SnmpClient, parse_oid};
    ///
    /// let client = SnmpClient::new("192.168.1.1:161", b"public");
    /// let oid = parse_oid("1.3.6.1.2.1.2.2.1")?;
    /// let values = client.walk(&oid)?;
    ///
    /// for value in values {
    ///     println!("Value: {}", value);
    /// }
    /// # Ok::<(), snmp2::Error>(())
    /// ```
    pub fn walk(&self, oid: &Oid) -> Result<Vec<String>> {
        let mut session = self.connect()?;
        session.walk_strings(oid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = SnmpClient::new("192.168.1.1:161", b"public");
        assert_eq!(client.host, "192.168.1.1:161");
        assert_eq!(client.community, b"public");
        assert_eq!(client.timeout, Some(Duration::from_secs(2)));
    }
    
    #[test]
    fn test_client_with_timeout() {
        let client = SnmpClient::new("192.168.1.1:161", b"public")
            .with_timeout(Duration::from_secs(5));
        assert_eq!(client.timeout, Some(Duration::from_secs(5)));
    }
    
    #[test]
    fn test_client_with_req_id() {
        let client = SnmpClient::new("192.168.1.1:161", b"public")
            .with_req_id(12345);
        assert_eq!(client.starting_req_id, 12345);
    }
    
    #[test]
    fn test_client_builder_chain() {
        let client = SnmpClient::new("192.168.1.1:161", b"public")
            .with_timeout(Duration::from_secs(10))
            .with_req_id(999);
        
        assert_eq!(client.timeout, Some(Duration::from_secs(10)));
        assert_eq!(client.starting_req_id, 999);
    }
}
