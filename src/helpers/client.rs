use std::time::Duration;

use crate::{Oid, Result, SyncSession, Error};

use super::session::SessionExt;
use super::value::OwnedValue;

/// SNMP client with version fallback (v2c -> v1) and configurable retries.
///
/// This client simplifies SNMP operations by:
/// - trying SNMPv2c first, falling back to SNMPv1
/// - Retrying failed operations with exponential backoff
/// - Providing both typed and string-based return values
///
/// # Examples
/// ```no_run
/// use snmp2::helpers::{SnmpClient, parse_oid};
///
/// let client = SnmpClient::new("192.168.1.1:161", b"public")
///     .with_timeout(std::time::Duration::from_secs(5))
///     .with_retries(3);
///
/// let oid = parse_oid("1.3.6.1.2.1.1.1.0")?;
/// let value = client.get(&oid)?;
/// println!("sysDescr: {}", value);
/// # Ok::<(), snmp2::Error>(())
/// ```
pub struct SnmpClient {
    host: String,
    community: Vec<u8>,
    timeout: Option<Duration>,
    starting_req_id: i32,
    retries: u32,
    max_backoff_secs: u64,
}

impl SnmpClient {
    /// Create a new SNMP client with default settings (2s timeout, 3 retries).
    pub fn new(host: &str, community: &[u8]) -> Self {
        Self {
            host: host.to_string(),
            community: community.to_vec(),
            timeout: Some(Duration::from_secs(2)),
            starting_req_id: 0,
            retries: 3,
            max_backoff_secs: 8,
        }
    }

    /// Set a custom timeout per SNMP operation.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the number of retry attempts (default: 3).
    ///
    /// Each retry uses exponential backoff: sleep(min(2^attempt, max_backoff)).
    pub fn with_retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }

    /// Set the maximum backoff duration between retries (default: 8 seconds).
    pub fn with_max_backoff(mut self, secs: u64) -> Self {
        self.max_backoff_secs = secs;
        self
    }

    /// Set a custom starting request ID.
    pub fn with_req_id(mut self, req_id: i32) -> Self {
        self.starting_req_id = req_id;
        self
    }

    /// Calculate backoff sleep duration for a given attempt number.
    fn backoff_duration(&self, attempt: u32) -> Duration {
        let secs = (1u64 << attempt).min(self.max_backoff_secs);
        Duration::from_secs(secs)
    }

    /// Try to establish a v2c session, falling back to v1.
    fn connect_v2c(&self) -> std::result::Result<SyncSession, std::io::Error> {
        SyncSession::new_v2c(
            &self.host,
            &self.community,
            self.timeout,
            self.starting_req_id,
        )
    }

    fn connect_v1(&self) -> std::result::Result<SyncSession, std::io::Error> {
        SyncSession::new_v1(
            &self.host,
            &self.community,
            self.timeout,
            self.starting_req_id,
        )
    }

    /// Establish a session, trying v2c first, falling back to v1.
    ///
    /// If you need to perform multiple operations on the same device,
    /// use this to get a session and call methods on it directly.
    pub fn connect(&self) -> Result<SyncSession> {
        match self.connect_v2c() {
            Ok(session) => Ok(session),
            Err(_) => self.connect_v1().map_err(|_| Error::Send),
        }
    }

    /// Get a single OID value as a string, with retries and version fallback.
    ///
    /// retries with backoff, then tries v1 if v2c fails.
    pub fn get(&self, oid: &Oid) -> Result<String> {
        // Try v2c with retries
        if let Ok(mut session) = self.connect_v2c() {
            for attempt in 0..self.retries {
                match session.get_string(oid) {
                    Ok(val) if !val.is_empty() => return Ok(val),
                    Ok(_) => {}
                    Err(_) => {}
                }
                if attempt < self.retries - 1 {
                    std::thread::sleep(self.backoff_duration(attempt));
                }
            }
        }
        // Fall back to v1 with retries
        if let Ok(mut session) = self.connect_v1() {
            for attempt in 0..self.retries {
                match session.get_string(oid) {
                    Ok(val) if !val.is_empty() => return Ok(val),
                    Ok(_) => {}
                    Err(_) => {}
                }
                if attempt < self.retries - 1 {
                    std::thread::sleep(self.backoff_duration(attempt));
                }
            }
        }
        Ok(String::new())
    }

    /// Get a single OID value preserving type information, with retries.
    pub fn get_value(&self, oid: &Oid) -> Result<OwnedValue> {
        if let Ok(mut session) = self.connect_v2c() {
            for attempt in 0..self.retries {
                match session.get_value(oid) {
                    Ok(val) if !val.is_error() && val != OwnedValue::Null => return Ok(val),
                    Ok(_) => {}
                    Err(_) => {}
                }
                if attempt < self.retries - 1 {
                    std::thread::sleep(self.backoff_duration(attempt));
                }
            }
        }
        if let Ok(mut session) = self.connect_v1() {
            for attempt in 0..self.retries {
                match session.get_value(oid) {
                    Ok(val) if !val.is_error() && val != OwnedValue::Null => return Ok(val),
                    Ok(_) => {}
                    Err(_) => {}
                }
                if attempt < self.retries - 1 {
                    std::thread::sleep(self.backoff_duration(attempt));
                }
            }
        }
        Ok(OwnedValue::Null)
    }

    /// Walk an OID tree returning string values, with retries and version fallback.
    ///
    /// Mirrors the behavior of Python `snmpwalkNext()`.
    pub fn walk(&self, oid: &Oid) -> Result<Vec<String>> {
        // Try v2c with retries
        if let Ok(mut session) = self.connect_v2c() {
            for attempt in 0..self.retries {
                match session.walk_strings(oid) {
                    Ok(results) if !results.is_empty() => return Ok(results),
                    Ok(_) => {}
                    Err(_) => {}
                }
                if attempt < self.retries - 1 {
                    std::thread::sleep(self.backoff_duration(attempt));
                }
            }
        }
        // Fall back to v1 with retries
        if let Ok(mut session) = self.connect_v1() {
            for attempt in 0..self.retries {
                match session.walk_strings(oid) {
                    Ok(results) if !results.is_empty() => return Ok(results),
                    Ok(_) => {}
                    Err(_) => {}
                }
                if attempt < self.retries - 1 {
                    std::thread::sleep(self.backoff_duration(attempt));
                }
            }
        }
        Ok(Vec::new())
    }

    /// Walk an OID tree returning raw byte vectors, with retries and version fallback.
    ///
    /// This is the preferred method for walking tables that contain binary data
    /// like MAC addresses.
    pub fn walk_bytes(&self, oid: &Oid) -> Result<Vec<Vec<u8>>> {
        if let Ok(mut session) = self.connect_v2c() {
            for attempt in 0..self.retries {
                match session.walk_bytes(oid) {
                    Ok(results) if !results.is_empty() => return Ok(results),
                    Ok(_) => {}
                    Err(_) => {}
                }
                if attempt < self.retries - 1 {
                    std::thread::sleep(self.backoff_duration(attempt));
                }
            }
        }
        if let Ok(mut session) = self.connect_v1() {
            for attempt in 0..self.retries {
                match session.walk_bytes(oid) {
                    Ok(results) if !results.is_empty() => return Ok(results),
                    Ok(_) => {}
                    Err(_) => {}
                }
                if attempt < self.retries - 1 {
                    std::thread::sleep(self.backoff_duration(attempt));
                }
            }
        }
        Ok(Vec::new())
    }

    /// Walk an OID tree returning typed OwnedValues, with retries and version fallback.
    pub fn walk_values(&self, oid: &Oid) -> Result<Vec<(Oid<'static>, OwnedValue)>> {
        if let Ok(mut session) = self.connect_v2c() {
            for attempt in 0..self.retries {
                match session.walk_values(oid) {
                    Ok(results) if !results.is_empty() => return Ok(results),
                    Ok(_) => {}
                    Err(_) => {}
                }
                if attempt < self.retries - 1 {
                    std::thread::sleep(self.backoff_duration(attempt));
                }
            }
        }
        if let Ok(mut session) = self.connect_v1() {
            for attempt in 0..self.retries {
                match session.walk_values(oid) {
                    Ok(results) if !results.is_empty() => return Ok(results),
                    Ok(_) => {}
                    Err(_) => {}
                }
                if attempt < self.retries - 1 {
                    std::thread::sleep(self.backoff_duration(attempt));
                }
            }
        }
        Ok(Vec::new())
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
        assert_eq!(client.retries, 3);
    }

    #[test]
    fn test_client_with_timeout() {
        let client = SnmpClient::new("192.168.1.1:161", b"public")
            .with_timeout(Duration::from_secs(5));
        assert_eq!(client.timeout, Some(Duration::from_secs(5)));
    }

    #[test]
    fn test_client_with_retries() {
        let client = SnmpClient::new("192.168.1.1:161", b"public").with_retries(5);
        assert_eq!(client.retries, 5);
    }

    #[test]
    fn test_client_with_req_id() {
        let client = SnmpClient::new("192.168.1.1:161", b"public").with_req_id(12345);
        assert_eq!(client.starting_req_id, 12345);
    }

    #[test]
    fn test_backoff_duration() {
        let client = SnmpClient::new("192.168.1.1:161", b"public").with_max_backoff(8);
        assert_eq!(client.backoff_duration(0), Duration::from_secs(1));
        assert_eq!(client.backoff_duration(1), Duration::from_secs(2));
        assert_eq!(client.backoff_duration(2), Duration::from_secs(4));
        assert_eq!(client.backoff_duration(3), Duration::from_secs(8));
        assert_eq!(client.backoff_duration(4), Duration::from_secs(8)); // capped
    }

    #[test]
    fn test_client_builder_chain() {
        let client = SnmpClient::new("192.168.1.1:161", b"public")
            .with_timeout(Duration::from_secs(10))
            .with_retries(5)
            .with_max_backoff(16)
            .with_req_id(999);

        assert_eq!(client.timeout, Some(Duration::from_secs(10)));
        assert_eq!(client.retries, 5);
        assert_eq!(client.max_backoff_secs, 16);
        assert_eq!(client.starting_req_id, 999);
    }
}
