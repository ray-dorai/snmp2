use crate::Value;

/// Owned necessary for operations like walk where each GETNEXT call
/// overwrites the session's receive buffer, invalidating any borrowed Values.
#[derive(Debug, Clone, PartialEq)]
pub enum OwnedValue {
    Boolean(bool),
    Null,
    Integer(i64),
    OctetString(Vec<u8>),
    ObjectIdentifier(String),
    IpAddress([u8; 4]),
    Counter32(u32),
    Unsigned32(u32),
    Timeticks(u32),
    Opaque(Vec<u8>),
    Counter64(u64),
    EndOfMibView,
    NoSuchObject,
    NoSuchInstance,
}

impl OwnedValue {
    /// Convert a borrowed Value into an OwnedValue
    pub fn from_value(value: &Value) -> Self {
        match value {
            Value::Boolean(b) => OwnedValue::Boolean(*b),
            Value::Null => OwnedValue::Null,
            Value::Integer(i) => OwnedValue::Integer(*i),
            Value::OctetString(s) => OwnedValue::OctetString(s.to_vec()),
            Value::ObjectIdentifier(oid) => OwnedValue::ObjectIdentifier(oid.to_string()),
            Value::IpAddress(ip) => OwnedValue::IpAddress(*ip),
            Value::Counter32(c) => OwnedValue::Counter32(*c),
            Value::Unsigned32(u) => OwnedValue::Unsigned32(*u),
            Value::Timeticks(t) => OwnedValue::Timeticks(*t),
            Value::Opaque(o) => OwnedValue::Opaque(o.to_vec()),
            Value::Counter64(c) => OwnedValue::Counter64(*c),
            Value::EndOfMibView => OwnedValue::EndOfMibView,
            Value::NoSuchObject => OwnedValue::NoSuchObject,
            Value::NoSuchInstance => OwnedValue::NoSuchInstance,
            // Constructed/Request/Response types don't make sense as owned walk results
            _ => OwnedValue::Null,
        }
    }

    /// Convert to string representation (lossy for binary data)
    pub fn to_string_lossy(&self) -> String {
        match self {
            OwnedValue::Boolean(b) => b.to_string(),
            OwnedValue::Null => String::from("null"),
            OwnedValue::Integer(i) => i.to_string(),
            OwnedValue::OctetString(s) => String::from_utf8_lossy(s).to_string(),
            OwnedValue::ObjectIdentifier(oid) => oid.clone(),
            OwnedValue::IpAddress(ip) => format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
            OwnedValue::Counter32(c) => c.to_string(),
            OwnedValue::Unsigned32(u) => u.to_string(),
            OwnedValue::Timeticks(t) => t.to_string(),
            OwnedValue::Opaque(bytes) => format!("Opaque({} bytes)", bytes.len()),
            OwnedValue::Counter64(c) => c.to_string(),
            OwnedValue::EndOfMibView => String::from("EndOfMibView"),
            OwnedValue::NoSuchObject => String::from("NoSuchObject"),
            OwnedValue::NoSuchInstance => String::from("NoSuchInstance"),
        }
    }

    /// Extract as signed integer if possible
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            OwnedValue::Integer(i) => Some(*i),
            OwnedValue::Counter32(c) => Some(i64::from(*c)),
            OwnedValue::Unsigned32(u) => Some(i64::from(*u)),
            OwnedValue::Timeticks(t) => Some(i64::from(*t)),
            OwnedValue::Counter64(c) => i64::try_from(*c).ok(),
            _ => None,
        }
    }

    /// Extract as unsigned integer if possible
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            OwnedValue::Counter32(c) => Some(u64::from(*c)),
            OwnedValue::Unsigned32(u) => Some(u64::from(*u)),
            OwnedValue::Timeticks(t) => Some(u64::from(*t)),
            OwnedValue::Counter64(c) => Some(*c),
            OwnedValue::Integer(i) => u64::try_from(*i).ok(),
            _ => None,
        }
    }

    /// Extract raw bytes if this is an OctetString or Opaque
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            OwnedValue::OctetString(s) => Some(s),
            OwnedValue::Opaque(o) => Some(o),
            _ => None,
        }
    }

    /// Extract as UTF-8 string if possible
    pub fn as_str(&self) -> Option<&str> {
        if let OwnedValue::OctetString(s) = self {
            std::str::from_utf8(s).ok()
        } else {
            None
        }
    }

    /// Extract as IPv4 address
    pub fn as_ipv4(&self) -> Option<std::net::Ipv4Addr> {
        if let OwnedValue::IpAddress(ip) = self {
            Some(std::net::Ipv4Addr::from(*ip))
        } else {
            None
        }
    }

    /// Check if this value indicates end-of-mib or no-such-object/instance
    pub fn is_error(&self) -> bool {
        matches!(
            self,
            OwnedValue::EndOfMibView | OwnedValue::NoSuchObject | OwnedValue::NoSuchInstance
        )
    }
}

/// Extension trait for Value with convenience extraction methods
///
/// This trait provides ergonomic methods to extract values from SNMP responses
/// without verbose pattern matching.
pub trait ValueExt {
    /// Convert value to string representation (lossy for binary data)
    fn to_string_lossy(&self) -> String;

    /// Extract as signed integer if possible (works for Integer, Counter32, etc.)
    fn as_i64(&self) -> Option<i64>;

    /// Extract as unsigned integer if possible
    fn as_u64(&self) -> Option<u64>;

    /// Extract as byte slice if this is an OctetString
    fn as_bytes(&self) -> Option<&[u8]>;

    /// Extract as UTF-8 string if possible
    fn as_str(&self) -> Option<&str>;

    /// Extract as IPv4 address if this is an IpAddress
    fn as_ipv4(&self) -> Option<std::net::Ipv4Addr>;
}

impl<'a> ValueExt for Value<'a> {
    fn to_string_lossy(&self) -> String {
        value_to_string(self)
    }

    fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Integer(i) => Some(*i),
            Value::Counter32(c) => Some(i64::from(*c)),
            Value::Unsigned32(u) => Some(i64::from(*u)),
            Value::Timeticks(t) => Some(i64::from(*t)),
            Value::Counter64(c) => i64::try_from(*c).ok(),
            _ => None,
        }
    }

    fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Counter32(c) => Some(u64::from(*c)),
            Value::Unsigned32(u) => Some(u64::from(*u)),
            Value::Timeticks(t) => Some(u64::from(*t)),
            Value::Counter64(c) => Some(*c),
            Value::Integer(i) => u64::try_from(*i).ok(),
            _ => None,
        }
    }

    fn as_bytes(&self) -> Option<&[u8]> {
        if let Value::OctetString(s) = self {
            Some(s)
        } else {
            None
        }
    }

    fn as_str(&self) -> Option<&str> {
        self.as_bytes().and_then(|b| std::str::from_utf8(b).ok())
    }

    fn as_ipv4(&self) -> Option<std::net::Ipv4Addr> {
        if let Value::IpAddress(ip) = self {
            Some(std::net::Ipv4Addr::from(*ip))
        } else {
            None
        }
    }
}

/// Convert an SNMP Value to a string representation
pub fn value_to_string(value: &Value) -> String {
    match value {
        Value::Integer(i) => i.to_string(),
        Value::OctetString(s) => String::from_utf8_lossy(s).to_string(),
        Value::ObjectIdentifier(oid) => oid.to_string(),
        Value::IpAddress(ip) => format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
        Value::Counter32(c) => c.to_string(),
        Value::Counter64(c) => c.to_string(),
        Value::Timeticks(t) => t.to_string(),
        Value::Unsigned32(u) => u.to_string(),
        Value::Null => String::from("null"),
        Value::EndOfMibView => String::from("EndOfMibView"),
        Value::NoSuchObject => String::from("NoSuchObject"),
        Value::NoSuchInstance => String::from("NoSuchInstance"),
        Value::Boolean(b) => b.to_string(),
        Value::Opaque(bytes) => format!("Opaque({} bytes)", bytes.len()),
        _ => String::from("<unknown>"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_owned_value_from_integer() {
        let val = Value::Integer(42);
        let owned = OwnedValue::from_value(&val);
        assert_eq!(owned, OwnedValue::Integer(42));
        assert_eq!(owned.as_i64(), Some(42));
        assert_eq!(owned.to_string_lossy(), "42");
    }

    #[test]
    fn test_owned_value_from_octet_string() {
        let data = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let val = Value::OctetString(&data);
        let owned = OwnedValue::from_value(&val);
        assert_eq!(owned.as_bytes(), Some(&data[..]));
    }

    #[test]
    fn test_owned_value_from_ip() {
        let val = Value::IpAddress([10, 56, 27, 13]);
        let owned = OwnedValue::from_value(&val);
        assert_eq!(
            owned.as_ipv4(),
            Some(std::net::Ipv4Addr::new(10, 56, 27, 13))
        );
        assert_eq!(owned.to_string_lossy(), "10.56.27.13");
    }

    #[test]
    fn test_owned_value_is_error() {
        assert!(OwnedValue::EndOfMibView.is_error());
        assert!(OwnedValue::NoSuchObject.is_error());
        assert!(OwnedValue::NoSuchInstance.is_error());
        assert!(!OwnedValue::Integer(42).is_error());
    }

    #[test]
    fn test_value_ext_integer() {
        let val = Value::Integer(42);
        assert_eq!(val.as_i64(), Some(42));
        assert_eq!(val.to_string_lossy(), "42");
    }

    #[test]
    fn test_value_ext_negative_integer() {
        let val = Value::Integer(-42);
        assert_eq!(val.as_i64(), Some(-42));
        assert_eq!(val.as_u64(), None);
    }

    #[test]
    fn test_value_ext_counter32() {
        let val = Value::Counter32(100);
        assert_eq!(val.as_u64(), Some(100));
        assert_eq!(val.as_i64(), Some(100));
        assert_eq!(val.to_string_lossy(), "100");
    }

    #[test]
    fn test_value_ext_counter64() {
        let val = Value::Counter64(18446744073709551615);
        assert_eq!(val.as_u64(), Some(18446744073709551615));
        assert_eq!(val.as_i64(), None);
    }

    #[test]
    fn test_value_ext_octet_string() {
        let val = Value::OctetString(b"test");
        assert_eq!(val.as_str(), Some("test"));
        assert_eq!(val.as_bytes(), Some(&b"test"[..]));
        assert_eq!(val.to_string_lossy(), "test");
    }

    #[test]
    fn test_value_ext_octet_string_invalid_utf8() {
        let val = Value::OctetString(&[0xFF, 0xFE, 0xFD]);
        assert_eq!(val.as_str(), None);
        assert!(val.as_bytes().is_some());
    }

    #[test]
    fn test_value_ext_ip() {
        let val = Value::IpAddress([192, 168, 1, 1]);
        assert_eq!(
            val.as_ipv4(),
            Some(std::net::Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(val.to_string_lossy(), "192.168.1.1");
    }

    #[test]
    fn test_value_ext_null() {
        let val = Value::Null;
        assert_eq!(val.as_i64(), None);
        assert_eq!(val.as_str(), None);
        assert_eq!(val.to_string_lossy(), "null");
    }
}
