use crate::Value;

/// Extension trait for Value with convenience extraction methods
///
/// This trait provides ergonomic methods to extract values from SNMP responses
/// without verbose pattern matching.
pub trait ValueExt {
    /// Convert value to string representation (lossy for binary data)
    ///
    /// # Examples
    /// ```
    /// use snmp2::{Value, helpers::ValueExt};
    ///
    /// let val = Value::Integer(42);
    /// assert_eq!(val.to_string_lossy(), "42");
    ///
    /// let val = Value::IpAddress([192, 168, 1, 1]);
    /// assert_eq!(val.to_string_lossy(), "192.168.1.1");
    /// ```
    fn to_string_lossy(&self) -> String;
    
    /// Extract as signed integer if possible (works for Integer, Counter32, etc.)
    ///
    /// Returns `Some(i64)` for Integer, Counter32, Unsigned32, Timeticks, and Counter64 types.
    /// Returns `None` for other types.
    fn as_i64(&self) -> Option<i64>;
    
    /// Extract as unsigned integer if possible
    ///
    /// Returns `Some(u64)` for Counter32, Unsigned32, Timeticks, and Counter64 types.
    /// Returns `None` for other types or negative integers.
    fn as_u64(&self) -> Option<u64>;
    
    /// Extract as byte slice if this is an OctetString
    fn as_bytes(&self) -> Option<&[u8]>;
    
    /// Extract as UTF-8 string if possible
    ///
    /// Returns `Some(&str)` if the value is an OctetString containing valid UTF-8.
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
///
/// This is used internally by `ValueExt::to_string_lossy()` and is also
/// used by the session helpers.
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
    fn test_value_ext_integer() {
        let val = Value::Integer(42);
        assert_eq!(val.as_i64(), Some(42));
        assert_eq!(val.to_string_lossy(), "42");
    }
    
    #[test]
    fn test_value_ext_negative_integer() {
        let val = Value::Integer(-42);
        assert_eq!(val.as_i64(), Some(-42));
        assert_eq!(val.as_u64(), None); // Negative can't be u64
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
        // i64::MAX is smaller, so this should fail
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
        assert_eq!(val.as_str(), None); // Invalid UTF-8
        assert!(val.as_bytes().is_some());
    }
    
    #[test]
    fn test_value_ext_ip() {
        let val = Value::IpAddress([192, 168, 1, 1]);
        assert_eq!(val.as_ipv4(), Some(std::net::Ipv4Addr::new(192, 168, 1, 1)));
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
