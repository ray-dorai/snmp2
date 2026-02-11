/// Network-related SNMP utility functions.
///
/// Provides common conversions needed when working with SNMP data from
/// wireless access points and network equipment.

/// Format raw bytes as a colon-separated MAC address string.
///
/// Handles the common SNMP case where MAC addresses are returned as
/// 6-byte OctetStrings.
///
/// # Examples
/// ```
/// use snmp2::helpers::format_mac;
///
/// let bytes = &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
/// assert_eq!(format_mac(bytes), "aa:bb:cc:dd:ee:ff");
///
/// // Handles non-standard lengths gracefully
/// let short = &[0x01, 0x02];
/// assert_eq!(format_mac(short), "01:02");
///
/// // Empty input
/// assert_eq!(format_mac(&[]), "");
/// ```
pub fn format_mac(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Format raw bytes as a dash-separated MAC address string (Cambium/CBRS style).
///
/// # Examples
/// ```
/// use snmp2::helpers::format_mac_dashed;
///
/// let bytes = &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
/// assert_eq!(format_mac_dashed(bytes), "aa-bb-cc-dd-ee-ff");
/// ```
pub fn format_mac_dashed(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("-")
}

/// Try to parse a MAC address from SNMP response bytes.
///
/// SNMP agents return MACs in different formats:
/// - Raw 6 bytes (most common): `[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]`
/// - Hex string: `"aabbccddeeff"` or `"0xaabbccddeeff"`
/// - Already formatted: `"aa:bb:cc:dd:ee:ff"`
///
/// This function handles all three cases and returns a normalized
/// colon-separated lowercase MAC string.
///
/// # Examples
/// ```
/// use snmp2::helpers::parse_mac;
///
/// // Raw bytes (most common from easysnmp / snmp2)
/// assert_eq!(parse_mac(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]), Some("aa:bb:cc:dd:ee:ff".to_string()));
///
/// // Already formatted string
/// assert_eq!(parse_mac(b"aa:bb:cc:dd:ee:ff"), Some("aa:bb:cc:dd:ee:ff".to_string()));
///
/// // Hex string
/// assert_eq!(parse_mac(b"aabbccddeeff"), Some("aa:bb:cc:dd:ee:ff".to_string()));
///
/// // Invalid
/// assert_eq!(parse_mac(&[0x01, 0x02]), None);
/// ```
pub fn parse_mac(bytes: &[u8]) -> Option<String> {
    // Case 1: Raw 6-byte MAC
    if bytes.len() == 6 && !bytes.iter().all(|b| b.is_ascii()) {
        return Some(format_mac(bytes));
    }

    // Case 2: It's a string representation
    if let Ok(s) = std::str::from_utf8(bytes) {
        let s = s.trim();

        // Already formatted "aa:bb:cc:dd:ee:ff"
        if s.len() == 17 && s.chars().filter(|&c| c == ':').count() == 5 {
            return Some(s.to_lowercase());
        }

        // Already formatted "aa-bb-cc-dd-ee-ff"
        if s.len() == 17 && s.chars().filter(|&c| c == '-').count() == 5 {
            return Some(s.replace('-', ":").to_lowercase());
        }

        // Hex string "aabbccddeeff" or "0xaabbccddeeff"
        let hex = s.strip_prefix("0x").unwrap_or(s);
        if hex.len() == 12 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            let formatted: String = hex
                .as_bytes()
                .chunks(2)
                .map(|chunk| std::str::from_utf8(chunk).unwrap_or("00"))
                .collect::<Vec<_>>()
                .join(":");
            return Some(formatted.to_lowercase());
        }
    }

    // Case 3: 6 bytes that happen to be valid ASCII (rare edge case)
    // Re-check: if it's exactly 6 bytes, assume raw MAC regardless
    if bytes.len() == 6 {
        return Some(format_mac(bytes));
    }

    None
}

/// Convert meters to miles, rounded to 3 decimal places.
///
/// # Examples
/// ```
/// use snmp2::helpers::meters_to_miles;
///
/// assert_eq!(meters_to_miles(1609.344), 1.0);
/// assert_eq!(meters_to_miles(0.0), 0.0);
/// ```
pub fn meters_to_miles(meters: f64) -> f64 {
    (meters * 0.000_621_371 * 1000.0).round() / 1000.0
}

/// Convert Cambium FSK/PMP distance bits to miles.
///
/// FSK and PMP radios report distance as "bits" which need to be converted:
/// bits -> feet (×49.25) -> meters (×0.304) -> miles
///
/// # Examples
/// ```
/// use snmp2::helpers::bits_to_miles;
///
/// let distance_bits = 100;
/// let miles = bits_to_miles(distance_bits);
/// assert!(miles > 0.0);
/// ```
pub fn bits_to_miles(bits: u64) -> f64 {
    let meters = bits as f64 * 49.25 * 0.304;
    meters_to_miles(meters)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_mac() {
        assert_eq!(
            format_mac(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(
            format_mac(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            "00:11:22:33:44:55"
        );
        assert_eq!(format_mac(&[]), "");
    }

    #[test]
    fn test_format_mac_dashed() {
        assert_eq!(
            format_mac_dashed(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            "aa-bb-cc-dd-ee-ff"
        );
    }

    #[test]
    fn test_parse_mac_raw_bytes() {
        assert_eq!(
            parse_mac(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
    }

    #[test]
    fn test_parse_mac_colon_formatted() {
        assert_eq!(
            parse_mac(b"AA:BB:CC:DD:EE:FF"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
    }

    #[test]
    fn test_parse_mac_dash_formatted() {
        assert_eq!(
            parse_mac(b"AA-BB-CC-DD-EE-FF"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
    }

    #[test]
    fn test_parse_mac_hex_string() {
        assert_eq!(
            parse_mac(b"aabbccddeeff"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
    }

    #[test]
    fn test_parse_mac_hex_string_0x() {
        assert_eq!(
            parse_mac(b"0xaabbccddeeff"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
    }

    #[test]
    fn test_parse_mac_invalid() {
        assert_eq!(parse_mac(&[0x01, 0x02]), None);
        assert_eq!(parse_mac(b"not-a-mac"), None);
        assert_eq!(parse_mac(&[]), None);
    }

    #[test]
    fn test_meters_to_miles() {
        assert_eq!(meters_to_miles(0.0), 0.0);
        // 1 mile ≈ 1609.344 meters
        let miles = meters_to_miles(1609.344);
        assert!((miles - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_bits_to_miles() {
        let miles = bits_to_miles(100);
        assert!(miles > 0.0);
        assert_eq!(bits_to_miles(0), 0.0);
    }
}
