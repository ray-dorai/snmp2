
Dependency-free basic SNMP v1/v2/v3 client in Rust, forked from [snmp2](https://github.com/roboplc/snmp2), which is focused on programmable logic controllers.

This fork is focused on **wireless networking equipment**.


## Quick start

Get a single value from a device:

```rust
use snmp2::{oid, SnmpClient};

fn main() -> Result {
    let client = SnmpClient::new("10.56.27.13:161", b"public");

    let freq = client.get(&oid!("1.3.6.1.4.1.161.19.3.1.7.37"))?;
    println!("Frequency: {}", freq);

    Ok(())
}
```

Walk a table (e.g. list all connected subscribers on an AP):

```rust
use snmp2::{oid, SnmpClient, parse_mac};

fn main() -> Result {
    let client = SnmpClient::new("10.56.27.13:161", b"public");

    let ips  = client.walk(&oid!("1.3.6.1.4.1.41112.1.4.7.1.10"))?;
    let macs = client.walk_bytes(&oid!("1.3.6.1.4.1.41112.1.4.7.1.1"))?;

    for (ip, mac_bytes) in ips.iter().zip(macs.iter()) {
        let mac = parse_mac(mac_bytes).unwrap_or_default();
        println!("{} - {}", ip, mac);
    }

    Ok(())
}

## Getting data out

There are a few ways to read values depending on what you need:

| Method | Returns | Use when |
|--------|---------|----------|
| `client.get(&oid)` | `String` | You just need text (IPs, names, frequencies) |
| `client.get_value(&oid)` | `OwnedValue` | You need the actual SNMP type (integer, bytes, etc.) |
| `client.walk(&oid)` | `Vec<String>` | Walking a table, text values are fine |
| `client.walk_bytes(&oid)` | `Vec<Vec<u8>>` | Walking a table with binary data (MACs) |
| `client.walk_values(&oid)` | `Vec<(Oid, OwnedValue)>` | You need both the OID and typed value |

### Typed values

`OwnedValue` keeps the original SNMP type so you can pull out exactly what you need:

```rust
use snmp2::{oid, SnmpClient};

let client = SnmpClient::new("10.56.27.13:161", b"public");
let value = client.get_value(&oid!("1.3.6.1.4.1.161.19.3.1.7.37"))?;

if let Some(freq) = value.as_i64() {
    println!("Frequency: {} kHz", freq);
}
```

Methods on `OwnedValue`: `as_i64()`, `as_u64()`, `as_bytes()`, `as_str()`, `as_ipv4()`, `is_error()`, `to_string_lossy()`.

## OIDs

Use the `oid!` macro for hardcoded OIDs. It panics on typos so you catch mistakes early:

```rust
use snmp2::oid;

let freq_oid  = oid!("1.3.6.1.4.1.41112.1.4.1.1.4");
let freq_oid2 = oid!(".1.3.6.1.4.1.41112.1.4.1.1.4");  // leading dot is fine
```

If you're building OIDs from user input, use `parse_oid()` which returns a `Result` instead:

```rust
use snmp2::parse_oid;

let oid = parse_oid("1.3.6.1.2.1.1.1.0")?;
```

## MAC addresses

SNMP devices return MACs in all sorts of formats. `parse_mac` handles the common ones:

```rust
use snmp2::parse_mac;

// Raw 6 bytes (most common from SNMP walks)
parse_mac(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
// -> Some("aa:bb:cc:dd:ee:ff")

// Already formatted string
parse_mac(b"AA:BB:CC:DD:EE:FF");
// -> Some("aa:bb:cc:dd:ee:ff")

// Hex string
parse_mac(b"aabbccddeeff");
// -> Some("aa:bb:cc:dd:ee:ff")
```

There's also `format_mac(&[u8])` for raw bytes to `aa:bb:cc:dd:ee:ff`, and `format_mac_dashed` for `aa-bb-cc-dd-ee-ff`.

## Distance conversion

Wireless radios report distance in different units. Two helpers for the common conversions:

```rust
use snmp2::{meters_to_miles, bits_to_miles};

// Ubiquiti/ePMP: distance in meters
let miles = meters_to_miles(1609.344);  // -> 1.0

// Cambium FSK/PMP: distance in "bits" (bits * 49.25 * 0.304 = meters)
let miles = bits_to_miles(100);
```

## Lower-level access

If you need more control (e.g. holding one session open for multiple calls), use `SyncSession` and `SessionExt` directly:

```rust
use snmp2::{SyncSession, SessionExt, parse_oid};

let mut session = SyncSession::new_v2c("10.56.27.13:161", b"public", None, 0)?;

let oid = parse_oid("1.3.6.1.4.1.41112.1.4.7.1.10")?;
let ips = session.walk_strings(&oid)?;
let values = session.walk_values(&oid)?;
```

## Full example: scraping an AirOS AP

```rust
use snmp2::{oid, SnmpClient, parse_mac, meters_to_miles};

fn scrape_airos_children(ip: &str, community: &[u8]) {
    let client = SnmpClient::new(&format!("{}:161", ip), community);

    let ips       = client.walk(&oid!("1.3.6.1.4.1.41112.1.4.7.1.10")).unwrap_or_default();
    let macs      = client.walk_bytes(&oid!("1.3.6.1.4.1.41112.1.4.7.1.1")).unwrap_or_default();
    let names     = client.walk(&oid!("1.3.6.1.4.1.41112.1.4.7.1.2")).unwrap_or_default();
    let distances = client.walk(&oid!("1.3.6.1.4.1.41112.1.4.7.1.5")).unwrap_or_default();

    if ips.len() != macs.len() || ips.len() != names.len() || ips.len() != distances.len() {
        println!("Table length mismatch, skipping {}", ip);
        return;
    }

    for i in 0..ips.len() {
        let mac = parse_mac(&macs[i]).unwrap_or_else(|| format!("Unknown-{}", i));
        let dist: f64 = distances[i].parse().unwrap_or(0.0);

        println!("{} | {} | {} | {:.3} mi",
            ips[i], mac, names[i], meters_to_miles(dist));
    }
}
```


## Copyright for RUST SNMP2

Copyright 2016-2018 Hroi Sigurdsson

Copyright 2024 Serhij Symonenko, [Bohemia Automation Limited](https://www.bohemia-automation.com)

Licensed under the [Apache License, Version
2.0](http://www.apache.org/licenses/LICENSE-2.0) or the [MIT
license](http://opensource.org/licenses/MIT), at your option. This file may not
be copied, modified, or distributed except according to those terms.
