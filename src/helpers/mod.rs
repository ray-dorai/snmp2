//! Convenience helpers and extensions for ergonomic SNMP operations.
//!
//! This module provides:
//! - OID string parsing and the `oid!` macro (`parse_oid`)
//! - Session extensions for walk operations with type preservation (`SessionExt`)
//! - Owned value type for data that outlives the receive buffer (`OwnedValue`)
//! - Value extraction helpers (`ValueExt`)
//! - Version fallback client with retry logic (`SnmpClient`)
//! - Network utilities: MAC formatting, distance conversion (`format_mac`, `meters_to_miles`)

mod client;
mod net;
mod oid;
mod session;
mod value;

pub use client::SnmpClient;
pub use net::{bits_to_miles, format_mac, format_mac_dashed, meters_to_miles, parse_mac};
pub use oid::parse_oid;
pub use session::SessionExt;
pub use value::{value_to_string, OwnedValue, ValueExt};
