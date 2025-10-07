//! Convenience helpers and extensions for ergonomic SNMP operations.
//!
//! This module provides:
//! - OID string parsing (`parse_oid`)
//! - Session extensions for walk operations (`SessionExt`)
//! - Value extraction helpers (`ValueExt`)
//! - Version fallback client (`SnmpClient`)

mod oid;
mod session;
mod value;
mod client;

pub use oid::parse_oid;
pub use session::SessionExt;
pub use value::{ValueExt, value_to_string};
pub use client::SnmpClient;
