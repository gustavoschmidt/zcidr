//! Shared C ABI conventions: status codes used across the FFI boundary.
//!
//! Functions that only signal success/failure return `Status` (a `c_int`).
//! Functions that return a length return a non-negative count on success or a
//! negative `Status` value on failure.

/// Success.
pub const OK: c_int = 0;
/// Input was not a valid address / CIDR for the requested family.
pub const ERR_INVALID: c_int = -1;
/// Caller-provided output buffer was too small.
pub const ERR_BUFFER: c_int = -2;
/// Allocation failed.
pub const ERR_NOMEM: c_int = -3;
/// Lookup found no matching entry.
pub const ERR_NOTFOUND: c_int = -4;
