//! TLS wire format, fixed to big-endian.
//!
//! RFC 8446 Appendix B — every multi-byte integer on the wire is big-endian,
//! so this pins the byte order once and keeps call sites from repeating it.
//! `stdx.wire` is the codec; this module is only the specialization.

const stdx = @import("stdx");

pub const Writer = stdx.wire.Writer(.big);
pub const Reader = stdx.wire.Reader(.big);
