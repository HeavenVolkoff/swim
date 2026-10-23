//! Windows Authenticode code signing engine for MSI packages and PE binaries.
//!
//! Submodules:
//! - `msi`: Canonical MSI stream collation and imprint computation.
//! - `pe`: Portable Executable (PE32/PE32+) parser, Authenticode hasher, and signer.
//! - `asn1`: Authenticode ASN.1 schemas (SpcIndirectDataContent, SpcSipInfo, SpcPeImageData).
//! - `signer`: Cryptographic signer (ECDSA P-384/P-256, RSA) and CMS SignedData generator.
//! - `verify`: In-tree signature verification oracles for unit and integration testing.
//! - `timestamp`: RFC 3161 HTTP Time-Stamp Authority client.

pub const msi = @import("authenticode/msi.zig");
pub const pe = @import("authenticode/pe.zig");
pub const asn1 = @import("authenticode/asn1.zig");
pub const signer = @import("authenticode/signer.zig");
pub const verify = @import("authenticode/verify.zig");
pub const timestamp = @import("authenticode/timestamp.zig");

test {
    const testing = @import("std").testing;
    testing.refAllDecls(@This());
    testing.refAllDecls(msi);
    testing.refAllDecls(pe);
    testing.refAllDecls(asn1);
    testing.refAllDecls(signer);
    testing.refAllDecls(verify);
    testing.refAllDecls(timestamp);
}
