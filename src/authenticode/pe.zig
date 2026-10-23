//! Portable Executable (PE32 / PE32+) Authenticode parser, hasher, and signer.
//!
//! Authenticode for PE executables (.exe) and dynamic libraries (.dll) operates
//! by calculating a cryptographic hash over the binary headers and sections while
//! explicitly skipping:
//! 1. The 4-byte `CheckSum` in the PE Optional Header.
//! 2. The 8-byte `IMAGE_DIRECTORY_ENTRY_SECURITY` entry in the Optional Header Data
//!    Directories (offset + size of the Certificate Table).
//! 3. The Certificate Table itself appended at the end of the file.
//!
//! Signature Table (`WIN_CERTIFICATE`):
//! - `dwLength: u32` (8-byte header + CMS SignedData DER payload)
//! - `wRevision: u16 = 0x0200` (WIN_CERT_REVISION_2_0)
//! - `wCertificateType: u16 = 0x0002` (WIN_CERT_TYPE_PKCS_SIGNED_DATA)
//! - `bCertificate: [dwLength - 8]u8` (CMS SignedData ASN.1 DER)
//! The entire table entry is aligned to an 8-byte boundary with zero padding.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const HashAlgorithm = @import("msi.zig").HashAlgorithm;

/// Magic signature at byte 0 of an MS-DOS header ("MZ").
pub const dos_magic = [2]u8{ 'M', 'Z' };

/// Magic signature at `e_lfanew` of a PE file ("PE\0\0").
pub const pe_signature = [4]u8{ 'P', 'E', 0, 0 };

/// Optional Header magic numbers.
pub const pe32_magic: u16 = 0x010B;
pub const pe32_plus_magic: u16 = 0x020B;

/// Revision constant for WIN_CERTIFICATE structure (version 2.0).
pub const win_cert_revision_2_0: u16 = 0x0200;

/// Certificate type constant for PKCS#7 / CMS SignedData.
pub const win_cert_type_pkcs_signed_data: u16 = 0x0002;

/// Parsed metadata for a Portable Executable file.
pub const PeInfo = struct {
    /// True if 64-bit PE32+, false if 32-bit PE32.
    is_pe64: bool,
    /// Offset of the PE signature ("PE\0\0").
    pe_offset: usize,
    /// File offset of the 4-byte CheckSum field in Optional Header.
    checksum_offset: usize,
    /// File offset of the 8-byte Certificate Table Data Directory entry.
    security_dir_offset: usize,
    /// VirtualAddress (file offset) of the Certificate Table (0 if unsigned).
    cert_table_offset: u32,
    /// Size in bytes of the Certificate Table (0 if unsigned).
    cert_table_size: u32,
    /// Offset where binary hashing ends (before Certificate Table if signed, or EOF).
    fileend: usize,
    /// True if the file carries a digital signature in the Certificate Table.
    is_signed: bool,
};

/// Errors encountered while parsing PE headers.
pub const PeError = error{
    InvalidDosHeader,
    InvalidPeSignature,
    UnsupportedOptionalHeaderMagic,
    UnexpectedEof,
    InvalidCertificateTable,
};

/// Reports whether the given byte slice begins with a valid MS-DOS and PE header.
pub fn isPe(bytes: []const u8) bool {
    _ = parsePe(bytes) catch return false;
    return true;
}

/// Parses the PE headers and returns structural layout offsets.
pub fn parsePe(bytes: []const u8) PeError!PeInfo {
    // 1. Validate DOS Header
    if (bytes.len < 0x40) return error.InvalidDosHeader;
    if (!mem.eql(u8, bytes[0..2], &dos_magic)) return error.InvalidDosHeader;

    const e_lfanew: usize = mem.readInt(u32, bytes[0x3c..0x40], .little);
    if (e_lfanew + 24 > bytes.len) return error.UnexpectedEof;

    // 2. Validate PE Signature ("PE\0\0")
    if (!mem.eql(u8, bytes[e_lfanew..][0..4], &pe_signature)) {
        return error.InvalidPeSignature;
    }

    // 3. Inspect Optional Header
    const opt_offset = e_lfanew + 24;
    if (opt_offset + 2 > bytes.len) return error.UnexpectedEof;
    const opt_magic = mem.readInt(u16, bytes[opt_offset..][0..2], .little);

    const is_pe64 = switch (opt_magic) {
        pe32_plus_magic => true,
        pe32_magic => false,
        else => return error.UnsupportedOptionalHeaderMagic,
    };

    // CheckSum field is at offset 64 in both PE32 and PE32+ Optional Header.
    const checksum_offset = opt_offset + 64;

    // Data Directory index 4 (IMAGE_DIRECTORY_ENTRY_SECURITY):
    // PE32:  OptionalHeader offset 96 + 4 * 8 = 128
    // PE32+: OptionalHeader offset 112 + 4 * 8 = 144
    const sec_dir_rel: usize = if (is_pe64) 144 else 128;
    const sec_dir_offset = opt_offset + sec_dir_rel;

    if (sec_dir_offset + 8 > bytes.len) return error.UnexpectedEof;

    const cert_va = mem.readInt(u32, bytes[sec_dir_offset..][0..4], .little);
    const cert_sz = mem.readInt(u32, bytes[sec_dir_offset + 4 ..][0..4], .little);

    const is_signed = (cert_va != 0 and cert_sz != 0);
    const fileend: usize = if (is_signed) cert_va else bytes.len;

    if (fileend > bytes.len or fileend < sec_dir_offset + 8) return error.InvalidCertificateTable;

    return .{
        .is_pe64 = is_pe64,
        .pe_offset = e_lfanew,
        .checksum_offset = checksum_offset,
        .security_dir_offset = sec_dir_offset,
        .cert_table_offset = cert_va,
        .cert_table_size = cert_sz,
        .fileend = fileend,
        .is_signed = is_signed,
    };
}

/// Reports whether the PE binary is digitally signed.
pub fn isSigned(bytes: []const u8) !bool {
    const info = try parsePe(bytes);
    return info.is_signed;
}

/// Computes the PE Authenticode message digest over the binary.
///
/// Hashing skips the CheckSum, the Security Directory entry, and any existing
/// certificate table, padding the hashed image to an 8-byte boundary with zeros
/// if unsigned.
pub fn computeDigest(
    allocator: Allocator,
    bytes: []const u8,
    algorithm: HashAlgorithm,
) ![]u8 {
    const info = try parsePe(bytes);
    var hasher = algorithm.hasher();

    // Hash everything except the CheckSum field and the Security Directory entry.
    hasher.update(bytes[0..info.checksum_offset]);
    hasher.update(bytes[info.checksum_offset + 4 .. info.security_dir_offset]);
    hasher.update(bytes[info.security_dir_offset + 8 .. info.fileend]);

    // Unsigned images are hashed as if zero-padded to the 8-byte boundary that
    // `appendSignature` inserts before the certificate table.
    if (!info.is_signed) {
        const zeros: [8]u8 = @splat(0);
        hasher.update(zeros[0..padTo8(info.fileend)]);
    }

    return hasher.finalAlloc(allocator);
}

/// Returns the number of zero bytes needed to align `len` to an 8-byte boundary.
fn padTo8(len: usize) usize {
    return (8 - len % 8) % 8;
}

/// Computes the standard Windows PE CheckSum over the modified binary bytes.
pub fn computePeChecksum(bytes: []const u8, checksum_offset: usize) u32 {
    var sum: u64 = 0;
    var i: usize = 0;

    while (i + 1 < bytes.len) : (i += 2) {
        if (i == checksum_offset or i == checksum_offset + 2) {
            // Treat the 4-byte CheckSum field itself as zero
            continue;
        }
        const word: u16 = mem.readInt(u16, bytes[i..][0..2], .little);
        sum += word;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Handle trailing odd byte if any
    if (i < bytes.len) {
        const word: u16 = bytes[i];
        sum += word;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    sum = (sum & 0xFFFF) + (sum >> 16);
    return @intCast(sum + bytes.len);
}

/// Extracts the raw CMS SignedData DER payload from a signed PE binary, including
/// any trailing zero alignment padding. Returns null if the binary is unsigned.
pub fn extractSignature(bytes: []const u8) !?[]const u8 {
    const info = try parsePe(bytes);
    if (!info.is_signed) return null;

    const offset: usize = info.cert_table_offset;
    const size: usize = info.cert_table_size;

    if (offset + size > bytes.len or size < 8) {
        return error.InvalidCertificateTable;
    }

    const dwLength = mem.readInt(u32, bytes[offset..][0..4], .little);
    const wRevision = mem.readInt(u16, bytes[offset + 4 ..][0..2], .little);
    const wCertType = mem.readInt(u16, bytes[offset + 6 ..][0..2], .little);

    if (dwLength > size or wRevision != win_cert_revision_2_0 or
        wCertType != win_cert_type_pkcs_signed_data)
    {
        return error.InvalidCertificateTable;
    }

    return bytes[offset + 8 .. offset + dwLength];
}

/// Appends a `WIN_CERTIFICATE` entry containing `pkcs7_der` to an unsigned PE binary,
/// updates the Security Directory and PE CheckSum, and returns the signed binary slice.
///
/// The image is zero-padded to an 8-byte boundary before the table, and the table
/// itself is zero-padded so the file ends on an 8-byte boundary. `dwLength` and the
/// Security Directory size both include that trailing padding, so the certificate
/// table extends exactly to the end of the file.
pub fn appendSignature(
    allocator: Allocator,
    pe_bytes: []const u8,
    pkcs7_der: []const u8,
) ![]u8 {
    const info = try parsePe(pe_bytes);
    if (info.is_signed) return error.AlreadySigned;

    const cert_start = pe_bytes.len + padTo8(pe_bytes.len);
    const table_len = 8 + pkcs7_der.len + padTo8(pkcs7_der.len);
    const cert_va = std.math.cast(u32, cert_start) orelse return error.ImageTooLarge;
    const dw_length = std.math.cast(u32, table_len) orelse return error.ImageTooLarge;

    const out = try allocator.alloc(u8, cert_start + table_len);
    errdefer allocator.free(out);
    @memset(out, 0);
    @memcpy(out[0..pe_bytes.len], pe_bytes);

    // WIN_CERTIFICATE header followed by the CMS payload
    mem.writeInt(u32, out[cert_start..][0..4], dw_length, .little);
    mem.writeInt(u16, out[cert_start + 4 ..][0..2], win_cert_revision_2_0, .little);
    mem.writeInt(u16, out[cert_start + 6 ..][0..2], win_cert_type_pkcs_signed_data, .little);
    @memcpy(out[cert_start + 8 ..][0..pkcs7_der.len], pkcs7_der);

    // Update Security Directory in Optional Header
    mem.writeInt(u32, out[info.security_dir_offset..][0..4], cert_va, .little);
    mem.writeInt(u32, out[info.security_dir_offset + 4 ..][0..4], dw_length, .little);

    // Recalculate PE CheckSum
    const new_checksum = computePeChecksum(out, info.checksum_offset);
    mem.writeInt(u32, out[info.checksum_offset..][0..4], new_checksum, .little);

    return out;
}

const testing = std.testing;
const fixtures = @import("../fixtures.zig");

test "pe detection and parsing on mock.exe and mock.dll" {
    for ([_][]const u8{ "mock.exe", "mock.dll" }) |name| {
        const bytes = try fixtures.read(name);
        defer testing.allocator.free(bytes);

        const info = try parsePe(bytes);
        try testing.expect(info.is_pe64);
        try testing.expect(!info.is_signed);
        try testing.expectEqual(@as(u32, 0), info.cert_table_size);
    }
    try testing.expect(!isPe("MZ-not-a-real-executable"));
}

test "pe digest ignores CheckSum and Security Directory but covers everything else" {
    const exe = try fixtures.read("mock.exe");
    defer testing.allocator.free(exe);
    const info = try parsePe(exe);

    const base = try computeDigest(testing.allocator, exe, .sha384);
    defer testing.allocator.free(base);
    try testing.expectEqual(@as(usize, 48), base.len);

    exe[info.checksum_offset] ^= 0xFF;
    const same = try computeDigest(testing.allocator, exe, .sha384);
    defer testing.allocator.free(same);
    try testing.expectEqualSlices(u8, base, same);

    exe[info.checksum_offset - 1] ^= 0xFF;
    const changed = try computeDigest(testing.allocator, exe, .sha384);
    defer testing.allocator.free(changed);
    try testing.expect(!mem.eql(u8, base, changed));
}

test "pe appendSignature and extractSignature roundtrip" {
    const alloc = testing.allocator;
    const exe_bytes = try fixtures.read("mock.exe");
    defer alloc.free(exe_bytes);

    const fake_cms = "dummy-cms-signature-content-for-testing-purposes!";
    const signed_exe = try appendSignature(alloc, exe_bytes, fake_cms);
    defer alloc.free(signed_exe);

    try testing.expect(try isSigned(signed_exe));
    try testing.expectError(error.AlreadySigned, appendSignature(alloc, signed_exe, fake_cms));

    // The certificate table is 8-byte aligned and extends exactly to the end of the file.
    const info = try parsePe(signed_exe);
    try testing.expectEqual(@as(usize, 0), signed_exe.len % 8);
    try testing.expectEqual(signed_exe.len, info.cert_table_offset + info.cert_table_size);

    const extracted = (try extractSignature(signed_exe)).?;
    try testing.expect(mem.startsWith(u8, extracted, fake_cms));

    // Signing must not change the Authenticode digest of the image.
    const digest_unsigned = try computeDigest(alloc, exe_bytes, .sha256);
    defer alloc.free(digest_unsigned);
    const digest_signed = try computeDigest(alloc, signed_exe, .sha256);
    defer alloc.free(digest_signed);
    try testing.expectEqualSlices(u8, digest_unsigned, digest_signed);
}
