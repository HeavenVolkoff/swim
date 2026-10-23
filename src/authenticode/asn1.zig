//! Authenticode ASN.1 DER schemas and serialization helpers.
//!
//! Implements PKCS#7 / CMS SignedData generation for Windows Authenticode:
//! - ContentInfo (OID 1.2.840.113549.1.7.2 - signedData)
//! - SignedData (RFC 2315 / RFC 5652)
//! - SpcIndirectDataContent (MSI SIP GUID or PE SpcPeImageData)
//! - Authenticode SignedAttributes (contentType, messageDigest, signingTime,
//!   spcStatementType, spcSpOpusInfo)

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const HashAlgorithm = @import("msi.zig").HashAlgorithm;

/// Target format for the Authenticode signature.
pub const Target = enum {
    msi,
    pe,
};

// Standard Cryptographic and Authenticode Object Identifiers (OIDs) in DER.
pub const oid_signed_data_pkcs7 = [_]u8{
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
};
pub const oid_attr_content_type = [_]u8{
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03,
};
pub const oid_attr_message_digest = [_]u8{
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04,
};
pub const oid_attr_signing_time = [_]u8{
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05,
};
pub const oid_spc_indirect_data = [_]u8{
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04,
};
pub const oid_spc_statement_type = [_]u8{
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0b,
};
pub const oid_spc_sp_opus_info = [_]u8{
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0c,
};
pub const oid_spc_pe_image_data = [_]u8{
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0f,
};
pub const oid_spc_individual_code_signing = [_]u8{
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x15,
};
pub const oid_spc_sip_info = [_]u8{
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x1e,
};
pub const oid_rsa_encryption = [_]u8{
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
};
pub const oid_sha256_with_rsa_encryption = [_]u8{
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
};
pub const oid_sha384_with_rsa_encryption = [_]u8{
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c,
};
pub const oid_ecdsa_with_sha256 = [_]u8{
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
};
pub const oid_ecdsa_with_sha384 = [_]u8{
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03,
};
pub const oid_sha256 = [_]u8{
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
};
pub const oid_sha384 = [_]u8{
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
};
/// Authenticode RFC 3161 counter-signature unsigned attribute (1.3.6.1.4.1.311.3.3.1).
/// Windows only recognizes timestamps stored under this OID, not under the generic
/// CMS `id-aa-timeStampToken` (1.2.840.113549.1.9.16.2.14).
pub const oid_rfc3161_counter_sign = [_]u8{
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x03, 0x03, 0x01,
};

/// MSI SIP GUID stored in SpcSipInfo ({000C10F1-0000-0000-C000-000000000046}).
pub const msi_sip_guid = [_]u8{
    0xf1, 0x10, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
};

/// ASN.1 NULL value (`0x05, 0x00`).
pub const asn1_null = [_]u8{ 0x05, 0x00 };

/// Pre-encoded DER INTEGER 0 and INTEGER 1.
pub const int_v0 = [_]u8{ 0x02, 0x01, 0x00 };
pub const int_v1 = [_]u8{ 0x02, 0x01, 0x01 };

/// Pre-encoded DER AlgorithmIdentifier (`SEQUENCE { OID, NULL }`) for SHA-256 and SHA-384.
pub const alg_id_sha256 = [_]u8{ 0x30, 0x0d } ++ oid_sha256 ++ asn1_null;
pub const alg_id_sha384 = [_]u8{ 0x30, 0x0d } ++ oid_sha384 ++ asn1_null;

/// Returns the DER-encoded AlgorithmIdentifier for `algorithm`.
pub fn digestAlgorithmIdentifier(algorithm: HashAlgorithm) []const u8 {
    return switch (algorithm) {
        .sha256 => &alg_id_sha256,
        .sha384 => &alg_id_sha384,
    };
}

/// Appends DER length bytes to `buf`.
pub fn appendDerLength(len: usize, buf: *std.ArrayList(u8), alloc: Allocator) !void {
    if (len < 128) {
        try buf.append(alloc, @intCast(len));
    } else if (len <= 0xFF) {
        try buf.append(alloc, 0x81);
        try buf.append(alloc, @intCast(len));
    } else if (len <= 0xFFFF) {
        try buf.append(alloc, 0x82);
        try buf.append(alloc, @intCast((len >> 8) & 0xFF));
        try buf.append(alloc, @intCast(len & 0xFF));
    } else {
        try buf.append(alloc, 0x83);
        try buf.append(alloc, @intCast((len >> 16) & 0xFF));
        try buf.append(alloc, @intCast((len >> 8) & 0xFF));
        try buf.append(alloc, @intCast(len & 0xFF));
    }
}

/// Concatenates `parts` inside a DER TLV container with `tag`.
pub fn wrapTaggedParts(allocator: Allocator, tag: u8, parts: []const []const u8) ![]u8 {
    var content_len: usize = 0;
    for (parts) |p| content_len += p.len;

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    try out.append(allocator, tag);
    try appendDerLength(content_len, &out, allocator);
    for (parts) |p| try out.appendSlice(allocator, p);
    return out.toOwnedSlice(allocator);
}

/// Wraps `content` in a DER TLV container with the specified tag.
pub fn wrapTagged(allocator: Allocator, tag: u8, content: []const u8) ![]u8 {
    return wrapTaggedParts(allocator, tag, &.{content});
}

/// Concatenates `parts` inside a DER SEQUENCE (tag `0x30`).
pub fn wrapSequenceParts(allocator: Allocator, parts: []const []const u8) ![]u8 {
    return wrapTaggedParts(allocator, 0x30, parts);
}

/// Wraps `content` in a DER SEQUENCE (tag `0x30`).
pub fn wrapSequence(allocator: Allocator, content: []const u8) ![]u8 {
    return wrapTagged(allocator, 0x30, content);
}

/// Wraps `content` in a `[0] EXPLICIT` context tag (tag `0xA0`).
pub fn wrapExplicit0(allocator: Allocator, content: []const u8) ![]u8 {
    return wrapTagged(allocator, 0xA0, content);
}

/// Wraps `content` in a DER OCTET STRING (tag `0x04`).
pub fn wrapOctetString(allocator: Allocator, bytes: []const u8) ![]u8 {
    return wrapTagged(allocator, 0x04, bytes);
}

/// Encodes a CMS Attribute (`SEQUENCE { attrType OID, attrValues SET OF AttributeValue }`).
pub fn encodeAttribute(allocator: Allocator, oid_der: []const u8, value_der: []const u8) ![]u8 {
    const val_set = try wrapSet(allocator, &.{value_der});
    defer allocator.free(val_set);
    return wrapSequenceParts(allocator, &.{ oid_der, val_set });
}

/// Wraps elements in a DER SET (tag `0x31`), sorting them lexicographically
/// by their complete DER byte encodings as required by DER encoding rules.
pub fn wrapSet(allocator: Allocator, elements: []const []const u8) ![]u8 {
    return wrapSetTagged(allocator, 0x31, elements);
}

/// Wraps elements in a DER SET with a custom tag (e.g. `0xA0` for `[0] IMPLICIT SET`).
pub fn wrapSetTagged(allocator: Allocator, tag: u8, elements: []const []const u8) ![]u8 {
    const sorted = try allocator.dupe([]const u8, elements);
    defer allocator.free(sorted);

    const SortCtx = struct {
        pub fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return mem.order(u8, a, b) == .lt;
        }
    };
    std.sort.block([]const u8, sorted, {}, SortCtx.lessThan);

    return wrapTaggedParts(allocator, tag, sorted);
}

/// Encodes an epoch timestamp as a DER Time value (`UTCTime` before 2050,
/// `GeneralizedTime` from 2050 onward per RFC 5652 Section 11.3).
pub fn wrapUtcTime(allocator: Allocator, epoch_seconds: i64) ![]u8 {
    const epoch: u64 = if (epoch_seconds >= 0) @intCast(epoch_seconds) else 0;
    const epoch_sec = std.time.epoch.EpochSeconds{ .secs = epoch };
    const epoch_day = epoch_sec.getEpochDay();
    const day_seconds = epoch_sec.getDaySeconds();

    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    const month = month_day.month.numeric();
    const day = month_day.day_index + 1;
    const hours = day_seconds.getHoursIntoDay();
    const minutes = day_seconds.getMinutesIntoHour();
    const seconds = day_seconds.getSecondsIntoMinute();

    if (year_day.year >= 2050) {
        var time_buf: [15]u8 = undefined;
        _ = std.fmt.bufPrint(
            &time_buf,
            "{d:0>4}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z",
            .{ year_day.year, month, day, hours, minutes, seconds },
        ) catch unreachable;
        return wrapTagged(allocator, 0x18, &time_buf);
    }

    var time_buf: [13]u8 = undefined;
    _ = std.fmt.bufPrint(
        &time_buf,
        "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z",
        .{ year_day.year % 100, month, day, hours, minutes, seconds },
    ) catch unreachable;
    return wrapTagged(allocator, 0x17, &time_buf);
}

/// Encodes a UTF-8 string as a Big-Endian UTF-16 BMPString wrapped in SpcString.
pub fn wrapOpusDescription(allocator: Allocator, desc: []const u8) ![]u8 {
    if (desc.len == 0) {
        return wrapSequence(allocator, &.{});
    }

    const utf16 = try std.unicode.utf8ToUtf16LeAlloc(allocator, desc);
    defer allocator.free(utf16);
    for (utf16) |*unit| unit.* = mem.nativeToBig(u16, mem.littleToNative(u16, unit.*));

    const spc_str = try wrapTagged(allocator, 0x80, mem.sliceAsBytes(utf16));
    defer allocator.free(spc_str);
    const prog_name = try wrapTagged(allocator, 0xA0, spc_str);
    defer allocator.free(prog_name);

    return wrapSequence(allocator, prog_name);
}

pub const SpcIndirectDataResult = struct {
    der: []u8,
    contents: []u8,

    pub fn deinit(self: SpcIndirectDataResult, allocator: Allocator) void {
        allocator.free(self.der);
        allocator.free(self.contents);
    }
};

/// Builds the SpcIndirectDataContent structure for either MSI or PE.
/// Returns both the full DER sequence and its contents octets (used for messageDigest).
pub fn buildSpcIndirectData(
    allocator: Allocator,
    target: Target,
    digest: []const u8,
    algorithm: HashAlgorithm,
) !SpcIndirectDataResult {
    const data_seq = switch (target) {
        .msi => blk: {
            const guid_octets = try wrapOctetString(allocator, &msi_sip_guid);
            defer allocator.free(guid_octets);

            // SpcSipInfo: SEQUENCE { version (1), sipGUID, r1..r5 (0,0,0,0,0) }
            const sip_seq = try wrapSequenceParts(allocator, &.{
                &int_v1,
                guid_octets,
                &int_v0,
                &int_v0,
                &int_v0,
                &int_v0,
                &int_v0,
            });
            defer allocator.free(sip_seq);
            break :blk try wrapSequenceParts(allocator, &.{ &oid_spc_sip_info, sip_seq });
        },
        .pe => blk: {
            // SpcPeImageData: SEQUENCE { flags BIT STRING, file [0] EXPLICIT SpcLink }
            // Hardcoded standard <<<Obsolete>>> link matching Windows SDK and osslsigncode
            const pe_image_data_body = [_]u8{
                0x03, 0x01, 0x00, 0xA0, 0x20, 0xA2, 0x1E, 0x80,
                0x1C, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x3C, 0x00,
                0x4F, 0x00, 0x62, 0x00, 0x73, 0x00, 0x6F, 0x00,
                0x6C, 0x00, 0x65, 0x00, 0x74, 0x00, 0x65, 0x00,
                0x3E, 0x00, 0x3E, 0x00, 0x3E,
            };
            const pe_seq = try wrapSequence(allocator, &pe_image_data_body);
            defer allocator.free(pe_seq);
            break :blk try wrapSequenceParts(allocator, &.{ &oid_spc_pe_image_data, pe_seq });
        },
    };
    defer allocator.free(data_seq);

    // DigestInfo: SEQUENCE { algorithm AlgorithmIdentifier, digest OCTET STRING }
    const dig_octets = try wrapOctetString(allocator, digest);
    defer allocator.free(dig_octets);

    const digest_info = try wrapSequenceParts(allocator, &.{
        digestAlgorithmIdentifier(algorithm),
        dig_octets,
    });
    defer allocator.free(digest_info);

    // SpcIndirectDataContent: SEQUENCE { data, messageDigest }
    const contents = try mem.concat(allocator, u8, &.{ data_seq, digest_info });
    errdefer allocator.free(contents);
    const der = try wrapSequence(allocator, contents);

    return .{
        .der = der,
        .contents = contents,
    };
}

pub const SignedAttrsResult = struct {
    embedded_attrs: []u8,
    signing_attrs_set: []u8,

    pub fn deinit(self: SignedAttrsResult, allocator: Allocator) void {
        allocator.free(self.embedded_attrs);
        allocator.free(self.signing_attrs_set);
    }
};

/// Builds the signed attributes for an Authenticode CMS signature.
/// Returns both the `[0] IMPLICIT` embedded attribute bytes and the
/// DER `SET` (tag `0x31`) bytes over which the signature hash is calculated.
pub fn buildSignedAttributes(
    allocator: Allocator,
    spc_contents_digest: []const u8,
    signing_time: i64,
    description: ?[]const u8,
) !SignedAttrsResult {
    var raw_attrs: std.ArrayList([]u8) = .empty;
    defer {
        for (raw_attrs.items) |a| allocator.free(a);
        raw_attrs.deinit(allocator);
    }

    const dig_octets = try wrapOctetString(allocator, spc_contents_digest);
    defer allocator.free(dig_octets);
    const time_val = try wrapUtcTime(allocator, signing_time);
    defer allocator.free(time_val);
    const stmt_seq = try wrapSequence(allocator, &oid_spc_individual_code_signing);
    defer allocator.free(stmt_seq);
    const opus_val = try wrapOpusDescription(allocator, description orelse "");
    defer allocator.free(opus_val);

    try raw_attrs.append(
        allocator,
        try encodeAttribute(allocator, &oid_attr_content_type, &oid_spc_indirect_data),
    );
    try raw_attrs.append(
        allocator,
        try encodeAttribute(allocator, &oid_attr_message_digest, dig_octets),
    );
    try raw_attrs.append(
        allocator,
        try encodeAttribute(allocator, &oid_attr_signing_time, time_val),
    );
    try raw_attrs.append(
        allocator,
        try encodeAttribute(allocator, &oid_spc_statement_type, stmt_seq),
    );
    try raw_attrs.append(
        allocator,
        try encodeAttribute(allocator, &oid_spc_sp_opus_info, opus_val),
    );

    const signing_set = try wrapSet(allocator, raw_attrs.items);
    errdefer allocator.free(signing_set);

    const embedded = try allocator.dupe(u8, signing_set);
    embedded[0] = 0xA0;

    return .{
        .embedded_attrs = embedded,
        .signing_attrs_set = signing_set,
    };
}

/// Assembles the complete ContentInfo / SignedData Authenticode structure.
pub fn assembleContentInfo(
    allocator: Allocator,
    spc_der: []const u8,
    leaf_cert_der: []const u8,
    issuer_der: []const u8,
    serial_der: []const u8,
    chain_certs_der: []const []const u8,
    hash_algorithm: HashAlgorithm,
    sig_algorithm_oid: []const u8,
    sig_algorithm_has_null: bool,
    embedded_attrs: []const u8,
    signature_bytes: []const u8,
    timestamp_token: ?[]const u8,
) ![]u8 {
    const digest_alg_der = digestAlgorithmIdentifier(hash_algorithm);

    const issuer_and_serial = try wrapSequenceParts(allocator, &.{ issuer_der, serial_der });
    defer allocator.free(issuer_and_serial);

    const sig_alg_der = if (sig_algorithm_has_null)
        try wrapSequenceParts(allocator, &.{ sig_algorithm_oid, &asn1_null })
    else
        try wrapSequence(allocator, sig_algorithm_oid);
    defer allocator.free(sig_alg_der);

    const sig_octets = try wrapOctetString(allocator, signature_bytes);
    defer allocator.free(sig_octets);

    const unauth_attrs = if (timestamp_token) |tst| blk: {
        const tst_attr = try encodeAttribute(allocator, &oid_rfc3161_counter_sign, tst);
        defer allocator.free(tst_attr);
        break :blk try wrapSetTagged(allocator, 0xA1, &.{tst_attr});
    } else &[_]u8{};
    defer if (unauth_attrs.len > 0) allocator.free(unauth_attrs);

    const signer_info_der = try wrapSequenceParts(allocator, &.{
        &int_v1,
        issuer_and_serial,
        digest_alg_der,
        embedded_attrs,
        sig_alg_der,
        sig_octets,
        unauth_attrs,
    });
    defer allocator.free(signer_info_der);

    var all_certs: std.ArrayList([]const u8) = .empty;
    defer all_certs.deinit(allocator);
    try all_certs.append(allocator, leaf_cert_der);
    for (chain_certs_der) |c| try all_certs.append(allocator, c);

    const certs_der = try wrapSetTagged(allocator, 0xA0, all_certs.items);
    defer allocator.free(certs_der);

    const spc_explicit0 = try wrapExplicit0(allocator, spc_der);
    defer allocator.free(spc_explicit0);
    const encap_der = try wrapSequenceParts(allocator, &.{ &oid_spc_indirect_data, spc_explicit0 });
    defer allocator.free(encap_der);

    const digest_algs_set = try wrapSet(allocator, &.{digest_alg_der});
    defer allocator.free(digest_algs_set);

    const signer_infos_set = try wrapSet(allocator, &.{signer_info_der});
    defer allocator.free(signer_infos_set);

    const signed_data_der = try wrapSequenceParts(allocator, &.{
        &int_v1,
        digest_algs_set,
        encap_der,
        certs_der,
        signer_infos_set,
    });
    defer allocator.free(signed_data_der);

    const sd_explicit0 = try wrapExplicit0(allocator, signed_data_der);
    defer allocator.free(sd_explicit0);

    return wrapSequenceParts(allocator, &.{ &oid_signed_data_pkcs7, sd_explicit0 });
}

test "asn1 wrapSet sorts elements lexicographically" {
    const testing = std.testing;
    const alloc = testing.allocator;

    const elem_b = [_]u8{ 0x02, 0x01, 0x02 }; // INTEGER 2
    const elem_a = [_]u8{ 0x02, 0x01, 0x01 }; // INTEGER 1

    const set_der = try wrapSet(alloc, &.{ &elem_b, &elem_a });
    defer alloc.free(set_der);

    // Must be tag 0x31, len 6, then elem_a, then elem_b
    try testing.expectEqual(@as(u8, 0x31), set_der[0]);
    try testing.expectEqual(@as(u8, 0x06), set_der[1]);
    try testing.expectEqualSlices(u8, &elem_a, set_der[2..5]);
    try testing.expectEqualSlices(u8, &elem_b, set_der[5..8]);
}

test "asn1 buildSpcIndirectData for MSI and PE" {
    const testing = std.testing;
    const alloc = testing.allocator;

    const fake_digest: [32]u8 = @splat(0xAA);

    const msi_idc = try buildSpcIndirectData(alloc, .msi, &fake_digest, .sha256);
    defer msi_idc.deinit(alloc);

    try testing.expect(msi_idc.der.len > msi_idc.contents.len);
    try testing.expectEqual(@as(u8, 0x30), msi_idc.der[0]);

    const pe_idc = try buildSpcIndirectData(alloc, .pe, &fake_digest, .sha256);
    defer pe_idc.deinit(alloc);

    try testing.expect(pe_idc.der.len > pe_idc.contents.len);
    try testing.expectEqual(@as(u8, 0x30), pe_idc.der[0]);
}

test "asn1 buildSignedAttributes produces expected tags" {
    const testing = std.testing;
    const alloc = testing.allocator;

    const fake_digest: [32]u8 = @splat(0x55);
    const attrs = try buildSignedAttributes(alloc, &fake_digest, 1776963092, "TestApp");
    defer attrs.deinit(alloc);

    try testing.expectEqual(@as(u8, 0xA0), attrs.embedded_attrs[0]);
    try testing.expectEqual(@as(u8, 0x31), attrs.signing_attrs_set[0]);
    try testing.expectEqual(attrs.embedded_attrs.len, attrs.signing_attrs_set.len);
}
