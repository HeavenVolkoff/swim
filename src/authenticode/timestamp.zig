//! RFC 3161 Time-Stamp Protocol (TSP) client for Authenticode code signing.
//!
//! Provides cryptographically verifiable proof of signing time from an RFC 3161
//! Time-Stamp Authority (TSA). The returned TimeStampToken is embedded by
//! `asn1.assembleContentInfo` as the Authenticode RFC 3161 counter-signature
//! unsigned attribute (1.3.6.1.4.1.311.3.3.1).

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const asn1 = @import("asn1.zig");
const signer = @import("signer.zig");
const HashAlgorithm = @import("msi.zig").HashAlgorithm;

/// Constructs an ASN.1 DER `TimeStampReq` structure (RFC 3161 Section 2.4.1).
///
/// ```asn1
/// TimeStampReq ::= SEQUENCE {
///     version         INTEGER (1),
///     messageImprint  MessageImprint {
///         hashAlgorithm   AlgorithmIdentifier,
///         hashedMessage   OCTET STRING
///     },
///     reqPolicy       TSAPolicyId OPTIONAL,
///     nonce           INTEGER OPTIONAL,
///     certReq         BOOLEAN (true) OPTIONAL
/// }
/// ```
pub fn buildTimeStampReq(
    allocator: Allocator,
    digest: []const u8,
    algorithm: HashAlgorithm,
) ![]u8 {
    const dig_octets = try asn1.wrapOctetString(allocator, digest);
    defer allocator.free(dig_octets);

    const message_imprint = try asn1.wrapSequenceParts(allocator, &.{
        asn1.digestAlgorithmIdentifier(algorithm),
        dig_octets,
    });
    defer allocator.free(message_imprint);

    // certReq BOOLEAN (true: 0x01, 0x01, 0xFF)
    const cert_req = [_]u8{ 0x01, 0x01, 0xFF };
    return asn1.wrapSequenceParts(allocator, &.{ &asn1.int_v1, message_imprint, &cert_req });
}

/// Parses an RFC 3161 `TimeStampResp` DER sequence and extracts the `TimeStampToken`.
///
/// ```asn1
/// TimeStampResp ::= SEQUENCE {
///     status         PKIStatusInfo,
///     timeStampToken TimeStampToken OPTIONAL
/// }
/// ```
pub fn extractTimeStampToken(resp_der: []const u8) ![]const u8 {
    const resp_tlv = try signer.readTlv(resp_der, 0);
    if (resp_tlv.tag != 0x30) return error.InvalidTimeStampResponse;

    // 1. PKIStatusInfo: SEQUENCE { status PKIStatus (INTEGER) }
    const status_tlv = try signer.readTlv(resp_tlv.data, 0);
    if (status_tlv.tag != 0x30) return error.InvalidTimeStampResponse;

    const pki_status = try signer.readTlv(status_tlv.data, 0);
    if (pki_status.tag != 0x02 or pki_status.data.len == 0) {
        return error.InvalidTimeStampResponse;
    }

    // Status 0 indicates "granted" (RFC 3161 Section 2.4.2)
    if (pki_status.data[pki_status.data.len - 1] != 0) {
        return error.TsaStatusRejected;
    }

    // 2. TimeStampToken: ContentInfo (SEQUENCE)
    const token_tlv = try signer.readTlv(resp_tlv.data, status_tlv.next);
    if (token_tlv.tag != 0x30) return error.InvalidTimeStampResponse;

    return resp_tlv.data[token_tlv.start..token_tlv.next];
}

/// Requests an RFC 3161 TimeStampToken over `HASH(signature_bytes)` (the CMS
/// `SignerInfo.signature`) from the specified TSA URL.
pub fn requestTimestamp(
    io: std.Io,
    allocator: Allocator,
    tsa_url: []const u8,
    signature_bytes: []const u8,
    algorithm: HashAlgorithm,
) ![]u8 {
    var sig_hash_buf: [HashAlgorithm.max_digest_length]u8 = undefined;
    const sig_hash = algorithm.hash(signature_bytes, &sig_hash_buf);

    const req_der = try buildTimeStampReq(allocator, sig_hash, algorithm);
    defer allocator.free(req_der);

    var client = std.http.Client{ .allocator = allocator, .io = io };
    defer client.deinit();

    var allocating = std.Io.Writer.Allocating.init(allocator);
    defer allocating.deinit();

    const extra_headers = [_]std.http.Header{
        .{ .name = "Content-Type", .value = "application/timestamp-query" },
        .{ .name = "Accept", .value = "application/timestamp-reply" },
    };

    const fetch_res = client.fetch(.{
        .location = .{ .url = tsa_url },
        .method = .POST,
        .payload = req_der,
        .extra_headers = &extra_headers,
        .response_writer = &allocating.writer,
    }) catch return error.TsaRequestFailed;

    if (fetch_res.status != .ok) return error.TsaRequestFailed;

    const token_slice = try extractTimeStampToken(allocating.written());
    return allocator.dupe(u8, token_slice);
}

test "buildTimeStampReq and extractTimeStampToken mock" {
    const testing = std.testing;
    const alloc = testing.allocator;

    const fake_sig_hash: [32]u8 = @splat(0x12);
    const req = try buildTimeStampReq(alloc, &fake_sig_hash, .sha256);
    defer alloc.free(req);

    try testing.expect(req.len > 0);
    try testing.expectEqual(@as(u8, 0x30), req[0]);

    // Build a mock TimeStampResp
    // SEQUENCE { PKIStatusInfo SEQUENCE { INTEGER 0 }, mockToken SEQUENCE { ... } }
    const status_zero = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x00 };
    const mock_token = [_]u8{ 0x30, 0x04, 0x02, 0x02, 0xCA, 0xFE };

    var resp_body: std.ArrayList(u8) = .empty;
    defer resp_body.deinit(alloc);
    try resp_body.appendSlice(alloc, &status_zero);
    try resp_body.appendSlice(alloc, &mock_token);

    const mock_resp = try asn1.wrapSequence(alloc, resp_body.items);
    defer alloc.free(mock_resp);

    const extracted = try extractTimeStampToken(mock_resp);
    try testing.expectEqualSlices(u8, &mock_token, extracted);
}
