//! Authenticode CMS signature verifier and test oracle for MSI and PE binaries.
//!
//! Validates:
//! 1. Container structure (ContentInfo -> SignedData -> SpcIndirectDataContent).
//! 2. Message digest in SpcIndirectData matches the binary Authenticode hash
//!    (for PE) or the canonical MSI Imprint (for MSI packages).
//! 3. `messageDigest` signed attribute matches HASH(SpcIndirectDataContent octets).
//! 4. Cryptographic signature over `signedAttrs` (ECDSA P-384, ECDSA P-256, RSA).
//! 5. Optional certificate thumbprint equality for payload consistency checks.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const cfbf = @import("../cfbf.zig");
const msi = @import("msi.zig");
const pe = @import("pe.zig");
const asn1 = @import("asn1.zig");
const signer = @import("signer.zig");
const HashAlgorithm = msi.HashAlgorithm;

pub const VerifyResult = struct {
    leaf_cert: signer.Certificate,
    digest_algorithm: HashAlgorithm,

    pub fn deinit(self: *VerifyResult, allocator: Allocator) void {
        self.leaf_cert.deinit(allocator);
    }
};

const ParsedCms = struct {
    hash_algo: HashAlgorithm,
    stored_imprint: []const u8,
    spc_contents: []const u8,
    certs_data: []const u8,
    target_issuer: []const u8,
    target_serial: []const u8,
    si_sa_raw: []const u8,
    si_sa_data: []const u8,
    sig_alg_oid: []const u8,
    signature_bytes: []const u8,
};

fn parseCms(cms_der: []const u8) !ParsedCms {
    // 1. Parse ContentInfo (tag 0x30)
    const ci_tlv = try signer.readTlv(cms_der, 0);
    if (ci_tlv.tag != 0x30) return error.InvalidCmsStructure;

    const ci_ct = try signer.readTlv(ci_tlv.data, 0);
    if (!mem.eql(u8, ci_ct.data, asn1.oid_signed_data_pkcs7[2..])) {
        return error.InvalidCmsStructure;
    }

    // 2. Parse [0] EXPLICIT SignedData
    const ci_content = try signer.readTlv(ci_tlv.data, ci_ct.next);
    if (ci_content.tag != 0xA0) return error.InvalidCmsStructure;

    const sd_tlv = try signer.readTlv(ci_content.data, 0);
    if (sd_tlv.tag != 0x30) return error.InvalidCmsStructure;

    // Inside SignedData: version, digestAlgorithms, encapContentInfo, certs, signerInfos
    const sd_v = try signer.readTlv(sd_tlv.data, 0);
    const sd_da = try signer.readTlv(sd_tlv.data, sd_v.next);
    const sd_encap = try signer.readTlv(sd_tlv.data, sd_da.next);
    const sd_certs = try signer.readTlv(sd_tlv.data, sd_encap.next);
    if (sd_certs.tag != 0xA0) return error.InvalidCmsStructure;
    const sd_si = try signer.readTlv(sd_tlv.data, sd_certs.next);

    // 3. Extract SpcIndirectDataContent from encapContentInfo
    const encap_type = try signer.readTlv(sd_encap.data, 0);
    if (!mem.eql(u8, encap_type.data, asn1.oid_spc_indirect_data[2..])) {
        return error.InvalidCmsStructure;
    }

    const encap_content = try signer.readTlv(sd_encap.data, encap_type.next);
    if (encap_content.tag != 0xA0) return error.InvalidCmsStructure;

    const spc_tlv = try signer.readTlv(encap_content.data, 0);
    const spc_contents = spc_tlv.data;

    // Inside SpcIndirectDataContent: data SEQUENCE, messageDigest SEQUENCE
    const spc_data = try signer.readTlv(spc_contents, 0);
    const spc_md = try signer.readTlv(spc_contents, spc_data.next);

    // Inside DigestInfo: algId SEQUENCE, digest OCTET STRING
    const md_alg = try signer.readTlv(spc_md.data, 0);
    const md_alg_oid = try signer.readTlv(md_alg.data, 0);
    const md_dig = try signer.readTlv(spc_md.data, md_alg.next);
    if (md_dig.tag != 0x04) return error.InvalidCmsStructure;

    const hash_algo: HashAlgorithm = if (mem.eql(u8, md_alg_oid.data, asn1.oid_sha256[2..]))
        .sha256
    else if (mem.eql(u8, md_alg_oid.data, asn1.oid_sha384[2..]))
        .sha384
    else
        return error.UnsupportedSignatureAlgorithm;

    // 4. Extract SignerInfo
    const si_tlv = try signer.readTlv(sd_si.data, 0);
    const si_v = try signer.readTlv(si_tlv.data, 0);
    const si_sid = try signer.readTlv(si_tlv.data, si_v.next);
    const sid_issuer = try signer.readTlv(si_sid.data, 0);
    const sid_serial = try signer.readTlv(si_sid.data, sid_issuer.next);

    const si_da = try signer.readTlv(si_tlv.data, si_sid.next);
    const si_sa = try signer.readTlv(si_tlv.data, si_da.next);
    if (si_sa.tag != 0xA0) return error.InvalidCmsStructure;

    const si_sigalg = try signer.readTlv(si_tlv.data, si_sa.next);
    const si_sigalg_oid = try signer.readTlv(si_sigalg.data, 0);

    const si_sig = try signer.readTlv(si_tlv.data, si_sigalg.next);
    if (si_sig.tag != 0x04) return error.InvalidCmsStructure;

    return .{
        .hash_algo = hash_algo,
        .stored_imprint = md_dig.data,
        .spc_contents = spc_contents,
        .certs_data = sd_certs.data,
        .target_issuer = si_sid.data[sid_issuer.start..sid_issuer.next],
        .target_serial = si_sid.data[sid_serial.start..sid_serial.next],
        .si_sa_raw = si_tlv.data[si_sa.start..si_sa.next],
        .si_sa_data = si_sa.data,
        .sig_alg_oid = si_sigalg_oid.data,
        .signature_bytes = si_sig.data,
    };
}

/// Inspects an Authenticode CMS SignedData blob and returns the digest algorithm
/// specified in its `SpcIndirectDataContent.messageDigest`.
pub fn detectCmsHashAlgorithm(cms_der: []const u8) !HashAlgorithm {
    return (try parseCms(cms_der)).hash_algo;
}

/// Parses and cryptographically verifies an Authenticode CMS SignedData blob
/// against an expected binary digest or MSI imprint.
pub fn verifyCms(
    allocator: Allocator,
    cms_der: []const u8,
    expected_digest: []const u8,
    trusted_cert: ?signer.Certificate,
) !VerifyResult {
    const cms = try parseCms(cms_der);

    // 1. Locate signer certificate in SignedData.certificates matching IssuerAndSerialNumber
    var matched_cert: ?signer.Certificate = null;
    var certs_offset: usize = 0;
    while (certs_offset < cms.certs_data.len) {
        const cert_tlv = try signer.readTlv(cms.certs_data, certs_offset);
        certs_offset = cert_tlv.next;
        const cert_der = cms.certs_data[cert_tlv.start..cert_tlv.next];
        var candidate = try signer.Certificate.parse(allocator, cert_der);
        if (mem.eql(u8, candidate.issuer_der, cms.target_issuer) and
            mem.eql(u8, candidate.serial_der, cms.target_serial))
        {
            matched_cert = candidate;
            break;
        }
        candidate.deinit(allocator);
    }

    var leaf_cert = matched_cert orelse return error.InvalidCertificate;
    errdefer leaf_cert.deinit(allocator);

    // Optional trusted cert comparison
    if (trusted_cert) |tc| {
        if (!mem.eql(u8, &leaf_cert.thumbprint, &tc.thumbprint)) {
            return error.CertificateMismatch;
        }
    }

    // 2. Verify stored imprint against computed binary digest
    if (!mem.eql(u8, cms.stored_imprint, expected_digest)) {
        return error.DigestMismatch;
    }

    // 3. Verify messageDigest attribute in signedAttrs
    var stored_spc_hash: ?[]const u8 = null;
    var sa_offset: usize = 0;
    while (sa_offset < cms.si_sa_data.len) {
        const attr_seq = try signer.readTlv(cms.si_sa_data, sa_offset);
        sa_offset = attr_seq.next;

        const attr_type = try signer.readTlv(attr_seq.data, 0);
        if (mem.eql(u8, attr_type.data, asn1.oid_attr_message_digest[2..])) {
            const attr_set = try signer.readTlv(attr_seq.data, attr_type.next);
            const attr_val = try signer.readTlv(attr_set.data, 0);
            stored_spc_hash = attr_val.data;
            break;
        }
    }

    const expected_spc_hash = stored_spc_hash orelse return error.InvalidCmsStructure;

    var actual_spc_buf: [HashAlgorithm.max_digest_length]u8 = undefined;
    const actual_spc_hash = cms.hash_algo.hash(cms.spc_contents, &actual_spc_buf);
    if (!mem.eql(u8, actual_spc_hash, expected_spc_hash)) {
        return error.MessageDigestAttributeMismatch;
    }

    // 4. Verify cryptographic signature over signedAttrs (SET tag 0x31)
    const attrs_set = try allocator.dupe(u8, cms.si_sa_raw);
    defer allocator.free(attrs_set);
    attrs_set[0] = 0x31; // Universal SET tag for signature verification

    try verifyCryptographicSignature(
        allocator,
        leaf_cert.raw,
        cms.sig_alg_oid,
        cms.hash_algo,
        attrs_set,
        cms.signature_bytes,
    );

    return .{
        .leaf_cert = leaf_cert,
        .digest_algorithm = cms.hash_algo,
    };
}

fn verifyEcdsa(
    comptime Curve: type,
    comptime Hash: type,
    pub_key_bytes: []const u8,
    msg: []const u8,
    sig_bytes: []const u8,
) !void {
    const Scheme = std.crypto.sign.ecdsa.Ecdsa(Curve, Hash);
    const pk = Scheme.PublicKey.fromSec1(pub_key_bytes) catch return error.InvalidCertificate;
    const sig = Scheme.Signature.fromDer(sig_bytes) catch return error.InvalidSignature;
    var hash_val: [Hash.digest_length]u8 = undefined;
    Hash.hash(msg, &hash_val, .{});
    sig.verifyPrehashed(hash_val, pk) catch return error.InvalidSignature;
}

fn verifyCryptographicSignature(
    allocator: Allocator,
    cert_der: []const u8,
    sig_alg_oid: []const u8,
    digest_algo: HashAlgorithm,
    signed_attrs_set: []const u8,
    sig_bytes: []const u8,
) !void {
    const cert_parsed = std.crypto.Certificate.parse(.{
        .buffer = cert_der,
        .index = 0,
    }) catch return error.InvalidCertificate;

    const pub_key_bytes = cert_parsed.pubKey();
    if (pub_key_bytes.len == 0) return error.InvalidCertificate;

    const P256 = std.crypto.ecc.P256;
    const P384 = std.crypto.ecc.P384;
    const Sha256 = std.crypto.hash.sha2.Sha256;
    const Sha384 = std.crypto.hash.sha2.Sha384;

    if (mem.eql(u8, sig_alg_oid, asn1.oid_ecdsa_with_sha256[2..])) {
        return switch (pub_key_bytes.len) {
            65 => verifyEcdsa(P256, Sha256, pub_key_bytes, signed_attrs_set, sig_bytes),
            97 => verifyEcdsa(P384, Sha256, pub_key_bytes, signed_attrs_set, sig_bytes),
            else => error.InvalidCertificate,
        };
    } else if (mem.eql(u8, sig_alg_oid, asn1.oid_ecdsa_with_sha384[2..])) {
        return switch (pub_key_bytes.len) {
            65 => verifyEcdsa(P256, Sha384, pub_key_bytes, signed_attrs_set, sig_bytes),
            97 => verifyEcdsa(P384, Sha384, pub_key_bytes, signed_attrs_set, sig_bytes),
            else => error.InvalidCertificate,
        };
    } else if (mem.eql(u8, sig_alg_oid, asn1.oid_rsa_encryption[2..]) or
        mem.eql(u8, sig_alg_oid, asn1.oid_sha256_with_rsa_encryption[2..]) or
        mem.eql(u8, sig_alg_oid, asn1.oid_sha384_with_rsa_encryption[2..]))
    {
        // RSA PKCS#1 v1.5: parse RSAPublicKey SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        const rsa_pub = try signer.readTlv(pub_key_bytes, 0);
        const mod_tlv = try signer.readTlv(rsa_pub.data, 0);
        const exp_num_tlv = try signer.readTlv(rsa_pub.data, mod_tlv.next);

        const mod_slice = signer.stripLeadingZero(mod_tlv.data);

        // Decrypt with public key: em = s^e mod n
        const Modulus = std.crypto.ff.Modulus(4096);
        const m = try Modulus.fromBytes(mod_slice, .big);
        const s = try Modulus.Fe.fromBytes(m, sig_bytes, .big);
        const em_fe = try m.powWithEncodedPublicExponent(s, exp_num_tlv.data, .big);

        var em_buf: [512]u8 = undefined;
        try em_fe.toBytes(em_buf[0..mod_slice.len], .big);
        const em = em_buf[0..mod_slice.len];

        const rsa_hash: HashAlgorithm = if (mem.eql(
            u8,
            sig_alg_oid,
            asn1.oid_sha384_with_rsa_encryption[2..],
        ))
            .sha384
        else if (mem.eql(u8, sig_alg_oid, asn1.oid_sha256_with_rsa_encryption[2..]))
            .sha256
        else
            digest_algo;

        const expected_em = try allocator.alloc(u8, mod_slice.len);
        defer allocator.free(expected_em);
        try signer.encodePkcs1v15(expected_em, signed_attrs_set, rsa_hash);

        if (!mem.eql(u8, em, expected_em)) return error.InvalidSignature;
    } else {
        return error.UnsupportedSignatureAlgorithm;
    }
}

/// Verifies a signed Portable Executable binary.
pub fn verifyPe(
    allocator: Allocator,
    pe_bytes: []const u8,
    trusted_cert: ?signer.Certificate,
) !VerifyResult {
    const raw_cms = (try pe.extractSignature(pe_bytes)) orelse {
        return error.NoSignatureFound;
    };

    const algo = try detectCmsHashAlgorithm(raw_cms);
    const expected_digest = try pe.computeDigest(allocator, pe_bytes, algo);
    defer allocator.free(expected_digest);

    return verifyCms(allocator, raw_cms, expected_digest, trusted_cert);
}

/// Verifies a signed Windows Installer (.msi) compound file package.
pub fn verifyMsi(
    allocator: Allocator,
    msi_bytes: []const u8,
    trusted_cert: ?signer.Certificate,
) !VerifyResult {
    const reader = cfbf.Reader{ .data = msi_bytes };
    const streams = try reader.readAllStreams(allocator);
    defer {
        for (streams) |s| {
            allocator.free(s.name);
            allocator.free(s.data);
        }
        allocator.free(streams);
    }

    // Extract signature stream (\x05DigitalSignature)
    var raw_cms: ?[]const u8 = null;
    for (streams) |s| {
        if (mem.eql(u16, s.name, msi.digital_signature_stream_name)) {
            raw_cms = s.data;
            break;
        }
    }

    const cms_bytes = raw_cms orelse return error.NoSignatureFound;

    const algo = try detectCmsHashAlgorithm(cms_bytes);
    const expected_imprint = try msi.computeImprint(
        allocator,
        streams,
        cfbf.msi_root_clsid,
        algo,
    );
    defer allocator.free(expected_imprint);

    return verifyCms(allocator, cms_bytes, expected_imprint, trusted_cert);
}

const testing = std.testing;
const fixtures = @import("../fixtures.zig");

test "verifyPe accepts ECDSA and RSA signatures and rejects other certificates" {
    const exe = try fixtures.read("mock.exe");
    defer testing.allocator.free(exe);

    var ecdsa = try fixtures.Credentials.load("leaf_g3c_us");
    defer ecdsa.deinit();
    var rsa = try fixtures.Credentials.load("rsa_codesign");
    defer rsa.deinit();
    var other = try fixtures.Credentials.load("leaf_g3b_nl");
    defer other.deinit();

    for ([_]fixtures.Credentials{ ecdsa, rsa }) |creds| {
        for ([_]HashAlgorithm{ .sha256, .sha384 }) |algorithm| {
            const signed = try creds.signPe(exe, algorithm);
            defer testing.allocator.free(signed);

            var res = try verifyPe(testing.allocator, signed, creds.cert);
            defer res.deinit(testing.allocator);
            try testing.expectEqual(algorithm, res.digest_algorithm);

            try testing.expectError(
                error.CertificateMismatch,
                verifyPe(testing.allocator, signed, other.cert),
            );
        }
    }
}

test "verifyPe detects tampered images" {
    const exe = try fixtures.read("mock.exe");
    defer testing.allocator.free(exe);
    var creds = try fixtures.Credentials.load("leaf_g3c_us");
    defer creds.deinit();

    const signed = try creds.signPe(exe, .sha256);
    defer testing.allocator.free(signed);
    signed[0x200] ^= 0xFF;
    try testing.expectError(error.DigestMismatch, verifyPe(testing.allocator, signed, null));
}

test "verifyMsi on signed MSI compound file using leaf_g3c_us" {
    const alloc = testing.allocator;
    var creds = try fixtures.Credentials.load("leaf_g3c_us");
    defer creds.deinit();

    var cf = cfbf.CompoundFile.init(alloc);
    defer cf.streams.deinit(alloc);
    try cf.addStream(std.unicode.utf8ToUtf16LeStringLiteral("Property"), "Property data");
    try cf.addStream(std.unicode.utf8ToUtf16LeStringLiteral("File"), "File data");

    const imprint = try msi.computeImprint(alloc, cf.streams.items, cfbf.msi_root_clsid, .sha256);
    defer alloc.free(imprint);

    const sig_der = try signer.sign(
        alloc,
        creds.key,
        creds.cert,
        &.{},
        .msi,
        imprint,
        .sha256,
        1776963092,
        "Test Installer",
        null,
    );
    defer alloc.free(sig_der);
    try cf.addStream(msi.digital_signature_stream_name, sig_der);

    const msi_bytes = try cf.write(alloc);
    defer alloc.free(msi_bytes);

    var res = try verifyMsi(alloc, msi_bytes, creds.cert);
    defer res.deinit(alloc);
    try testing.expectEqual(HashAlgorithm.sha256, res.digest_algorithm);
}
