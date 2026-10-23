//! Cryptographic key ingestion, signing algorithms, and CMS SignedData assembly.
//!
//! Supports:
//! - ECDSA signatures over NIST P-384 (secp384r1) and P-256 (secp256r1) curves
//!   via `std.crypto.sign.ecdsa`.
//! - RSA PKCS#1 v1.5 signatures via `std.crypto.ff.Modulus`.
//! - Ingestion of standard PEM and DER formatted X.509 certificates and private
//!   keys (unencrypted PKCS#8, SEC1, and PKCS#1).

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const asn1 = @import("asn1.zig");
const timestamp = @import("timestamp.zig");
const HashAlgorithm = @import("msi.zig").HashAlgorithm;

/// Optional RFC 3161 timestamp authority endpoint configuration.
pub const TimestampConfig = struct {
    io: std.Io,
    url: []const u8,
};

/// ASN.1 TLV cursor for parsing keys and certificates without dynamic overhead.
pub const Tlv = struct {
    tag: u8,
    data: []const u8,
    start: usize,
    next: usize,
};

/// Reads an ASN.1 DER Tag-Length-Value from `bytes` at `offset`.
pub fn readTlv(bytes: []const u8, offset: usize) !Tlv {
    if (offset >= bytes.len) return error.UnexpectedEof;
    const tag = bytes[offset];
    var i = offset + 1;
    if (i >= bytes.len) return error.UnexpectedEof;
    const len_byte = bytes[i];
    i += 1;
    var len: usize = 0;
    if ((len_byte & 0x80) == 0) {
        len = len_byte;
    } else {
        const num_bytes = len_byte & 0x7F;
        if (num_bytes > 4 or i + num_bytes > bytes.len) return error.InvalidLength;
        for (0..num_bytes) |_| {
            len = (len << 8) | bytes[i];
            i += 1;
        }
    }
    if (i + len > bytes.len) return error.UnexpectedEof;
    return .{
        .tag = tag,
        .data = bytes[i .. i + len],
        .start = offset,
        .next = i + len,
    };
}

/// Sequential decoder for the PEM blocks in a text buffer whose label contains
/// a given substring (for example `"CERTIFICATE"` or `"PRIVATE KEY"`).
const PemReader = struct {
    lines: mem.TokenIterator(u8, .scalar),
    label: []const u8,
    /// Set once any `-----BEGIN` armor line has been seen.
    found_armor: bool = false,

    fn init(input: []const u8, label: []const u8) PemReader {
        return .{ .lines = mem.tokenizeScalar(u8, input, '\n'), .label = label };
    }

    /// Returns the DER bytes of the next matching block (owned by the caller),
    /// or `null` when no matching blocks remain.
    fn next(self: *PemReader, allocator: Allocator) !?[]u8 {
        var b64: std.ArrayList(u8) = .empty;
        defer b64.deinit(allocator);
        var in_block = false;
        while (self.lines.next()) |raw_line| {
            const line = mem.trim(u8, raw_line, "\r \t");
            if (mem.startsWith(u8, line, "-----BEGIN ")) {
                self.found_armor = true;
                in_block = mem.indexOf(u8, line, self.label) != null;
                b64.clearRetainingCapacity();
            } else if (mem.startsWith(u8, line, "-----END ")) {
                if (in_block) return try decodeBase64(allocator, b64.items);
            } else if (in_block) {
                try b64.appendSlice(allocator, line);
            }
        }
        return null;
    }
};

/// Returns the DER bytes of the first PEM block labelled with `label`, a copy of
/// `input` when it carries no PEM armor (raw DER), or `null` when it is PEM text
/// without a matching block. Caller owns the returned slice.
fn decodeFirstPem(allocator: Allocator, input: []const u8, label: []const u8) !?[]u8 {
    var reader: PemReader = .init(input, label);
    if (try reader.next(allocator)) |der| return der;
    if (reader.found_armor) return null;
    return try allocator.dupe(u8, input);
}

/// Appends the DER bytes of every certificate in a PEM bundle (or of a single raw
/// DER certificate) to `list`. Appended slices are owned by the caller.
pub fn decodeCertificates(
    allocator: Allocator,
    input: []const u8,
    list: *std.ArrayList([]const u8),
) !void {
    var reader: PemReader = .init(input, "CERTIFICATE");
    while (try reader.next(allocator)) |der| {
        errdefer allocator.free(der);
        try list.append(allocator, der);
    }
    if (!reader.found_armor) try list.append(allocator, try allocator.dupe(u8, input));
}

fn decodeBase64(allocator: Allocator, encoded: []const u8) ![]u8 {
    const decoder = std.base64.standard.Decoder;
    const dest_len = decoder.calcSizeForSlice(encoded) catch return error.InvalidPem;
    const dest = try allocator.alloc(u8, dest_len);
    errdefer allocator.free(dest);
    decoder.decode(dest, encoded) catch return error.InvalidPem;
    return dest;
}

/// Ingested X.509 Certificate metadata.
pub const Certificate = struct {
    raw: []u8,
    issuer_der: []const u8,
    serial_der: []const u8,
    thumbprint: [32]u8,

    pub fn parse(allocator: Allocator, pem_or_der: []const u8) !Certificate {
        const der = try decodeFirstPem(allocator, pem_or_der, "CERTIFICATE") orelse
            return error.InvalidCertificate;
        errdefer allocator.free(der);

        const cert_tlv = try readTlv(der, 0);
        if (cert_tlv.tag != 0x30) return error.InvalidCertificate;

        const tbs_tlv = try readTlv(cert_tlv.data, 0);
        if (tbs_tlv.tag != 0x30) return error.InvalidCertificate;

        const f0 = try readTlv(tbs_tlv.data, 0);
        const serial_tlv = if (f0.tag == 0xA0)
            try readTlv(tbs_tlv.data, f0.next)
        else
            f0;

        if (serial_tlv.tag != 0x02) return error.InvalidCertificate;

        const sig_alg_tlv = try readTlv(tbs_tlv.data, serial_tlv.next);
        const issuer_tlv = try readTlv(tbs_tlv.data, sig_alg_tlv.next);
        if (issuer_tlv.tag != 0x30) return error.InvalidCertificate;

        const serial_slice = tbs_tlv.data[serial_tlv.start..serial_tlv.next];
        const issuer_slice = tbs_tlv.data[issuer_tlv.start..issuer_tlv.next];

        var thumbprint: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(der, &thumbprint, .{});

        return .{
            .raw = der,
            .issuer_der = issuer_slice,
            .serial_der = serial_slice,
            .thumbprint = thumbprint,
        };
    }

    pub fn deinit(self: *Certificate, allocator: Allocator) void {
        allocator.free(self.raw);
    }
};

/// Ingested Private Key.
pub const Key = union(enum) {
    ecdsa_p384: [48]u8,
    ecdsa_p256: [32]u8,
    rsa: struct {
        modulus: []u8,
        d: []u8,
    },

    pub fn parse(allocator: Allocator, pem_or_der: []const u8) !Key {
        const der = try decodeFirstPem(allocator, pem_or_der, "PRIVATE KEY") orelse
            return error.InvalidPrivateKey;
        defer allocator.free(der);

        const outer = try readTlv(der, 0);
        if (outer.tag != 0x30) return error.InvalidPrivateKey;

        const v0 = try readTlv(outer.data, 0);
        if (v0.tag != 0x02) return error.InvalidPrivateKey;

        const f1 = try readTlv(outer.data, v0.next);

        if (f1.tag == 0x30) {
            // PKCS#8 PrivateKeyInfo: SEQUENCE { version, algId, privateKey OCTET STRING }
            const alg_oid = try readTlv(f1.data, 0);
            if (alg_oid.tag != 0x06) return error.InvalidPrivateKey;

            const priv_oct = try readTlv(outer.data, f1.next);
            if (priv_oct.tag != 0x04) return error.InvalidPrivateKey;

            const ec_oid = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
            const rsa_oid = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };

            if (mem.eql(u8, alg_oid.data, &ec_oid)) {
                const sec1 = try readTlv(priv_oct.data, 0);
                const s1_v = try readTlv(sec1.data, 0);
                const scalar_tlv = try readTlv(sec1.data, s1_v.next);
                return parseEcScalar(scalar_tlv.data);
            } else if (mem.eql(u8, alg_oid.data, &rsa_oid)) {
                const rsa_seq = try readTlv(priv_oct.data, 0);
                return parseRsaSequence(allocator, rsa_seq.data);
            }
            return error.UnsupportedKeyAlgorithm;
        } else if (f1.tag == 0x04) {
            // SEC1 ECPrivateKey: SEQUENCE { version (1), privateKey OCTET STRING }
            return parseEcScalar(f1.data);
        } else if (f1.tag == 0x02) {
            // PKCS#1 RSAPrivateKey directly
            return parseRsaSequence(allocator, outer.data);
        }

        return error.InvalidPrivateKey;
    }

    /// Returns the elliptic curve group backing an ECDSA key variant.
    fn Curve(comptime tag: std.meta.Tag(Key)) type {
        return switch (tag) {
            .ecdsa_p384 => std.crypto.ecc.P384,
            .ecdsa_p256 => std.crypto.ecc.P256,
            .rsa => @compileError("RSA keys have no elliptic curve"),
        };
    }

    /// Reports whether this private key belongs to the public key embedded in `cert`.
    pub fn matches(self: Key, cert: Certificate) !bool {
        const parsed = std.crypto.Certificate.parse(.{ .buffer = cert.raw, .index = 0 }) catch
            return error.InvalidCertificate;
        const cert_pub_key = parsed.pubKey();
        switch (self) {
            inline .ecdsa_p384, .ecdsa_p256 => |sk, tag| {
                const Scheme = std.crypto.sign.ecdsa.Ecdsa(Curve(tag), std.crypto.hash.sha2.Sha256);
                const secret = Scheme.SecretKey.fromBytes(sk) catch return false;
                const kp = Scheme.KeyPair.fromSecretKey(secret) catch return false;
                return mem.eql(u8, &kp.public_key.toUncompressedSec1(), cert_pub_key);
            },
            .rsa => |r| {
                const rsa_pub = readTlv(cert_pub_key, 0) catch return false;
                if (rsa_pub.tag != 0x30) return false;
                const mod_tlv = readTlv(rsa_pub.data, 0) catch return false;
                if (mod_tlv.tag != 0x02) return false;
                return mem.eql(u8, stripLeadingZero(mod_tlv.data), r.modulus);
            },
        }
    }

    pub fn deinit(self: *Key, allocator: Allocator) void {
        switch (self.*) {
            .rsa => |r| {
                allocator.free(r.modulus);
                allocator.free(r.d);
            },
            else => {},
        }
    }
};

/// Classifies a raw ECDSA private scalar by its fixed SEC1 length.
fn parseEcScalar(scalar: []const u8) !Key {
    return switch (scalar.len) {
        48 => .{ .ecdsa_p384 = scalar[0..48].* },
        32 => .{ .ecdsa_p256 = scalar[0..32].* },
        else => error.UnsupportedCurve,
    };
}

fn parseRsaSequence(allocator: Allocator, rsa_data: []const u8) !Key {
    const v = try readTlv(rsa_data, 0);
    const n_tlv = try readTlv(rsa_data, v.next);
    const e_tlv = try readTlv(rsa_data, n_tlv.next);
    const d_tlv = try readTlv(rsa_data, e_tlv.next);

    const modulus = try allocator.dupe(u8, stripLeadingZero(n_tlv.data));
    errdefer allocator.free(modulus);

    const d = try allocator.dupe(u8, stripLeadingZero(d_tlv.data));
    errdefer allocator.free(d);

    return .{
        .rsa = .{
            .modulus = modulus,
            .d = d,
        },
    };
}

/// Strips the sign-padding `0x00` byte from an unsigned big-endian DER INTEGER.
pub fn stripLeadingZero(int_bytes: []const u8) []const u8 {
    return if (int_bytes.len > 1 and int_bytes[0] == 0x00) int_bytes[1..] else int_bytes;
}

/// Formats an EMSA-PKCS1-v1_5 encoded message block (`0x00 || 0x01 || PS || 0x00 || DigestInfo`)
/// over `msg` using `algorithm` into `em`.
pub fn encodePkcs1v15(em: []u8, msg: []const u8, algorithm: HashAlgorithm) !void {
    // DER DigestInfo header: SEQUENCE { AlgorithmIdentifier, OCTET STRING (digest) }
    const sha256_prefix = [_]u8{ 0x30, 0x31 } ++ asn1.alg_id_sha256 ++ [_]u8{ 0x04, 0x20 };
    const sha384_prefix = [_]u8{ 0x30, 0x41 } ++ asn1.alg_id_sha384 ++ [_]u8{ 0x04, 0x30 };

    var hash_buf: [HashAlgorithm.max_digest_length]u8 = undefined;
    const digest = algorithm.hash(msg, &hash_buf);
    const prefix: []const u8 = switch (algorithm) {
        .sha256 => &sha256_prefix,
        .sha384 => &sha384_prefix,
    };

    const t_len = prefix.len + digest.len;
    if (em.len < t_len + 11) return error.ModulusTooSmall;

    em[0] = 0x00;
    em[1] = 0x01;
    const ps_len = em.len - t_len - 3;
    @memset(em[2 .. 2 + ps_len], 0xFF);
    em[2 + ps_len] = 0x00;

    const t_start = 2 + ps_len + 1;
    @memcpy(em[t_start .. t_start + prefix.len], prefix);
    @memcpy(em[t_start + prefix.len .. em.len], digest);
}

fn signEcdsa(
    comptime Curve: type,
    comptime Hash: type,
    sk_bytes: [Curve.scalar.encoded_length]u8,
    msg: []const u8,
    out_buf: *[512]u8,
) ![]const u8 {
    const Scheme = std.crypto.sign.ecdsa.Ecdsa(Curve, Hash);
    var hash_val: [Hash.digest_length]u8 = undefined;
    Hash.hash(msg, &hash_val, .{});
    const sk = try Scheme.SecretKey.fromBytes(sk_bytes);
    const kp = try Scheme.KeyPair.fromSecretKey(sk);
    const ecdsa_sig = try kp.signPrehashed(hash_val, null);
    var der_buf: [Scheme.Signature.der_encoded_length_max]u8 = undefined;
    const der_slice = ecdsa_sig.toDer(&der_buf);
    @memcpy(out_buf[0..der_slice.len], der_slice);
    return out_buf[0..der_slice.len];
}

/// Generates a signed CMS / Authenticode ContentInfo structure for the given payload.
pub fn sign(
    allocator: Allocator,
    key: Key,
    cert: Certificate,
    chain_ders: []const []const u8,
    target: asn1.Target,
    message_imprint: []const u8,
    algorithm: HashAlgorithm,
    signing_time: ?i64,
    description: ?[]const u8,
    timestamp_config: ?TimestampConfig,
) ![]u8 {
    // 1. Build SpcIndirectDataContent
    const spc = try asn1.buildSpcIndirectData(allocator, target, message_imprint, algorithm);
    defer spc.deinit(allocator);

    // 2. Hash SpcIndirectDataContent contents octets
    var spc_digest_buf: [HashAlgorithm.max_digest_length]u8 = undefined;
    const spc_digest = algorithm.hash(spc.contents, &spc_digest_buf);

    // 3. Build Authenticode signed attributes
    const attrs = try asn1.buildSignedAttributes(
        allocator,
        spc_digest,
        signing_time orelse 0,
        description,
    );
    defer attrs.deinit(allocator);

    // 4. Compute cryptographic signature over `signing_attrs_set`
    var sig_bytes_buf: [512]u8 = undefined;
    var sig_bytes: []const u8 = undefined;
    var sig_alg_oid: []const u8 = undefined;
    var sig_alg_has_null: bool = false;

    switch (key) {
        inline .ecdsa_p384, .ecdsa_p256 => |sk, tag| {
            sig_bytes = switch (algorithm) {
                inline else => |alg| try signEcdsa(
                    Key.Curve(tag),
                    alg.Hash(),
                    sk,
                    attrs.signing_attrs_set,
                    &sig_bytes_buf,
                ),
            };
            sig_alg_oid = switch (algorithm) {
                .sha256 => &asn1.oid_ecdsa_with_sha256,
                .sha384 => &asn1.oid_ecdsa_with_sha384,
            };
        },
        .rsa => |r| {
            const em_len = r.modulus.len;
            var em_buf: [512]u8 = undefined;
            if (em_len > em_buf.len) return error.ModulusTooLarge;
            const em = em_buf[0..em_len];

            try encodePkcs1v15(em, attrs.signing_attrs_set, algorithm);

            const Modulus = std.crypto.ff.Modulus(4096);
            const mod = try Modulus.fromBytes(r.modulus, .big);
            const x = try Modulus.Fe.fromBytes(mod, em, .big);
            const s = try mod.powWithEncodedExponent(x, r.d, .big);

            try s.toBytes(sig_bytes_buf[0..em_len], .big);
            sig_bytes = sig_bytes_buf[0..em_len];

            sig_alg_oid = &asn1.oid_rsa_encryption;
            sig_alg_has_null = true;
        },
    }

    // 5. Optional RFC 3161 counter-signature over `sig_bytes` (SignerInfo.signature)
    const timestamp_token = if (timestamp_config) |tc|
        try timestamp.requestTimestamp(tc.io, allocator, tc.url, sig_bytes, algorithm)
    else
        null;
    defer if (timestamp_token) |tok| allocator.free(tok);

    // 6. Assemble ContentInfo DER container
    return asn1.assembleContentInfo(
        allocator,
        spc.der,
        cert.raw,
        cert.issuer_der,
        cert.serial_der,
        chain_ders,
        algorithm,
        sig_alg_oid,
        sig_alg_has_null,
        attrs.embedded_attrs,
        sig_bytes,
        timestamp_token,
    );
}

const fixtures = @import("../fixtures.zig");

test "keys match only their own certificates" {
    var ecdsa = try fixtures.Credentials.load("leaf_g3c_us");
    defer ecdsa.deinit();
    var rsa = try fixtures.Credentials.load("rsa_codesign");
    defer rsa.deinit();

    try std.testing.expect(try ecdsa.key.matches(ecdsa.cert));
    try std.testing.expect(try rsa.key.matches(rsa.cert));
    try std.testing.expect(!try ecdsa.key.matches(rsa.cert));
    try std.testing.expect(!try rsa.key.matches(ecdsa.cert));
}

test "PEM decoding selects labelled blocks and accepts raw DER" {
    const testing = std.testing;
    const alloc = testing.allocator;
    var creds = try fixtures.Credentials.load("leaf_g3c_us");
    defer creds.deinit();

    // A key file preceded by an unrelated PEM block (as `openssl ecparam -genkey` emits).
    const bundle = try mem.concat(alloc, u8, &.{
        "-----BEGIN EC PARAMETERS-----\nBgUrgQQAIg==\n-----END EC PARAMETERS-----\n",
        creds.key_pem,
    });
    defer alloc.free(bundle);
    var key = try Key.parse(alloc, bundle);
    defer key.deinit(alloc);
    try testing.expect(try key.matches(creds.cert));

    // Raw DER certificates pass through unchanged; bundles yield every certificate.
    var der_cert = try Certificate.parse(alloc, creds.cert.raw);
    defer der_cert.deinit(alloc);
    try testing.expectEqualSlices(u8, &creds.cert.thumbprint, &der_cert.thumbprint);

    const two = try mem.concat(alloc, u8, &.{ creds.cert_pem, creds.cert_pem });
    defer alloc.free(two);
    var list: std.ArrayList([]const u8) = .empty;
    defer {
        for (list.items) |c| alloc.free(c);
        list.deinit(alloc);
    }
    try decodeCertificates(alloc, two, &list);
    try testing.expectEqual(@as(usize, 2), list.items.len);
    try testing.expectEqualSlices(u8, creds.cert.raw, list.items[1]);

    try testing.expectError(error.InvalidCertificate, Certificate.parse(alloc, creds.key_pem));
}
