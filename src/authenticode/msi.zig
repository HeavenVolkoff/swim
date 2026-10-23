//! Canonical MSI Authenticode stream collation and imprint computation.
//!
//! Windows Installer packages (MS-CFB compound files) authenticate the container
//! by hashing all non-signature streams in a deterministic canonical order known
//! as "MSI Name Order", followed by the 16-byte COM Class ID (CLSID) of the
//! root storage ({000C1084-0000-0000-C000-000000000046}).
//!
//! Collation rules for MSI Name Order:
//! 1. Compare the raw UTF-16LE bytes of each stream name up to the length of the
//!    shorter name.
//! 2. If the shared prefix differs, the byte with the smaller unsigned value
//!    sorts first.
//! 3. If one name is a strict prefix of the other, the LONGER name sorts FIRST
//!    (opposite to the CFBF directory red-black tree order).
//!
//! Excluded streams:
//! - `\x05DigitalSignature` (standard Authenticode CMS SignedData stream)
//! - `\x05MsiDigitalSignatureEx` (extended MSI digital signature stream)

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const cfbf = @import("../cfbf.zig");

/// Standard Authenticode signature stream name (`\x05DigitalSignature`).
pub const digital_signature_stream_name: []const u16 =
    std.unicode.utf8ToUtf16LeStringLiteral("\x05DigitalSignature");

/// Extended signature stream name (`\x05MsiDigitalSignatureEx`).
pub const msi_digital_signature_ex_stream_name: []const u16 =
    std.unicode.utf8ToUtf16LeStringLiteral("\x05MsiDigitalSignatureEx");

/// Reports whether the stream name matches one of the excluded signature streams.
pub fn isSignatureStream(name: []const u16) bool {
    return mem.eql(u16, name, digital_signature_stream_name) or
        mem.eql(u16, name, msi_digital_signature_ex_stream_name);
}

/// Compares two UTF-16LE stream names according to MSI Name Order:
/// byte-by-byte over the little-endian UTF-16 encoding, with the longer
/// name sorting first on a shared prefix match.
pub fn lessMsiStreamName(a: []const u16, b: []const u16) bool {
    const a_bytes = mem.sliceAsBytes(a);
    const b_bytes = mem.sliceAsBytes(b);
    const min_len = @min(a_bytes.len, b_bytes.len);

    for (a_bytes[0..min_len], b_bytes[0..min_len]) |ab, bb| {
        if (ab != bb) return ab < bb;
    }

    // Prefix match: the longer name sorts FIRST.
    return a_bytes.len > b_bytes.len;
}

/// Context struct for sorting `cfbf.Stream` slices in MSI Name Order.
pub const StreamSortContext = struct {
    pub fn lessThan(_: void, a: cfbf.Stream, b: cfbf.Stream) bool {
        return lessMsiStreamName(a.name, b.name);
    }
};

/// Supported cryptographic hash algorithms for Authenticode signatures.
pub const HashAlgorithm = enum {
    sha256,
    sha384,

    pub const max_digest_length = 48;

    /// Incremental hasher for the selected algorithm.
    pub const Hasher = union(HashAlgorithm) {
        sha256: std.crypto.hash.sha2.Sha256,
        sha384: std.crypto.hash.sha2.Sha384,

        pub fn update(self: *Hasher, data: []const u8) void {
            switch (self.*) {
                inline else => |*h| h.update(data),
            }
        }

        /// Writes the final digest into `out` and returns the active slice.
        pub fn final(self: *Hasher, out: *[max_digest_length]u8) []const u8 {
            switch (self.*) {
                inline else => |*h| {
                    const len = @TypeOf(h.*).digest_length;
                    h.final(out[0..len]);
                    return out[0..len];
                },
            }
        }

        /// Returns the final digest as a newly allocated slice owned by the caller.
        pub fn finalAlloc(self: *Hasher, allocator: Allocator) ![]u8 {
            var buf: [max_digest_length]u8 = undefined;
            return allocator.dupe(u8, self.final(&buf));
        }
    };

    /// Returns the `std.crypto` hash function type for a comptime-known algorithm.
    pub fn Hash(comptime self: HashAlgorithm) type {
        return @FieldType(Hasher, @tagName(self));
    }

    pub fn hasher(self: HashAlgorithm) Hasher {
        return switch (self) {
            inline else => |tag| @unionInit(Hasher, @tagName(tag), .init(.{})),
        };
    }

    /// Computes a one-shot digest of `data` into `out` and returns the active slice.
    pub fn hash(self: HashAlgorithm, data: []const u8, out: *[max_digest_length]u8) []const u8 {
        var h = self.hasher();
        h.update(data);
        return h.final(out);
    }
};

/// Computes the canonical Authenticode MSI Imprint over the provided streams
/// and root storage CLSID.
///
/// Automatically excludes signature streams (`\x05DigitalSignature` and
/// `\x05MsiDigitalSignatureEx`), sorts remaining streams into MSI Name Order,
/// digests each stream's content bytes, and folds in the 16-byte CLSID.
pub fn computeImprint(
    allocator: Allocator,
    streams: []const cfbf.Stream,
    root_clsid: [16]u8,
    algorithm: HashAlgorithm,
) ![]u8 {
    // 1. Filter out signature streams
    var filtered: std.ArrayList(cfbf.Stream) = .empty;
    defer filtered.deinit(allocator);

    for (streams) |s| {
        if (isSignatureStream(s.name)) continue;
        try filtered.append(allocator, s);
    }

    // 2. Sort remaining streams in MSI Name Order
    std.sort.block(cfbf.Stream, filtered.items, {}, StreamSortContext.lessThan);

    // 3. Digest streams and fold in CLSID
    var hasher = algorithm.hasher();
    for (filtered.items) |s| hasher.update(s.data);
    hasher.update(&root_clsid);
    return hasher.finalAlloc(allocator);
}

test "msi stream name ordering prefix comparison" {
    // "ABC" vs "AB": shared prefix "AB", so "ABC" (longer) must sort before "AB".
    const abc: []const u16 = &.{ 'A', 'B', 'C' };
    const ab: []const u16 = &.{ 'A', 'B' };

    try std.testing.expect(lessMsiStreamName(abc, ab));
    try std.testing.expect(!lessMsiStreamName(ab, abc));
}

test "msi stream name ordering differing characters" {
    const a: []const u16 = &.{ 'A', 'A' };
    const b: []const u16 = &.{ 'A', 'B' };

    try std.testing.expect(lessMsiStreamName(a, b));
    try std.testing.expect(!lessMsiStreamName(b, a));
}

test "computeImprint excludes signature streams and produces deterministic digest" {
    const testing = std.testing;
    const alloc = testing.allocator;

    const stream1_name: []const u16 = &.{ 'F', 'i', 'l', 'e', '1' };
    const stream2_name: []const u16 = &.{ 'F', 'i', 'l', 'e', '2' };

    const streams: []const cfbf.Stream = &.{
        .{ .name = stream2_name, .data = "stream two data" },
        .{ .name = digital_signature_stream_name, .data = "signature bytes to exclude" },
        .{ .name = stream1_name, .data = "stream one data" },
        .{ .name = msi_digital_signature_ex_stream_name, .data = "extended sig bytes" },
    };

    const imprint1 = try computeImprint(alloc, streams, cfbf.msi_root_clsid, .sha256);
    defer alloc.free(imprint1);

    // Compute again with different stream input slice order (should produce identical hash)
    const reversed_streams: []const cfbf.Stream = &.{
        .{ .name = stream1_name, .data = "stream one data" },
        .{ .name = stream2_name, .data = "stream two data" },
    };

    const imprint2 = try computeImprint(alloc, reversed_streams, cfbf.msi_root_clsid, .sha256);
    defer alloc.free(imprint2);

    try testing.expectEqualSlices(u8, imprint1, imprint2);
    try testing.expectEqual(@as(usize, 32), imprint1.len);
}
