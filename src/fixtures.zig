//! Test-only helpers for loading files from the `test_fixtures/` directory.

const std = @import("std");
const testing = std.testing;
const signer = @import("authenticode/signer.zig");
const pe = @import("authenticode/pe.zig");
const HashAlgorithm = @import("authenticode/msi.zig").HashAlgorithm;

/// Reads `test_fixtures/<name>` using `testing.allocator`. Caller frees.
pub fn read(name: []const u8) ![]u8 {
    var path_buf: [256]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "test_fixtures/{s}", .{name});
    return std.Io.Dir.cwd().readFileAlloc(testing.io, path, testing.allocator, .unlimited);
}

/// Code signing credentials loaded from `test_fixtures/certs/<stem>.pem` and `.key`.
pub const Credentials = struct {
    cert_pem: []u8,
    key_pem: []u8,
    cert: signer.Certificate,
    key: signer.Key,

    pub fn load(comptime stem: []const u8) !Credentials {
        const cert_pem = try read("certs/" ++ stem ++ ".pem");
        errdefer testing.allocator.free(cert_pem);
        const key_pem = try read("certs/" ++ stem ++ ".key");
        errdefer testing.allocator.free(key_pem);
        var cert = try signer.Certificate.parse(testing.allocator, cert_pem);
        errdefer cert.deinit(testing.allocator);
        const key = try signer.Key.parse(testing.allocator, key_pem);
        return .{ .cert_pem = cert_pem, .key_pem = key_pem, .cert = cert, .key = key };
    }

    pub fn deinit(self: *Credentials) void {
        testing.allocator.free(self.cert_pem);
        testing.allocator.free(self.key_pem);
        self.cert.deinit(testing.allocator);
        self.key.deinit(testing.allocator);
    }

    /// Signs `exe` (an unsigned PE image) and returns the signed image. Caller frees.
    pub fn signPe(self: Credentials, exe: []const u8, algorithm: HashAlgorithm) ![]u8 {
        const digest = try pe.computeDigest(testing.allocator, exe, algorithm);
        defer testing.allocator.free(digest);
        const cms = try signer.sign(
            testing.allocator,
            self.key,
            self.cert,
            &.{},
            .pe,
            digest,
            algorithm,
            1_700_000_000,
            "Mock App",
            null,
        );
        defer testing.allocator.free(cms);
        return pe.appendSignature(testing.allocator, exe, cms);
    }
};

test {
    testing.refAllDecls(@This());
}
