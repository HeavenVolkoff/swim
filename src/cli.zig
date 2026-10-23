//! Command-line argument parsing and help generation powered by `zig-clap`.

const std = @import("std");
const clap = @import("clap");
const mem = std.mem;
const Allocator = mem.Allocator;

const builder = @import("builder.zig");

/// CLI specification.
pub const params = clap.parseParamsComptime(
    \\-n, --name <name>          Application name (required)
    \\-o, --output <file.msi>    Output MSI file (default: <name>.msi)
    \\-v, --version <x.x.x.x>    Application version, 1-4 numbers (default: 1.0.0.0)
    \\-m, --manufacturer <name>  Publisher / Manufacturer (default: <name>)
    \\-a, --arch <arch>          Target architecture: x64, arm64, arm, x86 (default: x64)
    \\-s, --scope <scope>        Installation scope: auto, machine, user (default: auto)
    \\-l, --license <file>       License agreement file (.rtf or text)
    \\-i, --icon <file.ico>      Application icon (installer, shortcuts, Add/Remove Programs)
    \\-t, --timestamp <seconds>  Package timestamp in Unix seconds (default: current time)
    \\    --main <path>          File that gets the shortcuts (default: first .exe)
    \\    --sign-cert <file>     Certificate file for Authenticode signing (PEM or DER)
    \\    --sign-key <file>      Private key file for Authenticode signing (PEM or DER)
    \\    --sign-chain <file>... Intermediate CA certificate chain (PEM or DER)
    \\    --sign-desc <desc>     Description for Authenticode signature (default: <name>)
    \\    --timestamp-url <url>  RFC 3161 timestamp server URL (e.g. DigiCert)
    \\-h, --help                 Show this help message
    \\<file>...                  Files to package (<path> or <source>:<destination>)
    \\
);

/// Value parsers mapped to the placeholder names in `params`.
const parsers = .{
    .name = clap.parsers.string,
    .@"file.msi" = clap.parsers.string,
    .@"x.x.x.x" = clap.parsers.string,
    .arch = clap.parsers.string,
    .scope = clap.parsers.enumeration(builder.Scope),
    .file = clap.parsers.string,
    .@"file.ico" = clap.parsers.string,
    .seconds = clap.parsers.string,
    .path = clap.parsers.string,
    .desc = clap.parsers.string,
    .url = clap.parsers.string,
};

/// Writes the full CLI banner, usage synopsis, and option table to `writer`.
pub fn writeHelp(writer: *std.Io.Writer) !void {
    try writer.writeAll(
        "swim - Simple Windows Installer (.msi) Creator\n\nUsage:\n  swim ",
    );
    try clap.usage(writer, clap.Help, &params);
    try writer.writeAll("\n\nOptions:\n");
    try clap.help(writer, clap.Help, &params, .{
        .indent = 2,
        .description_on_new_line = false,
        .description_indent = 4,
        .spacing_between_parameters = 0,
    });
}

/// Flushes the formatted CLI help text to `file` (typically `stdout`).
pub fn printHelp(io: std.Io, file: std.Io.File) !void {
    var buf: [1024]u8 = undefined;
    var writer = file.writer(io, &buf);
    try writeHelp(&writer.interface);
    try writer.interface.flush();
}

/// Mapping from a host file path to its relative path inside the install directory.
pub const FileSpec = struct {
    /// Path on the host filesystem to read the file content from.
    source: []const u8,
    /// Relative destination path under the install directory, normalized to `/` separators.
    target: []const u8,
};

/// Options for Windows Authenticode signing parsed from the command line.
pub const SigningArgs = struct {
    cert_path: []const u8,
    key_path: []const u8,
    chain_paths: []const []const u8 = &.{},
    description: ?[]const u8 = null,
    timestamp_url: ?[]const u8 = null,
};

/// Validated command-line arguments for building an MSI package.
pub const Args = struct {
    name: []const u8,
    output: []const u8,
    version: []const u8 = "1.0.0.0",
    manufacturer: ?[]const u8 = null,
    arch: builder.Arch = .x64,
    scope: builder.Scope = .auto,
    license_path: ?[]const u8 = null,
    icon_path: ?[]const u8 = null,
    timestamp: ?i64 = null,
    signing: ?SigningArgs = null,
    files: []const FileSpec,
    /// Index into `files` of the main executable that receives Desktop and Start Menu shortcuts,
    /// or `null` if no file was selected as main.
    main_index: ?usize = null,
};

/// Top-level action requested by the user on the command line.
pub const Command = union(enum) {
    help,
    build: Args,
};

/// Parses a string representation of a processor architecture into `builder.Arch`.
pub fn parseArch(str: []const u8) ?builder.Arch {
    if (std.ascii.eqlIgnoreCase(str, "x64") or std.ascii.eqlIgnoreCase(str, "amd64") or
        std.ascii.eqlIgnoreCase(str, "x86_64")) return .x64;
    if (std.ascii.eqlIgnoreCase(str, "arm64") or std.ascii.eqlIgnoreCase(str, "aarch64")) {
        return .arm64;
    }
    if (std.ascii.eqlIgnoreCase(str, "arm") or std.ascii.eqlIgnoreCase(str, "arm32")) {
        return .arm;
    }
    if (std.ascii.eqlIgnoreCase(str, "x86") or std.ascii.eqlIgnoreCase(str, "intel") or
        std.ascii.eqlIgnoreCase(str, "i386") or std.ascii.eqlIgnoreCase(str, "i686"))
    {
        return .x86;
    }
    return null;
}

/// Translates a CLI parsing error into a user-facing message, or returns `null`
/// for unrecognized errors.
pub fn errorMessage(err: anyerror) ?[]const u8 {
    return switch (err) {
        error.MissingName => "--name (-n) is required",
        error.NoFiles => "at least one file must be specified",
        error.InvalidFileSpec => "invalid file specification",
        error.UnknownOption, error.InvalidArgument, error.DoesntTakeValue => "unknown option",
        error.MissingValue => "option is missing its value",
        error.InvalidScope, error.NameNotPartOfEnum => "scope must be 'auto', 'machine' or 'user'",
        error.InvalidArch => "arch must be 'x64', 'arm64', 'arm', or 'x86'",
        error.InvalidTimestamp => "timestamp must be a valid integer number of Unix seconds",
        error.MissingSignKey, error.MissingSignCert => {
            return "both --sign-cert and --sign-key are required for code signing";
        },
        error.MainNotFound => "--main does not match any file",
        error.OutOfMemory => "out of memory",
        else => null,
    };
}

/// Returns a copy of `path` allocated in `arena` with all Windows `\` path
/// separators replaced by `/` so target paths use a single canonical separator.
fn normalizeSlashes(arena: Allocator, path: []const u8) ![]u8 {
    const normalized = try arena.dupe(u8, path);
    mem.replaceScalar(u8, normalized, '\\', '/');
    return normalized;
}

/// Parses a positional `<source>[:<destination>]` argument into a `FileSpec`.
///
/// When `:<destination>` is omitted, the destination defaults to the filename
/// component of `<source>` (accepting both `/` and `\` as path separators so
/// Windows paths work even when cross-packaging on Unix). A leading Windows
/// drive letter such as `C:\tool.exe` is skipped when searching for the `:`
/// delimiter so the drive colon is not mistaken for a destination separator.
fn parseFileSpec(arena: Allocator, spec: []const u8) !FileSpec {
    const has_drive = spec.len >= 2 and spec[1] == ':' and std.ascii.isAlphabetic(spec[0]);
    const search_from: usize = if (has_drive) 2 else 0;
    const colon = mem.indexOfScalarPos(u8, spec, search_from, ':');
    const source = if (colon) |c| spec[0..c] else spec;
    const target = if (colon) |c| spec[c + 1 ..] else std.fs.path.basenameWindows(spec);
    if (source.len == 0 or target.len == 0) return error.InvalidFileSpec;

    return .{ .source = source, .target = try normalizeSlashes(arena, target) };
}

/// Reports whether `path` ends with a `.exe` extension (case-insensitively).
fn isExe(path: []const u8) bool {
    return std.ascii.eqlIgnoreCase(std.fs.path.extension(path), ".exe");
}

/// Parses OS process arguments (skipping `argv[0]`) using `arena` for all
/// returned slices.
pub fn parseProcessArgs(arena: Allocator, process_args: std.process.Args) !Command {
    var iter = try process_args.iterateAllocator(arena);
    _ = iter.next();
    return parseIter(arena, &iter);
}

/// Parses a slice of argument strings (excluding the program name) using
/// `arena` for all returned slices.
pub fn parse(arena: Allocator, args: []const []const u8) !Command {
    var iter = clap.args.SliceIterator{ .args = args };
    return parseIter(arena, &iter);
}

/// Core argument parser shared by `parseProcessArgs` and `parse`.
///
/// Maps `zig-clap` diagnostics to domain-specific error tags and resolves which
/// packaged file (if any) is the main executable: either the file matching
/// `--main` (by source or destination path) or the first `.exe` file.
fn parseIter(arena: Allocator, iter: anytype) !Command {
    const res = clap.parseEx(clap.Help, &params, parsers, iter, .{
        .allocator = arena,
    }) catch |err| return switch (err) {
        error.InvalidArgument, error.DoesntTakeValue => error.UnknownOption,
        error.NameNotPartOfEnum => error.InvalidScope,
        else => err,
    };

    if (res.args.help != 0) return .help;
    const name = res.args.name orelse return error.MissingName;
    const raw_files = res.positionals[0];
    if (raw_files.len == 0) return error.NoFiles;

    const files = try arena.alloc(FileSpec, raw_files.len);
    for (files, raw_files) |*slot, spec| {
        slot.* = try parseFileSpec(arena, spec);
    }

    const arch: builder.Arch = if (res.args.arch) |a|
        parseArch(a) orelse return error.InvalidArch
    else
        .x64;

    const timestamp: ?i64 = if (res.args.timestamp) |ts|
        std.fmt.parseInt(i64, ts, 10) catch return error.InvalidTimestamp
    else
        null;

    const main_path = res.args.main;
    const main_target = if (main_path) |m| try normalizeSlashes(arena, m) else null;
    var main_index: ?usize = null;
    for (files, 0..) |file, index| {
        const is_main = if (main_path) |m|
            mem.eql(u8, file.target, main_target.?) or mem.eql(u8, file.source, m)
        else
            isExe(file.target);
        if (is_main) {
            main_index = index;
            break;
        }
    }
    if (main_path != null and main_index == null) return error.MainNotFound;

    const sign_cert = res.args.@"sign-cert";
    const sign_key = res.args.@"sign-key";
    if (sign_cert != null and sign_key == null) return error.MissingSignKey;
    if (sign_cert == null and sign_key != null) return error.MissingSignCert;
    if (sign_cert == null and (res.args.@"sign-chain".len > 0 or
        res.args.@"timestamp-url" != null or res.args.@"sign-desc" != null))
    {
        return error.MissingSignCert;
    }

    const signing: ?SigningArgs = if (sign_cert) |cert_path| .{
        .cert_path = cert_path,
        .key_path = sign_key.?,
        .chain_paths = res.args.@"sign-chain",
        .description = res.args.@"sign-desc" orelse name,
        .timestamp_url = res.args.@"timestamp-url",
    } else null;

    return .{
        .build = .{
            .name = name,
            .output = res.args.output orelse try std.fmt.allocPrint(arena, "{s}.msi", .{name}),
            .version = res.args.version orelse "1.0.0.0",
            .manufacturer = res.args.manufacturer,
            .arch = arch,
            .scope = res.args.scope orelse .auto,
            .license_path = res.args.license,
            .icon_path = res.args.icon,
            .timestamp = timestamp,
            .signing = signing,
            .files = files,
            .main_index = main_index,
        },
    };
}

const testing = std.testing;

fn parseForTest(arena: *std.heap.ArenaAllocator, args: []const []const u8) !Args {
    return (try parse(arena.allocator(), args)).build;
}

test "all options and file specs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const args = try parseForTest(&arena, &.{
        "-n",                    "TestApp",
        "--version=2.1.0",       "-m",
        "TestCorp",              "-s=user",
        "-l",                    "LICENSE.txt",
        "-i",                    "app.ico",
        "-o",                    "Custom.msi",
        "-a",                    "arm64",
        "-t",                    "1700000000",
        "bin/testapp.exe",       "lib/util.dll",
        "data.json:config.json", "C:\\tools\\x.dat:data\\x.dat",
        "C:\\tools\\y.dat",
    });
    try testing.expectEqualStrings("TestApp", args.name);
    try testing.expectEqualStrings("2.1.0", args.version);
    try testing.expectEqualStrings("TestCorp", args.manufacturer.?);
    try testing.expectEqual(builder.Arch.arm64, args.arch);
    try testing.expectEqual(builder.Scope.user, args.scope);
    try testing.expectEqualStrings("LICENSE.txt", args.license_path.?);
    try testing.expectEqualStrings("app.ico", args.icon_path.?);
    try testing.expectEqualStrings("Custom.msi", args.output);
    try testing.expectEqual(@as(?i64, 1700000000), args.timestamp);

    const expected = [_]FileSpec{
        .{ .source = "bin/testapp.exe", .target = "testapp.exe" },
        .{ .source = "lib/util.dll", .target = "util.dll" },
        .{ .source = "data.json", .target = "config.json" },
        .{ .source = "C:\\tools\\x.dat", .target = "data/x.dat" },
        .{ .source = "C:\\tools\\y.dat", .target = "y.dat" },
    };
    try testing.expectEqual(expected.len, args.files.len);
    for (expected, args.files) |want, got| {
        try testing.expectEqualStrings(want.source, got.source);
        try testing.expectEqualStrings(want.target, got.target);
    }
    try testing.expectEqual(@as(?usize, 0), args.main_index);
}

test "defaults" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const args = try parseForTest(&arena, &.{ "-n", "App", "readme.txt" });
    try testing.expectEqualStrings("App.msi", args.output);
    try testing.expectEqualStrings("1.0.0.0", args.version);
    try testing.expectEqual(builder.Arch.x64, args.arch);
    try testing.expectEqual(builder.Scope.auto, args.scope);
    try testing.expectEqual(@as(?i64, null), args.timestamp);
    try testing.expectEqual(@as(?usize, null), args.main_index);
}

test "architectures" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const cases = [_]struct { []const u8, builder.Arch }{
        .{ "x64", .x64 },
        .{ "amd64", .x64 },
        .{ "arm64", .arm64 },
        .{ "aarch64", .arm64 },
        .{ "arm", .arm },
        .{ "x86", .x86 },
        .{ "intel", .x86 },
    };
    for (cases) |c| {
        const args = try parseForTest(&arena, &.{ "-n", "App", "-a", c[0], "a.exe" });
        try testing.expectEqual(c[1], args.arch);
    }
}

test "scopes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const cases = [_]struct { []const u8, builder.Scope }{
        .{ "auto", .auto },
        .{ "machine", .machine },
        .{ "user", .user },
    };
    for (cases) |c| {
        const args = try parseForTest(&arena, &.{ "-n", "App", "-s", c[0], "a.exe" });
        try testing.expectEqual(c[1], args.scope);
    }
}

test "--main selects by target or source path" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const by_target = try parseForTest(
        &arena,
        &.{ "-n", "App", "--main", "tool.exe", "first.exe", "tool.exe" },
    );
    try testing.expectEqual(@as(?usize, 1), by_target.main_index);
    const by_win_target = try parseForTest(
        &arena,
        &.{ "-n", "App", "--main", "x\\b.exe", "a.exe", "bin\\b.exe:x\\b.exe" },
    );
    try testing.expectEqual(@as(?usize, 1), by_win_target.main_index);
    const by_source = try parseForTest(
        &arena,
        &.{ "-n", "App", "--main", "bin/b.exe", "a.exe", "bin/b.exe:x/b.exe" },
    );
    try testing.expectEqual(@as(?usize, 1), by_source.main_index);
}

test "errors and help" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const cases = [_]struct { []const []const u8, anyerror }{
        .{ &.{"app.exe"}, error.MissingName },
        .{ &.{ "-n", "App" }, error.NoFiles },
        .{ &.{ "-n", "App", ":dest.exe" }, error.InvalidFileSpec },
        .{ &.{ "-n", "App", "src.exe:" }, error.InvalidFileSpec },
        .{ &.{ "-n", "App", "--bogus", "a.exe" }, error.UnknownOption },
        .{ &.{ "-n", "App", "a.exe", "-o" }, error.MissingValue },
        .{ &.{ "-n", "App", "-s", "everyone", "a.exe" }, error.InvalidScope },
        .{ &.{ "-n", "App", "-a", "mips", "a.exe" }, error.InvalidArch },
        .{ &.{ "-n", "App", "-t", "notanumber", "a.exe" }, error.InvalidTimestamp },
        .{ &.{ "-n", "App", "--main", "nope.exe", "a.exe" }, error.MainNotFound },
    };
    for (cases) |c| try testing.expectError(c[1], parse(a, c[0]));
    for ([_][]const u8{ "-n", "-v", "-m", "-a", "-s", "-l", "-i", "-o", "-t", "--main" }) |flag| {
        try testing.expectError(error.MissingValue, parse(a, &.{flag}));
    }
    try testing.expect(try parse(a, &.{ "-n", "App", "--help" }) == .help);

    var help_buf: [2048]u8 = undefined;
    var writer = std.Io.Writer.fixed(&help_buf);
    try writeHelp(&writer);
    try testing.expect(mem.indexOf(u8, writer.buffered(), "-n, --name <name>") != null);
}

test "code signing CLI options" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Valid signing configuration
    const args = try parseForTest(
        &arena,
        &.{
            "-n",              "App",
            "--sign-cert",     "cert.pem",
            "--sign-key",      "key.pem",
            "--sign-chain",    "ca1.pem",
            "--sign-chain",    "ca2.pem",
            "--sign-desc",     "Custom Desc",
            "--timestamp-url", "http://timestamp.digicert.com",
            "app.exe",
        },
    );
    try testing.expect(args.signing != null);
    const sc = args.signing.?;
    try testing.expectEqualStrings("cert.pem", sc.cert_path);
    try testing.expectEqualStrings("key.pem", sc.key_path);
    try testing.expectEqual(@as(usize, 2), sc.chain_paths.len);
    try testing.expectEqualStrings("ca1.pem", sc.chain_paths[0]);
    try testing.expectEqualStrings("ca2.pem", sc.chain_paths[1]);
    try testing.expectEqualStrings("Custom Desc", sc.description.?);
    try testing.expectEqualStrings("http://timestamp.digicert.com", sc.timestamp_url.?);

    // Mismatched signing flags
    try testing.expectError(
        error.MissingSignKey,
        parse(a, &.{ "-n", "App", "--sign-cert", "cert.pem", "app.exe" }),
    );
    try testing.expectError(
        error.MissingSignCert,
        parse(a, &.{ "-n", "App", "--sign-key", "key.pem", "app.exe" }),
    );
    try testing.expectError(
        error.MissingSignCert,
        parse(a, &.{ "-n", "App", "--sign-chain", "ca.pem", "app.exe" }),
    );
}
