//! CLI entry point for `swim`.

const std = @import("std");
const swim = @import("swim");

const cli = swim.cli;

/// Prints a formatted diagnostic message prefixed with `swim: ` to `stderr`
/// and terminates the process with exit code 1.
fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("swim: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

/// Reads the entire contents of `path` into `arena`, terminating the process
/// with a human-readable diagnostic on I/O failure.
fn readFile(io: std.Io, arena: std.mem.Allocator, path: []const u8) []const u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, arena, .unlimited) catch |err|
        fail("cannot read '{s}': {s}", .{ path, @errorName(err) });
}

pub fn main(init: std.process.Init) void {
    const arena = init.arena.allocator();

    const command = cli.parseProcessArgs(arena, init.minimal.args) catch |err| {
        const message = cli.errorMessage(err) orelse @errorName(err);
        std.debug.print("swim: {s}\n\n", .{message});
        cli.printHelp(init.io, .stderr()) catch {};
        std.process.exit(1);
    };
    const args = switch (command) {
        .help => {
            cli.printHelp(init.io, .stdout()) catch |err|
                fail("cannot write to stdout: {s}", .{@errorName(err)});
            return;
        },
        .build => |args| args,
    };

    const files = arena.alloc(swim.builder.FileInput, args.files.len) catch |err|
        fail("{s}", .{@errorName(err)});
    for (files, args.files, 0..) |*file, spec, i| {
        file.* = .{
            .target_subpath = spec.target,
            .content = readFile(init.io, arena, spec.source),
            .is_main = i == args.main_index,
        };
    }

    const timestamp = args.timestamp orelse std.Io.Clock.real.now(init.io).toSeconds();

    var signing_config: ?swim.builder.SigningConfig = null;
    if (args.signing) |sc| {
        const cert_bytes = readFile(init.io, arena, sc.cert_path);
        const key_bytes = readFile(init.io, arena, sc.key_path);
        const chain_bytes = arena.alloc([]const u8, sc.chain_paths.len) catch |err|
            fail("{s}", .{@errorName(err)});
        for (chain_bytes, sc.chain_paths) |*slot, path| {
            slot.* = readFile(init.io, arena, path);
        }
        signing_config = .{
            .cert_bytes = cert_bytes,
            .key_bytes = key_bytes,
            .chain_bytes = chain_bytes,
            .description = sc.description,
            .timestamp_server = if (sc.timestamp_url) |url|
                .{ .io = init.io, .url = url }
            else
                null,
        };
    }

    const msi = swim.builder.buildMsi(arena, .{
        .name = args.name,
        .version = args.version,
        .manufacturer = args.manufacturer,
        .arch = args.arch,
        .scope = args.scope,
        .license = if (args.license_path) |path| readFile(init.io, arena, path) else null,
        .icon = if (args.icon_path) |path| readFile(init.io, arena, path) else null,
        .timestamp = timestamp,
        .signing = signing_config,
        .files = files,
    }) catch |err| fail("{s}", .{swim.builder.errorMessage(err) orelse @errorName(err)});

    std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = args.output, .data = msi }) catch |err|
        fail("cannot write '{s}': {s}", .{ args.output, @errorName(err) });
    std.debug.print("swim: wrote '{s}' ({d} bytes)\n", .{ args.output, msi.len });
}
