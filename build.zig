const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const strip = b.option(
        bool,
        "strip",
        "Strip debug information from binary",
    ) orelse (optimize == .small);
    const unwind_tables: ?std.builtin.UnwindTables = if (strip) .none else null;
    const error_tracing: ?bool = if (strip) false else null;
    const emit_pdb = b.option(
        bool,
        "pdb",
        "Emit PDB debug files on Windows (default: true for debug, false for release)",
    ) orelse (optimize == .debug);

    const test_filters = b.option(
        []const []const u8,
        "test-filter",
        "Skip tests that do not match any filter",
    ) orelse &.{};

    // Pure library module
    const mod = b.addModule("swim", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .strip = strip,
        .unwind_tables = unwind_tables,
        .error_tracing = error_tracing,
    });

    // Static library artifact for C / native consumers
    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "swim",
        .root_module = mod,
    });
    const lib_step = b.step("lib", "Build static library");
    lib_step.dependOn(&b.addInstallArtifact(lib, .{}).step);

    // Command-line executable application (imports swim and clap)
    const clap_dep = b.dependency("clap", .{
        .target = target,
        .optimize = optimize,
    });

    const exe_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = strip,
        .unwind_tables = unwind_tables,
        .error_tracing = error_tracing,
        .imports = &.{
            .{ .name = "swim", .module = mod },
            .{ .name = "clap", .module = clap_dep.module("clap") },
        },
    });

    const exe = b.addExecutable(.{
        .name = "swim",
        .root_module = exe_module,
    });
    const install_exe = b.addInstallArtifact(exe, .{
        .pdb_dir = if (emit_pdb) .default else .disabled,
    });
    b.default_step.dependOn(&install_exe.step);

    // Run step
    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();

    // Formatter steps
    const source_paths: []const std.Build.LazyPath = &.{
        b.path("src"),
        b.path("build.zig"),
        b.path("build.zig.zon"),
    };

    const fmt_step = b.step("fmt", "Format source files in-place");
    const fmt = b.addFmt(.{
        .paths = source_paths,
        .check = false,
    });
    fmt_step.dependOn(&fmt.step);

    const check_fmt_step = b.step("check-fmt", "Check source code formatting");
    const check_fmt = b.addFmt(.{
        .paths = source_paths,
        .check = true,
    });
    check_fmt_step.dependOn(&check_fmt.step);

    // Tests
    const mod_tests = b.addTest(.{
        .root_module = mod,
        .filters = test_filters,
    });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const cli_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cli.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "swim", .module = mod },
                .{ .name = "clap", .module = clap_dep.module("clap") },
            },
        }),
        .filters = test_filters,
    });
    const run_cli_tests = b.addRunArtifact(cli_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&check_fmt.step);
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_cli_tests.step);

    // Check step (for LSP / ZLS build-on-save diagnostics without emitting binaries)
    const check_step = b.step("check", "Check if project compiles without building artifacts");
    const exe_check = b.addExecutable(.{
        .name = "swim",
        .root_module = exe_module,
    });
    const mod_test_check = b.addTest(.{
        .root_module = mod,
    });
    const cli_test_check = b.addTest(.{
        .root_module = cli_tests.root_module,
    });
    check_step.dependOn(&exe_check.step);
    check_step.dependOn(&mod_test_check.step);
    check_step.dependOn(&cli_test_check.step);

    // Linter / static analysis step
    const lint_step = b.step("lint", "Run static analysis and formatting checks");
    lint_step.dependOn(&check_fmt.step);
    lint_step.dependOn(check_step);
}
