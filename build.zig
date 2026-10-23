const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const test_filters = b.option(
        []const []const u8,
        "test-filter",
        "Skip tests that do not match any filter",
    ) orelse &.{};

    const clap_dep = b.dependency("clap", .{
        .target = target,
        .optimize = optimize,
    });

    const mod = b.addModule("swim", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "clap", .module = clap_dep.module("clap") },
        },
    });

    const exe_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "swim", .module = mod },
        },
    });

    const exe = b.addExecutable(.{
        .name = "swim",
        .root_module = exe_module,
    });
    b.installArtifact(exe);

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

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&check_fmt.step);
    test_step.dependOn(&run_mod_tests.step);

    // Check step (for LSP / ZLS build-on-save diagnostics without emitting binaries)
    const check_step = b.step("check", "Check if project compiles without building artifacts");
    const exe_check = b.addExecutable(.{
        .name = "swim",
        .root_module = exe_module,
    });
    const mod_test_check = b.addTest(.{
        .root_module = mod,
    });
    check_step.dependOn(&exe_check.step);
    check_step.dependOn(&mod_test_check.step);

    // Linter / static analysis step
    const lint_step = b.step("lint", "Run static analysis and formatting checks");
    lint_step.dependOn(&check_fmt.step);
    lint_step.dependOn(check_step);
}
