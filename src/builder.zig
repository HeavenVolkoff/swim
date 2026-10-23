//! High-level Windows Installer (`.msi`) package validator and builder.
//!
//! Given a `Config` describing the product metadata, installation scope, optional
//! license/icon, and payload files, this module:
//! 1. Validates all user-supplied strings, version numbers, and target paths
//!    against Windows filesystem, Registry, and MSI `[Formatted]` string rules.
//! 2. Populates the relational MSI database (`buildDatabase`), deriving deterministic
//!    UUIDv4-formatted GUIDs from SHA-256 hashes of the inputs so builds are
//!    reproducible and upgrades work out of the box.
//! 3. Packs payload files into `cab1.cab`, writes `\x05SummaryInformation`, and
//!    serializes the entire compound file (`buildMsi`).

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const cab = @import("cab.zig");
const cfbf = @import("cfbf.zig");
const schema = @import("schema.zig");
const stream_name = @import("stream_name.zig");
const summary_info = @import("summary_info.zig");
const table = @import("table.zig");
const ui = @import("ui.zig");
const authenticode = @import("authenticode.zig");

const Database = table.Database;

/// Target processor architecture for the package.
pub const Arch = enum {
    /// 64-bit AMD64 / x86-64 architecture.
    x64,
    /// 64-bit ARM64 / AArch64 architecture.
    arm64,
    /// 32-bit ARM architecture.
    arm,
    /// 32-bit x86 architecture.
    x86,

    /// Returns the architecture token stored in the summary information template property.
    pub fn templateToken(self: Arch) []const u8 {
        return switch (self) {
            .x64 => "x64",
            .arm64 => "Arm64",
            .arm => "Arm",
            .x86 => "Intel",
        };
    }

    /// Reports whether this target architecture uses 64-bit directories and registry views.
    pub fn is64Bit(self: Arch) bool {
        return switch (self) {
            .x64, .arm64 => true,
            .arm, .x86 => false,
        };
    }

    /// Returns the standard Program Files directory property for this architecture.
    pub fn programFilesFolder(self: Arch) []const u8 {
        return if (self.is64Bit()) "ProgramFiles64Folder" else "ProgramFilesFolder";
    }
};

/// Installation privilege and target-directory scope for the MSI package.
pub const Scope = enum {
    /// Dual-purpose package (`ALLUSERS = 2`): installs per-machine under Program Files
    /// when run elevated, or per-user under `LocalAppDataFolder` without a UAC prompt
    /// when run by a standard user.
    auto,
    /// Per-machine installation (`ALLUSERS = 1`) into Program Files;
    /// triggers a UAC elevation prompt during installation.
    machine,
    /// Per-user installation (`ALLUSERS` omitted) into `LocalAppDataFolder`;
    /// never requires administrator privileges.
    user,
};

/// A payload file to be installed under `INSTALLFOLDER`.
pub const FileInput = struct {
    /// Relative destination path under the install directory using `/` separators
    /// (for example `"mock.exe"` or `"bin/mock.dll"`).
    target_subpath: []const u8,
    /// Raw file bytes to embed in the package cabinet.
    content: []const u8,
    /// When `true`, creates Desktop and Start Menu shortcuts pointing to this file.
    /// At most one file in `Config.files` may have `is_main = true`.
    is_main: bool = false,
};

/// Configuration for signing the package and payload binaries.
pub const SigningConfig = struct {
    /// Leaf code signing certificate in PEM or DER format.
    cert_bytes: []const u8,
    /// Private key for signing in PEM or DER format.
    key_bytes: []const u8,
    /// Optional intermediate certificate chain elements in PEM or DER format.
    chain_bytes: []const []const u8 = &.{},
    /// Optional publisher description (SpcSpOpusInfo).
    description: ?[]const u8 = null,
    /// Optional RFC 3161 Time-Stamp Authority used to counter-sign every signature.
    timestamp_server: ?authenticode.signer.TimestampConfig = null,
    /// Cryptographic hash algorithm (defaults to SHA-256).
    hash_algorithm: authenticode.msi.HashAlgorithm = .sha256,
};

/// Complete specification of an MSI package to be built by `buildMsi`.
pub const Config = struct {
    /// Product display name (`ProductName`), also used as the default install
    /// folder name under Program Files or `%LocalAppData%`.
    name: []const u8,
    /// Dot-separated product version (`1` to `4` components, max `255.255.65535.65535`).
    version: []const u8 = "1.0.0.0",
    /// Publisher name (`Manufacturer` property). Defaults to `name` when `null`.
    manufacturer: ?[]const u8 = null,
    /// Target processor architecture (defaults to `x64`).
    arch: Arch = .x64,
    scope: Scope = .auto,
    /// Optional license agreement text (plain UTF-8/Windows-1252 or raw RTF).
    /// When provided, the welcome dialog requires ticking a license-acceptance
    /// checkbox before `Install` is enabled.
    license: ?[]const u8 = null,
    /// Optional `.ico` file bytes used for shortcuts and Add/Remove Programs.
    icon: ?[]const u8 = null,
    /// Payload files to install (must contain at least one file).
    files: []const FileInput,
    /// Creation timestamp (seconds since the Unix epoch) recorded in
    /// `\x05SummaryInformation`. Defaults to `0` (1970-01-01T00:00:00Z) so builds
    /// are byte-for-byte deterministic when a timestamp is not supplied.
    timestamp: i64 = 0,
    /// Optional code signing configuration. When provided, unsigned PE binaries
    /// are automatically signed, pre-signed PE binaries are verified against the
    /// certificate, and the outer MSI package is signed with \x05DigitalSignature.
    signing: ?SigningConfig = null,
};

/// Maximum length in bytes of `Config.name` and `Config.manufacturer` (chosen to
/// fit within `Feature.Title`'s 64-character schema limit).
const max_label_len = 64;

const icon_name = "ProductIcon.ico";
const main_feature = "MainFeature";
const install_folder = "INSTALLFOLDER";

/// Registry root value `-1` indicates user-or-machine context: resolves to `HKLM`
/// during per-machine installs and `HKCU` during per-user installs.
const hkmu = -1;

/// Returns the `ALLUSERS` property value corresponding to `scope`, or `null` for
/// `.user` (where `ALLUSERS` must remain unset to force per-user context).
fn allUsers(scope: Scope) ?[]const u8 {
    return switch (scope) {
        .machine => "1",
        .auto => "2",
        .user => null,
    };
}

/// Translates a builder or validation error into a human-readable diagnostic,
/// or returns `null` for unexpected errors.
pub fn errorMessage(err: anyerror) ?[]const u8 {
    return switch (err) {
        error.InvalidName => "name must be 1-64 characters and must not contain" ++
            " control characters or any of \\ / : * ? \" < > | [ ]",
        error.InvalidManufacturer => "manufacturer must be 1-64 characters" ++
            " without control characters or any of \\ [ ]",
        error.InvalidVersion => "version must be 1 to 4 dot-separated numbers" ++
            " (max 255.255.65535.65535)",
        error.InvalidIcon => "icon file must not be empty",
        error.InvalidTargetPath => "install paths must be relative, use '/' separators" ++
            " and contain no '.', '..' or any of \\ : * ? \" < > | [ ]",
        error.DuplicateTarget => "two files have conflicting install paths",
        error.NoFiles => "at least one file must be specified",
        error.TooManyFiles => "too many files (maximum 65535)",
        error.TooManyMainFiles => "only one file can be the main executable",
        error.PackageTooLarge, error.CabinetTooLarge => "package contents exceed 2 GiB",
        error.StringTooLong => "a text value (such as the license) exceeds 65535 bytes",
        error.TooManyStrings => "string pool exceeds 65534 entries",
        error.UnsignedInstallerWithSignedPayload => "cannot create unsigned installer:" ++
            " payload file is already code signed." ++
            " Packages containing signed binaries must themselves be code signed",
        error.CertificateMismatch => "certificate mismatch: payload file is signed with" ++
            " a different certificate than the installer",
        error.KeyCertificateMismatch => "signing private key does not match the certificate",
        error.InvalidPem => "invalid PEM encoding in certificate or key file",
        error.InvalidCertificate => "invalid X.509 signing certificate (expected PEM or DER)",
        error.InvalidPrivateKey => "invalid signing private key" ++
            " (expected PKCS#8, SEC1, or PKCS#1 PEM/DER)",
        error.UnsupportedCurve => "unsupported elliptic curve (expected P-256 or P-384)",
        error.UnsupportedKeyAlgorithm => "unsupported private key algorithm" ++
            " (expected ECDSA or RSA)",
        error.TsaRequestFailed => "RFC 3161 timestamp authority HTTP request failed",
        error.TsaStatusRejected => "RFC 3161 timestamp authority rejected the request",
        error.InvalidTimeStampResponse => "RFC 3161 timestamp authority returned invalid response",
        error.OutOfMemory => "out of memory",
        else => null,
    };
}

/// Validates `config` and builds a complete `.msi` compound file in memory.
///
/// Caller owns the returned byte slice, which is allocated from `gpa` (all
/// intermediate database and cabinet structures use an internal arena).
pub fn buildMsi(gpa: Allocator, config: Config) ![]u8 {
    try validate(config);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    // 1. Prepare signing credentials if requested
    var signing_cert: ?authenticode.signer.Certificate = null;
    var signing_key: ?authenticode.signer.Key = null;
    var chain_list: std.ArrayList([]const u8) = .empty;

    if (config.signing) |sc| {
        signing_cert = try authenticode.signer.Certificate.parse(a, sc.cert_bytes);
        signing_key = try authenticode.signer.Key.parse(a, sc.key_bytes);
        if (!try signing_key.?.matches(signing_cert.?)) return error.KeyCertificateMismatch;
        for (sc.chain_bytes) |cb| {
            try authenticode.signer.decodeCertificates(a, cb, &chain_list);
        }
    }

    // 2. Payload Validation & Auto-Signing Engine (Rules 1-5)
    var processed_files = try a.alloc(FileInput, config.files.len);
    for (config.files, 0..) |file, i| {
        if (authenticode.pe.isPe(file.content)) {
            const is_signed = try authenticode.pe.isSigned(file.content);
            if (config.signing == null) {
                // Rule 1: Reject unsigned installer when any payload PE is signed
                if (is_signed) return error.UnsignedInstallerWithSignedPayload;
                processed_files[i] = file;
            } else {
                const sc = config.signing.?;
                if (is_signed) {
                    // Rule 2 & 4: Payload is already signed -> verify against installer certificate
                    var res = try authenticode.verify.verifyPe(
                        a,
                        file.content,
                        signing_cert.?,
                    );
                    res.deinit(a);
                    processed_files[i] = file;
                } else {
                    // Rule 3: Auto-sign unsigned PE payload in-memory
                    const pe_digest = try authenticode.pe.computeDigest(
                        a,
                        file.content,
                        sc.hash_algorithm,
                    );
                    const pe_sig = try authenticode.signer.sign(
                        a,
                        signing_key.?,
                        signing_cert.?,
                        chain_list.items,
                        .pe,
                        pe_digest,
                        sc.hash_algorithm,
                        config.timestamp,
                        sc.description,
                        sc.timestamp_server,
                    );
                    const signed_pe = try authenticode.pe.appendSignature(a, file.content, pe_sig);
                    processed_files[i] = .{
                        .target_subpath = file.target_subpath,
                        .content = signed_pe,
                        .is_main = file.is_main,
                    };
                }
            }
        } else {
            // Rule 5: Non-PE payload files pass through into cabinet
            processed_files[i] = file;
        }
    }

    var effective_config = config;
    effective_config.files = processed_files;

    var db = try buildDatabase(a, effective_config);
    var cf = cfbf.CompoundFile.init(a);

    var cabinet = cab.Cabinet.init(a);
    for (processed_files, 0..) |file, i| {
        try cabinet.addFile(try indexed(a, "fil", i), file.content);
    }
    try cf.addStream(try stream_name.encode(a, "cab1.cab", false), try cabinet.write(a));
    if (config.icon) |icon| {
        try cf.addStream(try stream_name.encode(a, "Icon." ++ icon_name, false), icon);
    }

    try db.writeStreams(&cf);
    const summary_name = std.unicode.utf8ToUtf16LeStringLiteral("\x05SummaryInformation");
    try cf.addStream(summary_name, try summaryInformation(a, effective_config));

    // 3. MSI Container Signing
    if (config.signing) |sc| {
        const imprint = try authenticode.msi.computeImprint(
            a,
            cf.streams.items,
            cfbf.msi_root_clsid,
            sc.hash_algorithm,
        );
        const msi_sig = try authenticode.signer.sign(
            a,
            signing_key.?,
            signing_cert.?,
            chain_list.items,
            .msi,
            imprint,
            sc.hash_algorithm,
            config.timestamp,
            sc.description,
            sc.timestamp_server,
        );
        try cf.addStream(authenticode.msi.digital_signature_stream_name, msi_sig);
    }

    return cf.write(gpa);
}

/// Constructs the in-memory MSI relational `Database` for `config`, including
/// properties, directory tree, components, files, shortcuts, wizard UI dialogs,
/// and execution sequences. All allocations are made from arena `a`.
pub fn buildDatabase(a: Allocator, config: Config) !Database {
    var db = Database.init(a);
    const mfr = config.manufacturer orelse config.name;
    var has_main = false;
    for (config.files) |f| {
        if (f.is_main) {
            has_main = true;
            break;
        }
    }
    try addProperties(&db, config, mfr, has_main);
    try addPayload(&db, config, mfr);

    const ui_seq = try ui.addWizard(&db, config.name, config.license, has_main);
    const exec_seq = try schema.addSequence(
        &db,
        "InstallExecuteSequence",
        &schema.install_execute_steps,
    );
    _ = try schema.addSequence(&db, "AdminExecuteSequence", &schema.admin_execute_steps);
    _ = try schema.addSequence(&db, "AdvtExecuteSequence", &schema.advt_execute_steps);
    if (config.scope == .auto) try addFolderSelection(&db, config, &.{ ui_seq, exec_seq });
    return db;
}

/// Appends property-assignment custom actions that dynamically point `INSTALLFOLDER`
/// to the target architecture's Program Files folder when `ALLUSERS = 1` (elevated
/// per-machine install) or `[LocalAppDataFolder]<name>` otherwise.
///
/// The actions are scheduled at sequences 990/991—immediately before costing
/// finalization (1000)—in both `InstallUISequence` and `InstallExecuteSequence` so
/// directory resolution uses the effective privilege context in both interactive
/// and silent installs.
fn addFolderSelection(db: *Database, config: Config, sequences: []const *table.Table) !void {
    const a = db.allocator;
    const t_action = try db.addTable(schema.custom_action);
    const Choice = struct {
        action: []const u8,
        root: []const u8,
        condition: []const u8,
        sequence: i32,
    };
    const choices = [_]Choice{
        .{
            .action = "SetFolder_Machine",
            .root = config.arch.programFilesFolder(),
            .condition = "ALLUSERS = 1",
            .sequence = 990,
        },
        .{
            .action = "SetFolder_User",
            .root = "LocalAppDataFolder",
            .condition = "NOT (ALLUSERS = 1)",
            .sequence = 991,
        },
    };
    for (choices) |c| {
        // Custom action type 51 (property formatted string assignment):
        // assigns the formatted string in `Target` to the property named in `Source`.
        try t_action.addRow(.{
            .Action = c.action,
            .Type = 51,
            .Source = install_folder,
            .Target = try std.fmt.allocPrint(a, "[{s}]{s}", .{ c.root, config.name }),
        });
        for (sequences) |seq| {
            try seq.addRow(.{
                .Action = c.action,
                .Condition = c.condition,
                .Sequence = c.sequence,
            });
        }
    }
}

/// Populates the `Property` table (and `Icon` table when an icon is configured).
///
/// `UpgradeCode` is derived deterministically from `(name, manufacturer)` so all
/// versions of the same product share a stable family identifier, whereas
/// `ProductCode` also hashes `version` so each release gets a distinct identity.
fn addProperties(db: *Database, config: Config, mfr: []const u8, has_main: bool) !void {
    const a = db.allocator;
    const t = try db.addTable(schema.property);

    const common = [_]struct { []const u8, []const u8 }{
        .{ "ProductName", config.name },
        .{ "ProductVersion", config.version },
        .{ "Manufacturer", mfr },
        .{ "ProductCode", try guid(a, &.{ "ProductCode", config.name, mfr, config.version }) },
        .{ "UpgradeCode", try guid(a, &.{ "UpgradeCode", config.name, mfr }) },
        .{ "ProductLanguage", "1033" },
        .{ "ARPINSTALLLOCATION", "[" ++ install_folder ++ "]" },
        .{ "DefaultUIFont", "DefaultUI_Font" },
    };
    for (common) |p| try t.addRow(.{ .Property = p[0], .Value = p[1] });

    if (allUsers(config.scope)) |value| try t.addRow(.{ .Property = "ALLUSERS", .Value = value });
    if (has_main) {
        try t.addRow(.{ .Property = "DESKTOPSHORTCUT", .Value = "1" });
        try t.addRow(.{ .Property = "STARTMENUSHORTCUT", .Value = "1" });
    }
    if (config.icon != null) {
        try t.addRow(.{ .Property = "ARPPRODUCTICON", .Value = icon_name });
        const t_icon = try db.addTable(schema.icon);
        try t_icon.addRow(.{ .Name = icon_name, .Data = icon_name });
    }
}

/// Populates the `Directory`, `Component`, `File`, `Feature`, `FeatureComponents`,
/// `Media`, `Registry`, and `Shortcut` tables for all payload files in `config`.
fn addPayload(db: *Database, config: Config, mfr: []const u8) !void {
    const a = db.allocator;
    const t_dir = try db.addTable(schema.directory);
    const t_comp = try db.addTable(schema.component);
    const t_file = try db.addTable(schema.file);
    const t_feature = try db.addTable(schema.feature);
    const t_feature_comp = try db.addTable(schema.feature_components);
    const t_media = try db.addTable(schema.media);
    const t_reg = try db.addTable(schema.registry);
    const t_shortcut = try db.addTable(schema.shortcut);

    const is_64 = config.arch.is64Bit();
    const prog_files = config.arch.programFilesFolder();
    const install_parent = if (config.scope == .machine)
        prog_files
    else
        "LocalAppDataFolder";
    try t_dir.addRow(.{ .Directory = "TARGETDIR", .DefaultDir = "SourceDir" });
    const std_dirs = [_][]const u8{
        prog_files,
        "LocalAppDataFolder",
        "DesktopFolder",
        "ProgramMenuFolder",
    };
    for (std_dirs) |dir| {
        try t_dir.addRow(.{ .Directory = dir, .Directory_Parent = "TARGETDIR", .DefaultDir = "." });
    }
    try t_dir.addRow(.{
        .Directory = install_folder,
        .Directory_Parent = install_parent,
        .DefaultDir = config.name,
    });

    try t_feature.addRow(.{
        .Feature = main_feature,
        .Title = config.name,
        .Display = 2,
        .Level = 1,
        .Directory_ = install_folder,
        .Attributes = 0,
    });
    try t_media.addRow(.{
        .DiskId = 1,
        .LastSequence = config.files.len,
        .Cabinet = "#cab1.cab",
    });

    // Subdirectories under `INSTALLFOLDER` are registered on demand, keyed by
    // their lowercased relative path so `"lib/x"` and `"LIB/y"` share one row.
    var dirs: std.StringHashMapUnmanaged([]const u8) = .empty;
    const reg_key = try std.fmt.allocPrint(a, "Software\\{s}\\{s}", .{ mfr, config.name });

    for (config.files, 0..) |file, i| {
        const comp = try indexed(a, "cmp", i);
        const file_id = try indexed(a, "fil", i);
        const slash = mem.lastIndexOfScalar(u8, file.target_subpath, '/');
        const subpath = if (slash) |s| file.target_subpath[0..s] else "";
        const dir = try directoryId(a, t_dir, &dirs, subpath);
        const file_name = if (slash) |s| file.target_subpath[s + 1 ..] else file.target_subpath;

        // Components installed into a per-user directory use a Registry key path
        // under HKMU rather than a file path.
        const uses_registry = config.scope != .machine;
        const reg_id = try indexed(a, "reg", i);
        if (uses_registry) {
            try t_reg.addRow(.{
                .Registry = reg_id,
                .Root = hkmu,
                .Key = reg_key,
                .Name = comp,
                .Value = "1",
                .Component_ = comp,
            });
        }

        // Bit 8 (0x0100 / 256) indicates a 64-bit component; bit 2 (0x0004 / 4) indicates
        // that KeyPath references the Registry table instead of the File table.
        const comp_attrs: i32 = (if (is_64) @as(i32, 256) else 0) |
            @as(i32, if (uses_registry) 4 else 0);
        try t_comp.addRow(.{
            .Component = comp,
            .ComponentId = try guid(a, &.{ "Component", config.name, file.target_subpath }),
            .Directory_ = dir,
            .Attributes = comp_attrs,
            .KeyPath = if (uses_registry) reg_id else file_id,
        });
        try t_feature_comp.addRow(.{ .Feature_ = main_feature, .Component_ = comp });
        try t_file.addRow(.{
            .File = file_id,
            .Component_ = comp,
            .FileName = file_name,
            .FileSize = file.content.len,
            // Bit 9 (0x0200 / 512): vital file whose installation failure aborts package install.
            .Attributes = 512,
            .Sequence = i + 1,
        });

        if (file.is_main) {
            const shortcut_items = [_]struct {
                sc_id: []const u8,
                dir_id: []const u8,
                comp_id: []const u8,
                reg_id: []const u8,
                reg_name: []const u8,
                cond: []const u8,
            }{
                .{
                    .sc_id = try std.fmt.allocPrint(a, "sc_desk_{d}", .{i}),
                    .dir_id = "DesktopFolder",
                    .comp_id = try std.fmt.allocPrint(a, "cmp_sc_desk_{d}", .{i}),
                    .reg_id = try std.fmt.allocPrint(a, "reg_sc_desk_{d}", .{i}),
                    .reg_name = "DesktopShortcut",
                    .cond = "DESKTOPSHORTCUT = 1",
                },
                .{
                    .sc_id = try std.fmt.allocPrint(a, "sc_menu_{d}", .{i}),
                    .dir_id = "ProgramMenuFolder",
                    .comp_id = try std.fmt.allocPrint(a, "cmp_sc_menu_{d}", .{i}),
                    .reg_id = try std.fmt.allocPrint(a, "reg_sc_menu_{d}", .{i}),
                    .reg_name = "StartMenuShortcut",
                    .cond = "STARTMENUSHORTCUT = 1",
                },
            };

            for (shortcut_items) |item| {
                try t_reg.addRow(.{
                    .Registry = item.reg_id,
                    .Root = hkmu,
                    .Key = reg_key,
                    .Name = item.reg_name,
                    .Value = "1",
                    .Component_ = item.comp_id,
                });

                const sc_comp_attrs: i32 = (if (is_64) @as(i32, 256) else 0) | 4;
                try t_comp.addRow(.{
                    .Component = item.comp_id,
                    .ComponentId = try guid(a, &.{ "Component", config.name, item.comp_id }),
                    .Directory_ = item.dir_id,
                    .Attributes = sc_comp_attrs,
                    .Condition = item.cond,
                    .KeyPath = item.reg_id,
                });
                try t_feature_comp.addRow(.{
                    .Feature_ = main_feature,
                    .Component_ = item.comp_id,
                });

                try t_shortcut.addRow(.{
                    .Shortcut = item.sc_id,
                    .Directory_ = item.dir_id,
                    .Name = config.name,
                    .Component_ = item.comp_id,
                    .Target = try std.fmt.allocPrint(a, "[#{s}]", .{file_id}),
                    .Description = config.name,
                    .Icon_ = if (config.icon != null) icon_name else null,
                    .IconIndex = if (config.icon != null) @as(?i32, 0) else null,
                    .WkDir = install_folder,
                });
            }
        }
    }
}

/// Resolves the `Directory` table primary key for `path` (a `/`-separated path
/// relative to `INSTALLFOLDER`), recursively creating `Directory` rows for any
/// ancestor subdirectories not yet in `dirs`.
///
/// Lookups in `dirs` are case-insensitive (matching the Windows filesystem) so
/// `"lib/core.dll"` and `"LIB/data.bin"` resolve to the same directory ID.
fn directoryId(
    a: Allocator,
    t_dir: *table.Table,
    dirs: *std.StringHashMapUnmanaged([]const u8),
    path: []const u8,
) ![]const u8 {
    if (path.len == 0) return install_folder;
    const key = try std.ascii.allocLowerString(a, path);
    if (dirs.get(key)) |id| return id;

    const slash = mem.lastIndexOfScalar(u8, path, '/');
    const parent = try directoryId(a, t_dir, dirs, if (slash) |s| path[0..s] else "");
    const id = try indexed(a, "dir", dirs.count());
    try t_dir.addRow(.{
        .Directory = id,
        .Directory_Parent = parent,
        .DefaultDir = if (slash) |s| path[s + 1 ..] else path,
    });
    try dirs.put(a, key, id);
    return id;
}

/// Builds and serializes the `\x05SummaryInformation` OLE property stream for `config`.
fn summaryInformation(a: Allocator, config: Config) ![]u8 {
    const mfr = config.manufacturer orelse config.name;
    var si = summary_info.SummaryInfo.init(a);
    try si.set(.codepage, .{ .int16 = 1252 });
    try si.set(.title, .{ .string = "Installation Database" });
    try si.set(.subject, .{ .string = config.name });
    try si.set(.author, .{ .string = mfr });
    try si.set(.keywords, .{ .string = "Installer" });
    const comment = try std.fmt.allocPrint(
        a,
        "This installer database contains the logic and data required to install {s}.",
        .{config.name},
    );
    try si.set(.comments, .{ .string = comment });
    try si.set(.template, .{ .string = try std.fmt.allocPrint(
        a,
        "{s};1033",
        .{config.arch.templateToken()},
    ) });
    try si.set(.revnumber, .{ .string = try packageCode(a, config) });

    // Convert Unix timestamp (seconds since 1970-01-01) to Windows FILETIME
    // (100-nanosecond intervals since 1601-01-01, offset by 11,644,473,600 seconds).
    const filetime = @as(u64, @intCast(@max(0, config.timestamp +| 11644473600))) *| 10_000_000;
    try si.set(.create_dtm, .{ .filetime = filetime });
    try si.set(.lastsave_dtm, .{ .filetime = filetime });

    // Minimum Windows Installer version: 500 (version 5.0), required for Arm, Arm64,
    // and dual-scope packages.
    try si.set(.pagecount, .{ .int32 = 500 });
    // Summary word count bitmask:
    // - Bit 1 (2): source files are compressed into a cabinet stream.
    // - Bit 3 (8): package is UAC-compliant (no elevation required by default),
    //   preventing forced elevation on per-user and dual-scope installs.
    try si.set(.wordcount, .{ .int32 = if (config.scope == .machine) 2 else 2 | 8 });
    try si.set(.appname, .{ .string = "swim" });
    try si.set(.security, .{ .int32 = 2 }); // 2 indicates read-only recommended
    return si.write(a);
}

/// Computes the deterministic package code GUID for `config`.
///
/// Because Windows Installer treats two `.msi` files with the same package code
/// as byte-identical cached packages, this hash covers every metadata field and
/// every payload file path, role, and content slice.
fn packageCode(a: Allocator, config: Config) ![]const u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    try parts.appendSlice(a, &.{
        "PackageCode",
        config.name,
        config.manufacturer orelse config.name,
        config.version,
        @tagName(config.arch),
        @tagName(config.scope),
        config.license orelse "",
        config.icon orelse "",
    });
    for (config.files) |f| {
        try parts.appendSlice(a, &.{ f.target_subpath, if (f.is_main) "main" else "", f.content });
    }
    return guid(a, parts.items);
}

/// Formats an indexed MSI primary key identifier such as `"fil_0"` or `"cmp_12"`.
fn indexed(a: Allocator, prefix: []const u8, i: usize) ![]const u8 {
    return std.fmt.allocPrint(a, "{s}_{d}", .{ prefix, i });
}

/// Generates a deterministic, uppercase, brace-enclosed UUIDv4 string
/// (`{XXXXXXXX-XXXX-4XXX-YXXX-XXXXXXXXXXXX}`) by hashing `parts` with SHA-256.
///
/// Each element of `parts` is terminated with a `0x00` separator byte in the
/// hash input so tuple boundaries are unambiguous (e.g., `&.{ "ab", "c" }`
/// cannot collide with `&.{ "a", "bc" }`).
fn guid(a: Allocator, parts: []const []const u8) ![]const u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (parts) |part| {
        hasher.update(part);
        hasher.update("\x00");
    }
    var bytes: [16]u8 = hasher.finalResult()[0..16].*;
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // RFC 4122 version 4 nibble
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 4122 variant 1 bits (10xx_xxxx)
    const h = std.fmt.bytesToHex(bytes, .upper);
    return std.fmt.allocPrint(
        a,
        "{{{s}-{s}-{s}-{s}-{s}}}",
        .{ h[0..8], h[8..12], h[12..16], h[16..20], h[20..32] },
    );
}

/// Validates all fields of `config` before building the package, returning a
/// descriptive error tag if any invariant is violated.
fn validate(config: Config) !void {
    try checkLabel(config.name, error.InvalidName);
    // In addition to `checkLabel`'s rules, `config.name` is used as the default
    // install directory name (`Directory.DefaultDir`) and shortcut filename
    // (`Shortcut.Name`), so it must not contain characters forbidden in Windows
    // filenames (`/ : * ? " < > |`).
    if (mem.indexOfAny(u8, config.name, "/:*?\"<>|") != null) return error.InvalidName;
    if (config.manufacturer) |m| try checkLabel(m, error.InvalidManufacturer);
    try checkVersion(config.version);
    if (config.icon) |icon| if (icon.len == 0) return error.InvalidIcon;

    if (config.files.len == 0) return error.NoFiles;
    if (config.files.len > std.math.maxInt(u16)) return error.TooManyFiles;
    var total: usize = 0;
    var mains: usize = 0;
    for (config.files, 0..) |file, i| {
        try checkTargetPath(file.target_subpath);
        total += file.content.len;
        mains += @intFromBool(file.is_main);
        for (config.files[0..i]) |other| {
            if (pathsConflict(other.target_subpath, file.target_subpath)) {
                return error.DuplicateTarget;
            }
        }
    }
    if (mains > 1) return error.TooManyMainFiles;
    if (total > std.math.maxInt(i32)) return error.PackageTooLarge;
}

/// Reports whether two `/`-separated relative install paths `a` and `b` conflict
/// on a case-insensitive Windows filesystem—either because they resolve to the
/// exact same path (e.g., `"app.exe"` vs `"APP.EXE"`) or because one is a file
/// at the same path where the other expects a directory (e.g., `"dir"` vs
/// `"DIR/file.txt"`).
fn pathsConflict(a: []const u8, b: []const u8) bool {
    const short, const long = if (a.len <= b.len) .{ a, b } else .{ b, a };
    return std.ascii.eqlIgnoreCase(short, long[0..short.len]) and
        (short.len == long.len or long[short.len] == '/');
}

/// Validates a product or manufacturer label (`text`), returning `err` if it is
/// empty, exceeds `max_label_len` (64 bytes), or contains characters that would
/// corrupt the generated MSI database.
///
/// Why these specific characters are rejected:
/// - `[` and `]`: Windows Installer evaluates `Registry.Key`, `CustomAction.Target`,
///   and `Control.Text` as `[Formatted]` strings, where `[Foo]` expands the property
///   named `Foo`. Allowing square brackets in a product or manufacturer name would
///   cause unintended property expansion or silent text truncation.
/// - `\`: Both `name` and `manufacturer` are interpolated as single path segments in
///   the Registry key `Software\<manufacturer>\<name>`; a backslash would split the
///   key into unintended subkeys.
/// - `0x00`..`0x1F` and `0x7F`: ASCII control characters are invalid in Windows
///   Registry key names, shortcut titles, and MSI summary strings.
fn checkLabel(text: []const u8, err: anyerror) !void {
    if (text.len == 0 or text.len > max_label_len) return err;
    for (text) |c| {
        if (c < 0x20 or c == 0x7f or c == '\\' or c == '[' or c == ']') return err;
    }
}

/// Validates that `version` is 1 to 4 dot-separated decimal integers within the
/// Windows Installer `ProductVersion` bounds (`255.255.65535.65535`), returning
/// `error.InvalidVersion` otherwise.
fn checkVersion(version: []const u8) !void {
    const limits = [_]u32{ 255, 255, 65535, 65535 };
    var it = mem.splitScalar(u8, version, '.');
    var count: usize = 0;
    while (it.next()) |part| : (count += 1) {
        if (count == limits.len) return error.InvalidVersion;
        const n = std.fmt.parseUnsigned(u32, part, 10) catch return error.InvalidVersion;
        if (n > limits[count]) return error.InvalidVersion;
    }
}

/// Validates a relative destination path (`FileInput.target_subpath`), returning
/// `error.InvalidTargetPath` if any `/`-separated path segment is invalid on
/// Windows or in an MSI `File` / `Directory` table.
///
/// Enforced rules per path segment:
/// - Must be 1..255 bytes ( prohibiting leading, trailing, or consecutive `/`).
/// - Must not be `.` or `..` (preventing directory traversal outside `INSTALLFOLDER`).
/// - Must not contain ASCII control characters (`< 0x20`), Windows reserved
///   filename characters (`\ : * ? " < > |`), or MSI `[Formatted]` delimiters
///   (`[ ]`).
/// - Must not end with a space or period, which the Win32 path normalizer silently
///   strips when creating files and folders.
fn checkTargetPath(path: []const u8) !void {
    var it = mem.splitScalar(u8, path, '/');
    while (it.next()) |part| {
        if (part.len == 0 or part.len > 255 or mem.eql(u8, part, ".") or mem.eql(u8, part, "..")) {
            return error.InvalidTargetPath;
        }
        for (part) |c| {
            if (c < 0x20 or mem.indexOfScalar(u8, "\\:*?\"<>|[]", c) != null) {
                return error.InvalidTargetPath;
            }
        }
        if (part[part.len - 1] == ' ' or part[part.len - 1] == '.') return error.InvalidTargetPath;
    }
}

const testing = std.testing;
const fixtures = @import("fixtures.zig");

fn testFiles() []const FileInput {
    return &.{
        .{ .target_subpath = "app.exe", .content = "MZ-EXE", .is_main = true },
        .{ .target_subpath = "lib/deep/core.dll", .content = "MZ-DLL" },
        .{ .target_subpath = "LIB/data.bin", .content = "DATA" },
    };
}

fn findRow(t: *const table.Table, column: []const u8, value: []const u8) ?[]const table.Value {
    const c = t.columnIndex(column).?;
    for (t.rows.items) |row| {
        if (mem.eql(u8, row[c].string, value)) return row;
    }
    return null;
}

fn propertyValue(db: *const Database, name: []const u8) ?[]const u8 {
    const row = findRow(db.getTable("Property").?, "Property", name) orelse return null;
    return row[1].string;
}

test "guid is deterministic, well formed and sensitive to every part" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const g1 = try guid(a, &.{ "ab", "c" });
    try testing.expectEqual(@as(usize, 38), g1.len);
    try testing.expect(g1[0] == '{' and g1[37] == '}');
    for ([_]usize{ 9, 14, 19, 24 }) |i| try testing.expectEqual(@as(u8, '-'), g1[i]);
    try testing.expectEqual(@as(u8, '4'), g1[15]);
    try testing.expectEqualStrings(g1, try guid(a, &.{ "ab", "c" }));
    try testing.expect(!mem.eql(u8, g1, try guid(a, &.{ "a", "bc" })));
}

test "scopes map to ALLUSERS, install folder and registry key paths" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const cases = [_]struct { Scope, ?[]const u8, []const u8, usize }{
        .{ .machine, "1", "ProgramFiles64Folder", 2 },
        .{ .user, null, "LocalAppDataFolder", 5 },
        .{ .auto, "2", "LocalAppDataFolder", 5 },
    };
    for (cases) |c| {
        const db = try buildDatabase(a, .{ .name = "App", .scope = c[0], .files = testFiles() });
        if (c[1]) |want| {
            try testing.expectEqualStrings(want, propertyValue(&db, "ALLUSERS").?);
        } else try testing.expect(propertyValue(&db, "ALLUSERS") == null);
        const folder = findRow(db.getTable("Directory").?, "Directory", install_folder).?;
        try testing.expectEqualStrings(c[2], folder[1].string);
        try testing.expectEqual(c[3], db.getTable("Registry").?.rows.items.len);
        try testing.expectEqual(c[0] == .auto, db.getTable("CustomAction") != null);
    }
}

test "files, nested directories and shortcuts" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const db = try buildDatabase(a, .{ .name = "App", .icon = "ICO", .files = testFiles() });
    try testing.expectEqual(@as(usize, 3), db.getTable("File").?.rows.items.len);
    // 3 file components + 2 dedicated shortcut components (desktop and start menu).
    try testing.expectEqual(@as(usize, 3 + 2), db.getTable("Component").?.rows.items.len);

    // lib and lib/deep become a two-level chain; lib/data.bin reuses lib.
    const dirs = db.getTable("Directory").?;
    const lib = findRow(dirs, "DefaultDir", "lib").?;
    const deep = findRow(dirs, "DefaultDir", "deep").?;
    try testing.expectEqualStrings(install_folder, lib[1].string);
    try testing.expectEqualStrings(lib[0].string, deep[1].string);
    try testing.expectEqual(@as(usize, 6 + 2), dirs.rows.items.len);

    // Only the main executable gets shortcuts, using dedicated components with conditions.
    const shortcuts = db.getTable("Shortcut").?;
    try testing.expectEqual(@as(usize, 2), shortcuts.rows.items.len);
    try testing.expectEqualStrings("cmp_sc_desk_0", shortcuts.rows.items[0][3].string);
    try testing.expectEqualStrings("cmp_sc_menu_0", shortcuts.rows.items[1][3].string);
    try testing.expectEqualStrings(icon_name, shortcuts.rows.items[0][8].string);
    try testing.expectEqualStrings(icon_name, propertyValue(&db, "ARPPRODUCTICON").?);

    const comp_table = db.getTable("Component").?;
    const desk_comp = findRow(comp_table, "Component", "cmp_sc_desk_0").?;
    const menu_comp = findRow(comp_table, "Component", "cmp_sc_menu_0").?;
    try testing.expectEqualStrings("DESKTOPSHORTCUT = 1", desk_comp[4].string);
    try testing.expectEqualStrings("STARTMENUSHORTCUT = 1", menu_comp[4].string);

    try testing.expectEqualStrings("1", propertyValue(&db, "DESKTOPSHORTCUT").?);
    try testing.expectEqualStrings("1", propertyValue(&db, "STARTMENUSHORTCUT").?);
}

test "target architectures configure template and directory models" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const cases = [_]struct { Arch, []const u8, []const u8, bool }{
        .{ .x64, "x64;1033", "ProgramFiles64Folder", true },
        .{ .arm64, "Arm64;1033", "ProgramFiles64Folder", true },
        .{ .arm, "Arm;1033", "ProgramFilesFolder", false },
        .{ .x86, "Intel;1033", "ProgramFilesFolder", false },
    };
    for (cases) |c| {
        const db = try buildDatabase(a, .{
            .name = "App",
            .arch = c[0],
            .scope = .machine,
            .files = testFiles(),
        });
        const folder = findRow(db.getTable("Directory").?, "Directory", install_folder).?;
        try testing.expectEqualStrings(c[2], folder[1].string);

        const comp_table = db.getTable("Component").?;
        const file_comp = findRow(comp_table, "Component", "cmp_0").?;
        const attrs = file_comp[3].int;
        if (c[3]) {
            try testing.expect((attrs & 256) != 0);
        } else {
            try testing.expect((attrs & 256) == 0);
        }

        const msi = try buildMsi(testing.allocator, .{
            .name = "App",
            .arch = c[0],
            .scope = .machine,
            .files = testFiles(),
        });
        defer testing.allocator.free(msi);

        const reader = cfbf.Reader{ .data = msi };
        const summary_name = std.unicode.utf8ToUtf16LeStringLiteral("\x05SummaryInformation");
        const summary_bytes = (try reader.readStream(a, summary_name)).?;
        const si = try summary_info.SummaryInfo.read(a, summary_bytes);
        try testing.expectEqualStrings(c[1], si.get(.template).?.string);
        try testing.expectEqual(@as(i32, 500), si.get(.pagecount).?.int32);
    }
}

test "valid packages round trip through the compound file" {
    const allocator = testing.allocator;
    const config: Config = .{
        .name = "App",
        .version = "1.2.3",
        .license = "Terms [of] use",
        .icon = "ICO",
        .files = testFiles(),
        .timestamp = 1_700_000_000,
    };

    const first = try buildMsi(allocator, config);
    defer allocator.free(first);
    const second = try buildMsi(allocator, config);
    defer allocator.free(second);
    try testing.expectEqualSlices(u8, first, second);

    var changed = config;
    changed.files = &.{.{ .target_subpath = "app.exe", .content = "other", .is_main = true }};
    const third = try buildMsi(allocator, changed);
    defer allocator.free(third);
    try testing.expect(!mem.eql(u8, first, third));

    const reader = cfbf.Reader{ .data = first };
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_][]const u8{ "cab1.cab", "Icon.ProductIcon.ico" }) |name| {
        const encoded = try stream_name.encode(a, name, false);
        try testing.expect(try reader.readStream(a, encoded) != null);
    }
    const table_names = [_][]const u8{
        "_Tables",
        "_Columns",
        "_StringPool",
        "_StringData",
        "Property",
        "File",
        "Control",
    };
    for (table_names) |name| {
        const encoded = try stream_name.encode(a, name, true);
        try testing.expect(try reader.readStream(a, encoded) != null);
    }
    const summary_name = std.unicode.utf8ToUtf16LeStringLiteral("\x05SummaryInformation");
    const summary = (try reader.readStream(a, summary_name)).?;
    const si = try summary_info.SummaryInfo.read(a, summary);
    try testing.expectEqualStrings("App", si.get(.subject).?.string);
    try testing.expectEqual(@as(i32, 10), si.get(.wordcount).?.int32);
}

test "invalid configurations are rejected" {
    const allocator = testing.allocator;
    const files = testFiles();
    const bad = [_]struct { Config, anyerror }{
        .{ .{ .name = "", .files = files }, error.InvalidName },
        .{ .{ .name = "A/B", .files = files }, error.InvalidName },
        .{ .{ .name = "A[1]", .files = files }, error.InvalidName },
        .{ .{ .name = &@as([65]u8, @splat('A')), .files = files }, error.InvalidName },
        .{
            .{ .name = "App", .manufacturer = "Bad\\Name", .files = files },
            error.InvalidManufacturer,
        },
        .{ .{ .name = "App", .version = "1.x", .files = files }, error.InvalidVersion },
        .{ .{ .name = "App", .version = "256.0", .files = files }, error.InvalidVersion },
        .{ .{ .name = "App", .version = "1.2.3.4.5", .files = files }, error.InvalidVersion },
        .{ .{ .name = "App", .files = &.{} }, error.NoFiles },
        .{
            .{ .name = "App", .files = &.{.{ .target_subpath = "../x", .content = "" }} },
            error.InvalidTargetPath,
        },
        .{
            .{ .name = "App", .files = &.{.{ .target_subpath = "/abs", .content = "" }} },
            error.InvalidTargetPath,
        },
        .{
            .{ .name = "App", .files = &.{.{ .target_subpath = "a\\b", .content = "" }} },
            error.InvalidTargetPath,
        },
        .{
            .{ .name = "App", .files = &.{.{ .target_subpath = "a//b", .content = "" }} },
            error.InvalidTargetPath,
        },
        .{ .{ .name = "App", .icon = "", .files = files }, error.InvalidIcon },
        .{
            .{ .name = "App", .files = &.{
                .{ .target_subpath = "x", .content = "" },
                .{ .target_subpath = "X", .content = "" },
            } },
            error.DuplicateTarget,
        },
        .{
            .{ .name = "App", .files = &.{
                .{ .target_subpath = "dir", .content = "" },
                .{ .target_subpath = "DIR/file.txt", .content = "" },
            } },
            error.DuplicateTarget,
        },
        .{
            .{ .name = "App", .files = &.{
                .{ .target_subpath = "x", .content = "", .is_main = true },
                .{ .target_subpath = "y", .content = "", .is_main = true },
            } },
            error.TooManyMainFiles,
        },
    };
    for (bad) |case| try testing.expectError(case[1], buildMsi(allocator, case[0]));
}

test "signing rule 1: unsigned installer rejects signed PE payload" {
    const exe = try fixtures.read("mock.exe");
    defer testing.allocator.free(exe);
    var creds = try fixtures.Credentials.load("leaf_g3c_us");
    defer creds.deinit();

    const signed_exe = try creds.signPe(exe, .sha256);
    defer testing.allocator.free(signed_exe);

    try testing.expectError(error.UnsignedInstallerWithSignedPayload, buildMsi(testing.allocator, .{
        .name = "TestApp",
        .files = &.{.{ .target_subpath = "mock.exe", .content = signed_exe, .is_main = true }},
    }));
}

test "signing rule 2: signed installer rejects certificate mismatch" {
    const exe = try fixtures.read("mock.exe");
    defer testing.allocator.free(exe);
    var payload_creds = try fixtures.Credentials.load("leaf_g3b_nl");
    defer payload_creds.deinit();
    var installer_creds = try fixtures.Credentials.load("leaf_g3c_us");
    defer installer_creds.deinit();

    const signed_exe = try payload_creds.signPe(exe, .sha256);
    defer testing.allocator.free(signed_exe);

    try testing.expectError(error.CertificateMismatch, buildMsi(testing.allocator, .{
        .name = "TestApp",
        .files = &.{.{ .target_subpath = "mock.exe", .content = signed_exe, .is_main = true }},
        .signing = .{
            .cert_bytes = installer_creds.cert_pem,
            .key_bytes = installer_creds.key_pem,
        },
    }));
}

test "signing rejects a private key that does not match the certificate" {
    var creds = try fixtures.Credentials.load("leaf_g3c_us");
    defer creds.deinit();
    var other = try fixtures.Credentials.load("leaf_g3b_nl");
    defer other.deinit();

    try testing.expectError(error.KeyCertificateMismatch, buildMsi(testing.allocator, .{
        .name = "TestApp",
        .files = testFiles(),
        .signing = .{ .cert_bytes = creds.cert_pem, .key_bytes = other.key_pem },
    }));
}

test "signing rules 3, 4, 5: auto-sign unsigned PE and verify end-to-end" {
    const allocator = testing.allocator;
    const exe = try fixtures.read("mock.exe");
    defer allocator.free(exe);
    const dll = try fixtures.read("mock.dll");
    defer allocator.free(dll);
    const chain_pem = try fixtures.read("certs/codesign_ca_g3c_us.pem");
    defer allocator.free(chain_pem);
    var creds = try fixtures.Credentials.load("leaf_g3c_us");
    defer creds.deinit();

    // Rule 3 (unsigned PE files are auto-signed) and rule 5 (non-PE files pass
    // through), with the intermediate CA embedded in SignedData.certificates.
    const msi_bytes = try buildMsi(allocator, .{
        .name = "SignedApp",
        .files = &.{
            .{ .target_subpath = "mock.exe", .content = exe, .is_main = true },
            .{ .target_subpath = "bin/mock.dll", .content = dll },
            .{ .target_subpath = "readme.txt", .content = "Documentation text file" },
        },
        .timestamp = 1700000000,
        .signing = .{
            .cert_bytes = creds.cert_pem,
            .key_bytes = creds.key_pem,
            .chain_bytes = &.{chain_pem},
            .description = "Signed App Suite",
        },
    });
    defer allocator.free(msi_bytes);

    var msi_verify = try authenticode.verify.verifyMsi(allocator, msi_bytes, creds.cert);
    defer msi_verify.deinit(allocator);
    try testing.expectEqual(authenticode.msi.HashAlgorithm.sha256, msi_verify.digest_algorithm);

    // Rule 4: a payload pre-signed with the installer certificate is accepted as-is.
    const pre_signed_exe = try creds.signPe(exe, .sha384);
    defer allocator.free(pre_signed_exe);

    const msi2_bytes = try buildMsi(allocator, .{
        .name = "SignedApp",
        .files = &.{
            .{ .target_subpath = "mock.exe", .content = pre_signed_exe, .is_main = true },
        },
        .timestamp = 1700000000,
        .signing = .{
            .cert_bytes = creds.cert_pem,
            .key_bytes = creds.key_pem,
            .chain_bytes = &.{chain_pem},
            .hash_algorithm = .sha384,
        },
    });
    defer allocator.free(msi2_bytes);

    var msi2_verify = try authenticode.verify.verifyMsi(allocator, msi2_bytes, creds.cert);
    defer msi2_verify.deinit(allocator);
    try testing.expectEqual(authenticode.msi.HashAlgorithm.sha384, msi2_verify.digest_algorithm);
}
