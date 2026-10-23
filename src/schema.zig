//! Standard Windows Installer table schemas and standard action sequences.
//!
//! Column names, widths, nullability, and localization flags match the official
//! Windows Installer schema so that packages pass `msival2` / ICE validation and
//! execute cleanly under `msiexec`.

const table = @import("table.zig");
const str = table.str;
const int = table.int;
const binary = table.binary;
const TableDef = table.TableDef;

/// Global installer properties (`ProductName`, `ProductCode`, `ALLUSERS`, etc.).
pub const property: TableDef = .{ .name = "Property", .columns = &.{
    str("Property", 72).key(),
    str("Value", 0).localizable(),
} };

/// Directory hierarchy mapping logical directory IDs (`TARGETDIR`, `INSTALLFOLDER`,
/// etc.) to parent directories and on-disk folder names.
pub const directory: TableDef = .{ .name = "Directory", .columns = &.{
    str("Directory", 72).key(),
    str("Directory_Parent", 72).nullable(),
    str("DefaultDir", 255).localizable(),
} };

/// Atomic installation units (`Component` table), each tracking a single file or
/// registry key path under a target `Directory_`.
pub const component: TableDef = .{ .name = "Component", .columns = &.{
    str("Component", 72).key(),
    str("ComponentId", 38).nullable(),
    str("Directory_", 72),
    int("Attributes", 2),
    str("Condition", 255).nullable(),
    str("KeyPath", 72).nullable(),
} };

/// Payload files installed by components (`File` table), ordered by their 1-based
/// position (`Sequence`) inside the cabinet archive.
pub const file: TableDef = .{ .name = "File", .columns = &.{
    str("File", 72).key(),
    str("Component_", 72),
    str("FileName", 255).localizable(),
    int("FileSize", 4),
    str("Version", 72).nullable(),
    str("Language", 20).nullable(),
    int("Attributes", 2).nullable(),
    int("Sequence", 4),
} };

/// User-selectable installation features (`Feature` table). `swim` packages place
/// all components into a single top-level `MainFeature`.
pub const feature: TableDef = .{ .name = "Feature", .columns = &.{
    str("Feature", 38).key(),
    str("Feature_Parent", 38).nullable(),
    str("Title", 64).localizable().nullable(),
    str("Description", 255).localizable().nullable(),
    int("Display", 2).nullable(),
    int("Level", 2),
    str("Directory_", 72).nullable(),
    int("Attributes", 2),
} };

/// Many-to-many join table linking `Feature` rows to their constituent `Component` rows.
pub const feature_components: TableDef = .{ .name = "FeatureComponents", .columns = &.{
    str("Feature_", 38).key(),
    str("Component_", 72).key(),
} };

/// Source media / cabinet descriptors (`Media` table). Prefixing `Cabinet` with `#`
/// (e.g., `"#cab1.cab"`) instructs Windows Installer to read the cabinet from an
/// embedded stream inside the `.msi` compound file rather than an external disk file.
pub const media: TableDef = .{ .name = "Media", .columns = &.{
    int("DiskId", 2).key(),
    int("LastSequence", 4),
    str("DiskPrompt", 64).localizable().nullable(),
    str("Cabinet", 255).nullable(),
    str("VolumeLabel", 32).nullable(),
    str("Source", 72).nullable(),
} };

/// Shell `.lnk` shortcuts (`Shortcut` table) created on the Desktop or Start Menu.
pub const shortcut: TableDef = .{ .name = "Shortcut", .columns = &.{
    str("Shortcut", 72).key(),
    str("Directory_", 72),
    str("Name", 128).localizable(),
    str("Component_", 72),
    str("Target", 72),
    str("Arguments", 255).nullable(),
    str("Description", 255).localizable().nullable(),
    int("Hotkey", 2).nullable(),
    str("Icon_", 72).nullable(),
    int("IconIndex", 2).nullable(),
    int("ShowCmd", 2).nullable(),
    str("WkDir", 72).nullable(),
    str("DisplayResourceDLL", 255).nullable(),
    int("DisplayResourceId", 4).nullable(),
    str("DescriptionResourceDLL", 255).nullable(),
    int("DescriptionResourceId", 4).nullable(),
} };

/// Icon binary streams (`Icon` table) referenced by `Shortcut.Icon_` and the
/// `ARPPRODUCTICON` Add/Remove Programs property. Each row's payload is stored in
/// a compound-file stream named `Icon.<Name>`.
pub const icon: TableDef = .{ .name = "Icon", .columns = &.{
    str("Name", 72).key(),
    binary("Data"),
} };

/// Registry values written during installation (`Registry` table). Used to provide
/// per-user/dual-scope components with a valid `HKMU` registry `KeyPath`.
pub const registry: TableDef = .{ .name = "Registry", .columns = &.{
    str("Registry", 72).key(),
    int("Root", 2),
    str("Key", 255).localizable(),
    str("Name", 255).localizable().nullable(),
    str("Value", 0).localizable().nullable(),
    str("Component_", 72),
} };

/// Custom actions (`CustomAction` table), such as Type 51 property-assignment
/// actions used by `Scope.auto` to switch `INSTALLFOLDER` between Program Files
/// and `%LocalAppData%`.
pub const custom_action: TableDef = .{ .name = "CustomAction", .columns = &.{
    str("Action", 72).key(),
    int("Type", 2),
    str("Source", 72).nullable(),
    str("Target", 255).nullable(),
} };

/// Modal and modeless wizard windows (`Dialog` table).
pub const dialog: TableDef = .{ .name = "Dialog", .columns = &.{
    str("Dialog", 72).key(),
    int("HCentering", 2),
    int("VCentering", 2),
    int("Width", 2),
    int("Height", 2),
    int("Attributes", 4).nullable(),
    str("Title", 128).localizable().nullable(),
    str("Control_First", 50),
    str("Control_Default", 50).nullable(),
    str("Control_Cancel", 50).nullable(),
} };

/// UI widgets (`PushButton`, `Text`, `ScrollableText`, `CheckBox`, `ProgressBar`)
/// belonging to a `Dialog` (`Control` table).
pub const control: TableDef = .{ .name = "Control", .columns = &.{
    str("Dialog_", 72).key(),
    str("Control", 50).key(),
    str("Type", 20),
    int("X", 2),
    int("Y", 2),
    int("Width", 2),
    int("Height", 2),
    int("Attributes", 4).nullable(),
    str("Property", 50).nullable(),
    str("Text", 0).localizable().nullable(),
    str("Control_Next", 50).nullable(),
    str("Help", 255).localizable().nullable(),
} };

/// Checked value mapping for dialog checkbox controls (`CheckBox` table).
pub const check_box: TableDef = .{ .name = "CheckBox", .columns = &.{
    str("Property", 72).key(),
    str("Value", 64).nullable(),
} };

/// Actions triggered when the user activates a dialog control (`ControlEvent` table).
pub const control_event: TableDef = .{ .name = "ControlEvent", .columns = &.{
    str("Dialog_", 72).key(),
    str("Control_", 50).key(),
    str("Event", 50).key(),
    str("Argument", 255).key(),
    str("Condition", 255).key().nullable(),
    int("Ordering", 2).nullable(),
} };

/// Conditional state changes (`Enable`, `Disable`, `Show`, `Hide`) applied to dialog
/// controls whenever installer properties change (`ControlCondition` table).
pub const control_condition: TableDef = .{ .name = "ControlCondition", .columns = &.{
    str("Dialog_", 72).key(),
    str("Control_", 50).key(),
    str("Action", 50).key(),
    str("Condition", 255).key(),
} };

/// Subscriptions that bind a dialog control attribute (such as a progress bar's
/// position or status label) to engine events emitted during installation
/// (`EventMapping` table).
pub const event_mapping: TableDef = .{ .name = "EventMapping", .columns = &.{
    str("Dialog_", 72).key(),
    str("Control_", 50).key(),
    str("Event", 50).key(),
    str("Attribute", 50),
} };

/// Named font styles (`TextStyle` table) referenced via `{\StyleName}` prefixes in
/// `Control.Text` strings.
pub const text_style: TableDef = .{ .name = "TextStyle", .columns = &.{
    str("TextStyle", 72).key(),
    str("FaceName", 32),
    int("Size", 2),
    int("Color", 4).nullable(),
    int("StyleBits", 2).nullable(),
} };

/// Returns the `TableDef` shared by all four Windows Installer action sequence
/// tables (`InstallUISequence`, `InstallExecuteSequence`, `AdminExecuteSequence`,
/// and `AdvtExecuteSequence`).
pub fn sequence(comptime name: []const u8) TableDef {
    return .{ .name = name, .columns = &.{
        str("Action", 72).key(),
        str("Condition", 255).nullable(),
        int("Sequence", 2).nullable(),
    } };
}

/// Pair of `(ActionName, SequenceNumber)` in an execution or UI sequence table.
pub const Step = struct { []const u8, i32 };

/// Standard costing actions run at the start of `InstallUISequence` before
/// displaying the welcome or maintenance dialog.
pub const install_ui_steps = [_]Step{
    .{ "CostInitialize", 800 },
    .{ "FileCost", 900 },
    .{ "CostFinalize", 1000 },
};

/// Standard actions run during `InstallExecuteSequence` to validate, remove old
/// resources, copy files, create shortcuts/registry keys, and register the product.
pub const install_execute_steps = [_]Step{
    .{ "ValidateProductID", 700 },
    .{ "CostInitialize", 800 },
    .{ "FileCost", 900 },
    .{ "CostFinalize", 1000 },
    .{ "InstallValidate", 1400 },
    .{ "InstallInitialize", 1500 },
    .{ "ProcessComponents", 1600 },
    .{ "UnpublishFeatures", 1800 },
    .{ "RemoveRegistryValues", 2600 },
    .{ "RemoveShortcuts", 3200 },
    .{ "RemoveFiles", 3500 },
    .{ "CreateFolders", 3700 },
    .{ "InstallFiles", 4000 },
    .{ "CreateShortcuts", 4500 },
    .{ "WriteRegistryValues", 5000 },
    .{ "RegisterUser", 6000 },
    .{ "RegisterProduct", 6100 },
    .{ "PublishFeatures", 6300 },
    .{ "PublishProduct", 6400 },
    .{ "InstallFinalize", 6600 },
};

/// Standard actions for administrative installs (`msiexec /a` via `AdminExecuteSequence`).
pub const admin_execute_steps = [_]Step{
    .{ "CostInitialize", 800 },
    .{ "FileCost", 900 },
    .{ "CostFinalize", 1000 },
    .{ "InstallInitialize", 1500 },
    .{ "InstallAdminPackage", 3900 },
    .{ "InstallFiles", 4000 },
    .{ "InstallFinalize", 6600 },
};

/// Standard actions for advertisement (`msiexec /j` via `AdvtExecuteSequence`).
pub const advt_execute_steps = [_]Step{
    .{ "CostInitialize", 800 },
    .{ "CostFinalize", 1000 },
    .{ "InstallInitialize", 1500 },
    .{ "CreateShortcuts", 4500 },
    .{ "PublishComponents", 6200 },
    .{ "PublishFeatures", 6300 },
    .{ "PublishProduct", 6400 },
    .{ "InstallFinalize", 6600 },
};

/// Creates the sequence table `name` in `db`, populates it with the unconditional
/// standard `steps`, and returns the table so the caller can append custom or
/// dialog actions.
pub fn addSequence(
    db: *table.Database,
    comptime name: []const u8,
    steps: []const Step,
) !*table.Table {
    const t = try db.addTable(comptime sequence(name));
    for (steps) |step| try t.addRow(.{ .Action = step[0], .Sequence = step[1] });
    return t;
}

test "standard sequences are sorted and unique" {
    const std = @import("std");
    inline for (.{
        install_ui_steps,
        install_execute_steps,
        admin_execute_steps,
        advt_execute_steps,
    }) |steps| {
        var prev: i32 = 0;
        for (steps) |step| {
            try std.testing.expect(step[1] > prev);
            prev = step[1];
        }
    }
}
