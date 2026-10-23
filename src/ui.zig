//! Built-in Windows Installer user interface wizard (`Dialog`, `Control`,
//! `ControlEvent`, `ControlCondition`, `EventMapping`, and `TextStyle` tables).
//!
//! Wizard flow:
//! - First-time install (`NOT Installed`): displays either `WelcomeDlg` or
//!   `WelcomeEulaDlg` (when a license agreement is configured, keeping `Install`
//!   disabled until the acceptance checkbox is ticked).
//! - Maintenance (`Installed`): displays `MaintenanceDlg` with `Repair` and
//!   `Uninstall` actions.
//! - Execution & completion: displays a modeless `ProgressDlg` while
//!   `ExecuteAction` runs `InstallExecuteSequence`, followed by `ExitDialog` on
//!   success (`-1`), `UserExit` on cancellation (`-2`), or `FatalError` on error
//!   (`-3`).

const std = @import("std");
const fmt = std.fmt;
const Allocator = std.mem.Allocator;

const table = @import("table.zig");
const schema = @import("schema.zig");

const Database = table.Database;

/// Dialog and control attribute bitflags:
/// - `0x00001`: visible
/// - `0x00002`: enabled (for controls) or modal (for dialogs); combined as `3`
/// - `0x00004`: sunken 3D border; combined with visible and enabled as `7`
/// - `0x10000`: transparent background (for text) or chunked progress blocks
const visible_enabled = 3;
const transparent_text = 0x10003;
const sunken_text = 7;
const progress_blocks = 0x10001;

/// Font style tags referencing rows in the `TextStyle` table.
const title_style = "{\\DefaultUI_Font_Title}";
const big_style = "{\\DefaultUI_Font_Bigger}";

/// Specification of a single UI widget inside a `Dialog`.
const Control = struct {
    name: []const u8,
    kind: []const u8,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    attributes: i32 = visible_enabled,
    property: ?[]const u8 = null,
    text: ?[]const u8 = null,
};

/// Specification of an installer wizard dialog window.
///
/// `controls` are linked into a circular tab-order chain (`Control.Control_Next`)
/// in the exact order they appear in the slice.
const Dialog = struct {
    name: []const u8,
    /// Name of the control that receives initial keyboard focus (`Control_First`).
    first: []const u8,
    /// Name of the default push button activated by Enter (`Control_Default`).
    default: ?[]const u8,
    /// Name of the push button activated by Escape or the window close button (`Control_Cancel`).
    cancel: ?[]const u8,
    attributes: i32 = visible_enabled,
    controls: []const Control,
};

/// Specification of a `ControlEvent` row binding a control activation to an installer event.
const Event = struct {
    dialog: []const u8,
    control: []const u8,
    event: []const u8,
    argument: []const u8,
    ordering: i32 = 1,
};

/// Creates a transparent title `Text` control named `"Title"`.
fn heading(x: i32, y: i32, w: i32, h: i32, text: []const u8) Control {
    return .{
        .name = "Title",
        .kind = "Text",
        .x = x,
        .y = y,
        .width = w,
        .height = h,
        .attributes = transparent_text,
        .text = text,
    };
}

/// Creates a standard static `Text` control.
fn label(name: []const u8, x: i32, y: i32, w: i32, h: i32, text: ?[]const u8) Control {
    return .{ .name = name, .kind = "Text", .x = x, .y = y, .width = w, .height = h, .text = text };
}

/// Creates a standard 65x17 wizard navigation `PushButton` (e.g., `Install`,
/// `Cancel`, `Finish`).
fn button(name: []const u8, x: i32, y: i32, text: []const u8) Control {
    return .{
        .name = name,
        .kind = "PushButton",
        .x = x,
        .y = y,
        .width = 65,
        .height = 17,
        .text = text,
    };
}

/// Creates a wider 80x24 action `PushButton` used on `MaintenanceDlg` for `Repair`
/// and `Uninstall`.
fn bigButton(name: []const u8, y: i32, text: []const u8) Control {
    return .{
        .name = name,
        .kind = "PushButton",
        .x = 30,
        .y = y,
        .width = 80,
        .height = 24,
        .text = text,
    };
}

/// Populates `db` with the wizard UI tables (`Dialog`, `Control`, `ControlEvent`,
/// `ControlCondition`, `EventMapping`, `TextStyle`, `CheckBox`, and `InstallUISequence`) and
/// returns the `InstallUISequence` table so the caller can schedule additional
/// custom actions.
pub fn addWizard(
    db: *Database,
    app_name: []const u8,
    license: ?[]const u8,
    has_main: bool,
) !*table.Table {
    const a = db.allocator;
    const t_dialog = try db.addTable(schema.dialog);
    const t_control = try db.addTable(schema.control);
    const t_event = try db.addTable(schema.control_event);
    const dialog_title = try fmt.allocPrint(a, "{s} Setup", .{app_name});

    const ui_seq = try schema.addSequence(db, "InstallUISequence", &schema.install_ui_steps);

    const welcome = if (license) |text|
        try licenseDialog(a, app_name, text, has_main)
    else
        try welcomeDialog(a, app_name, has_main);
    const dialogs = [_]Dialog{
        welcome,
        try maintenanceDialog(a, app_name),
        try progressDialog(a, app_name),
        try endDialog(
            a,
            app_name,
            "ExitDialog",
            "Completed Setup",
            "Click Finish to exit the {s} Setup Wizard.",
        ),
        try endDialog(
            a,
            app_name,
            "FatalError",
            "Setup Ended Prematurely",
            "{s} setup ended prematurely because of an error. Your system has not been modified.",
        ),
        try endDialog(
            a,
            app_name,
            "UserExit",
            "Setup Wizard Cancelled",
            "{s} setup wizard was cancelled. Your system has not been modified.",
        ),
    };
    for (dialogs) |d| {
        try t_dialog.addRow(.{
            .Dialog = d.name,
            .HCentering = 50,
            .VCentering = 50,
            .Width = 370,
            .Height = 270,
            .Attributes = d.attributes,
            .Title = dialog_title,
            .Control_First = d.first,
            .Control_Default = d.default,
            .Control_Cancel = d.cancel,
        });
        for (d.controls, 0..) |c, i| {
            try t_control.addRow(.{
                .Dialog_ = d.name,
                .Control = c.name,
                .Type = c.kind,
                .X = c.x,
                .Y = c.y,
                .Width = c.width,
                .Height = c.height,
                .Attributes = c.attributes,
                .Property = c.property,
                .Text = c.text,
                .Control_Next = d.controls[(i + 1) % d.controls.len].name,
            });
        }
    }

    const t_checkbox = try db.addTable(schema.check_box);
    if (license != null) {
        try t_checkbox.addRow(.{ .Property = "LicenseAccepted", .Value = "1" });
    }
    if (has_main) {
        try t_checkbox.addRow(.{ .Property = "DESKTOPSHORTCUT", .Value = "1" });
        try t_checkbox.addRow(.{ .Property = "STARTMENUSHORTCUT", .Value = "1" });
    }

    const ev = struct {
        fn init(
            dialog: []const u8,
            control: []const u8,
            event: []const u8,
            argument: []const u8,
            ordering: i32,
        ) Event {
            return .{
                .dialog = dialog,
                .control = control,
                .event = event,
                .argument = argument,
                .ordering = ordering,
            };
        }
    }.init;
    const events = [_]Event{
        ev(welcome.name, "Install", "EndDialog", "Return", 1),
        ev(welcome.name, "Cancel", "EndDialog", "Exit", 1),

        ev("MaintenanceDlg", "Repair", "[REINSTALL]", "ALL", 1),
        ev("MaintenanceDlg", "Repair", "Reinstall", "ALL", 2),
        ev("MaintenanceDlg", "Repair", "[REINSTALLMODE]", "omus", 3),
        ev("MaintenanceDlg", "Repair", "ReinstallMode", "omus", 4),
        ev("MaintenanceDlg", "Repair", "EndDialog", "Return", 5),
        ev("MaintenanceDlg", "Uninstall", "[REMOVE]", "ALL", 1),
        ev("MaintenanceDlg", "Uninstall", "Remove", "ALL", 2),
        ev("MaintenanceDlg", "Uninstall", "EndDialog", "Return", 3),
        ev("MaintenanceDlg", "Cancel", "EndDialog", "Exit", 1),

        ev("ProgressDlg", "Cancel", "EndDialog", "Exit", 1),
        ev("ExitDialog", "Finish", "EndDialog", "Return", 1),
        ev("FatalError", "Finish", "EndDialog", "Exit", 1),
        ev("UserExit", "Finish", "EndDialog", "Exit", 1),
    };
    for (events) |e| {
        try t_event.addRow(.{
            .Dialog_ = e.dialog,
            .Control_ = e.control,
            .Event = e.event,
            .Argument = e.argument,
            .Condition = "1",
            .Ordering = e.ordering,
        });
    }

    if (license != null) {
        const t_condition = try db.addTable(schema.control_condition);
        try t_condition.addRow(.{
            .Dialog_ = welcome.name,
            .Control_ = "Install",
            .Action = "Disable",
            .Condition = "LicenseAccepted <> \"1\"",
        });
        try t_condition.addRow(.{
            .Dialog_ = welcome.name,
            .Control_ = "Install",
            .Action = "Enable",
            .Condition = "LicenseAccepted = \"1\"",
        });
    }

    const t_mapping = try db.addTable(schema.event_mapping);
    try t_mapping.addRow(.{
        .Dialog_ = "ProgressDlg",
        .Control_ = "ActionText",
        .Event = "ActionText",
        .Attribute = "Text",
    });
    try t_mapping.addRow(.{
        .Dialog_ = "ProgressDlg",
        .Control_ = "ProgressBar",
        .Event = "SetProgress",
        .Attribute = "Progress",
    });

    const t_style = try db.addTable(schema.text_style);
    const styles = [_]struct { []const u8, i32, i32 }{
        .{ "DefaultUI_Font", 8, 0 },
        .{ "DefaultUI_Font_Bigger", 12, 1 },
        .{ "DefaultUI_Font_Title", 10, 1 },
    };
    for (styles) |st| {
        try t_style.addRow(.{
            .TextStyle = st[0],
            .FaceName = "Tahoma",
            .Size = st[1],
            .StyleBits = st[2],
        });
    }

    // `InstallUISequence` scheduling:
    // - Positive sequence numbers run in ascending order: `MaintenanceDlg` (1296)
    //   runs only when the product is already installed (`Installed`), whereas
    //   the welcome dialog (1298) runs only on fresh installs (`NOT Installed`).
    //   `ProgressDlg` (1299) is modeless and stays on screen while `ExecuteAction`
    //   (1300) invokes `InstallExecuteSequence`.
    // - Special negative sequence numbers defined by Windows Installer specify
    //   the terminal dialog shown when installation finishes: `-1` on normal
    //   completion, `-2` when cancelled by the user, and `-3` on fatal error.
    const Seq = struct { []const u8, ?[]const u8, i32 };
    const wizard_steps = [_]Seq{
        .{ "MaintenanceDlg", "Installed", 1296 },
        .{ welcome.name, "NOT Installed", 1298 },
        .{ "ProgressDlg", null, 1299 },
        .{ "ExecuteAction", null, 1300 },
        .{ "ExitDialog", null, -1 },
        .{ "UserExit", null, -2 },
        .{ "FatalError", null, -3 },
    };
    for (wizard_steps) |s| {
        try ui_seq.addRow(.{ .Action = s[0], .Condition = s[1], .Sequence = s[2] });
    }
    return ui_seq;
}

/// Builds `WelcomeEulaDlg`, displaying the license agreement in a scrollable RTF
/// box and keeping the `Install` button initially disabled (`attributes = 1`,
/// visible without enabled) until `LicenseAcceptedCheckBox` sets `LicenseAccepted = "1"`.
/// When `has_main` is true, also provides checkboxes to opt out of desktop and
/// start menu shortcuts.
fn licenseDialog(
    a: Allocator,
    app_name: []const u8,
    license: []const u8,
    has_main: bool,
) !Dialog {
    const rtf = try toRtf(a, license);
    const title = try fmt.allocPrint(
        a,
        "{s}Please review the {s} License Agreement",
        .{ title_style, app_name },
    );
    var controls: std.ArrayList(Control) = .empty;
    try controls.append(a, heading(15, 10, 340, 20, title));
    if (has_main) {
        try controls.append(a, .{
            .name = "LicenseText",
            .kind = "ScrollableText",
            .x = 15,
            .y = 32,
            .width = 340,
            .height = 120,
            .attributes = sunken_text,
            .text = rtf,
        });
        try controls.append(a, .{
            .name = "LicenseAcceptedCheckBox",
            .kind = "CheckBox",
            .x = 15,
            .y = 158,
            .width = 340,
            .height = 18,
            .property = "LicenseAccepted",
            .text = "I accept the terms in the License Agreement",
        });
        try controls.append(a, .{
            .name = "DesktopShortcutCheckBox",
            .kind = "CheckBox",
            .x = 15,
            .y = 180,
            .width = 340,
            .height = 18,
            .property = "DESKTOPSHORTCUT",
            .text = "Create a shortcut on the &Desktop",
        });
        try controls.append(a, .{
            .name = "StartMenuShortcutCheckBox",
            .kind = "CheckBox",
            .x = 15,
            .y = 202,
            .width = 340,
            .height = 18,
            .property = "STARTMENUSHORTCUT",
            .text = "Create a shortcut in the &Start Menu",
        });
    } else {
        try controls.append(a, .{
            .name = "LicenseText",
            .kind = "ScrollableText",
            .x = 15,
            .y = 35,
            .width = 340,
            .height = 165,
            .attributes = sunken_text,
            .text = rtf,
        });
        try controls.append(a, .{
            .name = "LicenseAcceptedCheckBox",
            .kind = "CheckBox",
            .x = 15,
            .y = 205,
            .width = 340,
            .height = 18,
            .property = "LicenseAccepted",
            .text = "I accept the terms in the License Agreement",
        });
    }
    try controls.append(a, .{
        .name = "Install",
        .kind = "PushButton",
        .x = 220,
        .y = 235,
        .width = 65,
        .height = 17,
        // Visible (1) but initially disabled; enabled via ControlCondition.
        .attributes = 1,
        .text = "Install",
    });
    try controls.append(a, button("Cancel", 295, 235, "Cancel"));

    return .{
        .name = "WelcomeEulaDlg",
        .first = "LicenseAcceptedCheckBox",
        .default = "Install",
        .cancel = "Cancel",
        .controls = try controls.toOwnedSlice(a),
    };
}

/// Builds `WelcomeDlg` for packages that do not specify a license agreement.
/// When `has_main` is true, also provides checkboxes to opt out of desktop and
/// start menu shortcuts.
fn welcomeDialog(a: Allocator, app_name: []const u8, has_main: bool) !Dialog {
    const title = try fmt.allocPrint(
        a,
        "{s}Welcome to the {s} Setup Wizard",
        .{ title_style, app_name },
    );
    const desc = try fmt.allocPrint(
        a,
        "The Setup Wizard will install {s} on your computer.\n\n" ++
            "Click Install to continue, or Cancel to exit the wizard.",
        .{app_name},
    );
    var controls: std.ArrayList(Control) = .empty;
    try controls.append(a, heading(15, 20, 340, 30, title));
    try controls.append(a, label("Description", 15, 60, 340, 50, desc));
    if (has_main) {
        try controls.append(a, .{
            .name = "DesktopShortcutCheckBox",
            .kind = "CheckBox",
            .x = 15,
            .y = 125,
            .width = 340,
            .height = 18,
            .property = "DESKTOPSHORTCUT",
            .text = "Create a shortcut on the &Desktop",
        });
        try controls.append(a, .{
            .name = "StartMenuShortcutCheckBox",
            .kind = "CheckBox",
            .x = 15,
            .y = 148,
            .width = 340,
            .height = 18,
            .property = "STARTMENUSHORTCUT",
            .text = "Create a shortcut in the &Start Menu",
        });
    }
    try controls.append(a, button("Install", 220, 235, "Install"));
    try controls.append(a, button("Cancel", 295, 235, "Cancel"));

    return .{
        .name = "WelcomeDlg",
        .first = "Install",
        .default = "Install",
        .cancel = "Cancel",
        .controls = try controls.toOwnedSlice(a),
    };
}

/// Builds `MaintenanceDlg`, shown when the user re-runs the MSI for an already
/// installed product to repair or uninstall it.
fn maintenanceDialog(a: Allocator, app_name: []const u8) !Dialog {
    const title = try fmt.allocPrint(
        a,
        "{s}Modify, repair, or remove {s}",
        .{ title_style, app_name },
    );
    const desc = try fmt.allocPrint(
        a,
        "Select an action below to repair or remove {s} from your system.",
        .{app_name},
    );
    const uninstall_text = try fmt.allocPrint(
        a,
        "Removes {s} completely from this computer.",
        .{app_name},
    );
    return .{
        .name = "MaintenanceDlg",
        .first = "Repair",
        .default = "Repair",
        .cancel = "Cancel",
        .controls = try a.dupe(Control, &.{
            heading(15, 15, 340, 25, title),
            label("Description", 15, 45, 340, 35, desc),
            bigButton("Repair", 95, "Repair"),
            label(
                "RepairText",
                120,
                100,
                230,
                20,
                "Repairs errors and restores missing or corrupt files.",
            ),
            bigButton("Uninstall", 135, "Uninstall"),
            label("UninstallText", 120, 140, 230, 20, uninstall_text),
            button("Cancel", 295, 235, "Cancel"),
        }),
    };
}

/// Builds the modeless `ProgressDlg` (`attributes = 1`, omitting the `Modal = 2`
/// bit so `ExecuteAction` continues running in the sequence immediately after the
/// dialog is created).
fn progressDialog(a: Allocator, app_name: []const u8) !Dialog {
    const title = try fmt.allocPrint(
        a,
        "{s}Please wait while setup configures {s}",
        .{ title_style, app_name },
    );
    return .{
        .name = "ProgressDlg",
        .first = "Cancel",
        .default = "Cancel",
        .cancel = "Cancel",
        .attributes = 1, // Visible (1), modeless (bit 1 = 0).
        .controls = try a.dupe(Control, &.{
            heading(20, 15, 330, 25, title),
            label("ActionText", 20, 55, 330, 20, null),
            .{
                .name = "ProgressBar",
                .kind = "ProgressBar",
                .x = 20,
                .y = 85,
                .width = 330,
                .height = 15,
                .attributes = progress_blocks,
                .property = "Progress",
            },
            button("Cancel", 295, 235, "Cancel"),
        }),
    };
}

/// Builds a terminal wizard page (`ExitDialog`, `FatalError`, or `UserExit`) with
/// a heading, a formatted `description` (containing one `{s}` placeholder for
/// `app_name`), and a `Finish` button.
fn endDialog(
    a: Allocator,
    app_name: []const u8,
    name: []const u8,
    heading_text: []const u8,
    comptime description: []const u8,
) !Dialog {
    return .{
        .name = name,
        .first = "Finish",
        .default = "Finish",
        .cancel = "Finish",
        .controls = try a.dupe(Control, &.{
            heading(20, 20, 330, 30, try fmt.allocPrint(a, "{s}{s}", .{ big_style, heading_text })),
            label("Description", 20, 60, 330, 40, try fmt.allocPrint(a, description, .{app_name})),
            button("Finish", 295, 235, "Finish"),
        }),
    };
}

/// Minimal RTF 1.5 document header selecting ANSI code page 1252, a 9pt (`\fs18`
/// half-points) Segoe UI font, and `\uc1` (1 fallback character per `\uN` escape).
const rtf_header =
    "{\\rtf1\\ansi\\ansicpg1252\\deff0{\\fonttbl{\\f0\\fnil Segoe UI;}}" ++
    "\\viewkind4\\uc1\\pard\\f0\\fs18 ";

/// Returns `text` formatted as an RTF document suitable for an MSI `ScrollableText`
/// control (which only renders Rich Text Format).
///
/// - Any leading UTF-8 BOM (`\xEF\xBB\xBF`) is stripped.
/// - If the remaining text already starts with `{\rtf`, it is duplicated unchanged.
/// - Otherwise, plain text is wrapped in `rtf_header` and escaped:
///   - RTF metacharacters (`\`, `{`, `}`) are backslash-escaped.
///   - `[` (`0x5B`) falls into the hex-escape branch (`\'5b`) because MSI evaluates
///     `Control.Text` as a `[Formatted]` string and would otherwise treat `[foo]`
///     inside a plain-text license as a property reference.
///   - Multi-byte UTF-8 sequences are converted to UTF-16LE code units and emitted
///     as signed 16-bit RTF Unicode escapes (`\uN?`, where `?` is the single ANSI
///     fallback character required by `\uc1`; code points above `U+FFFF` become a
///     surrogate pair of two `\uN?` escapes).
///   - Standalone high bytes that are not valid UTF-8 are emitted as `\'hh`
///     Windows-1252 hex escapes.
fn toRtf(a: Allocator, text: []const u8) ![]u8 {
    const body = std.mem.trimStart(u8, text, "\xef\xbb\xbf");
    if (std.mem.startsWith(u8, body, "{\\rtf")) return a.dupe(u8, body);

    var out: std.Io.Writer.Allocating = .init(a);
    errdefer out.deinit();
    const w = &out.writer;
    try w.writeAll(rtf_header);
    var i: usize = 0;
    while (i < body.len) : (i += 1) {
        switch (body[i]) {
            '\\', '{', '}' => |c| try w.print("\\{c}", .{c}),
            '\n' => try w.writeAll("\\par\r\n"),
            '\t' => try w.writeAll("\\tab "),
            '\r' => {},
            ' '...'[', ']'...'z', '|', '~' => |c| try w.writeByte(c),
            else => |c| {
                const len = std.unicode.utf8ByteSequenceLength(c) catch 1;
                var units: [2]u16 = undefined;
                const count = if (len > 1 and i + len <= body.len)
                    std.unicode.utf8ToUtf16Le(&units, body[i..][0..len]) catch null
                else
                    null;
                if (count) |n| {
                    for (units[0..n]) |u| try w.print("\\u{d}?", .{@as(i16, @bitCast(u))});
                    i += len - 1;
                } else try w.print("\\'{x:0>2}", .{c});
            },
        }
    }
    try w.writeAll("\\par\r\n}");
    return out.toOwnedSlice();
}

const testing = std.testing;

test "toRtf keeps RTF and escapes plain text" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try testing.expectEqualStrings("{\\rtf1 Hi}", try toRtf(a, "{\\rtf1 Hi}"));
    try testing.expectEqualStrings("{\\rtf1 Hi}", try toRtf(a, "\xef\xbb\xbf{\\rtf1 Hi}"));

    const rtf = try toRtf(a, "\xef\xbb\xbfA {b}\\\r\n\xc3\xa9 \xf0\x9f\x8e\x89 \xe9");
    try testing.expect(std.mem.startsWith(u8, rtf, "{\\rtf1"));
    const want_suffix = "A \\{b\\}\\\\\\par\r\n\\u233? \\u-10180?\\u-8311? \\'e9\\par\r\n}";
    try testing.expect(std.mem.endsWith(u8, rtf, want_suffix));
}

test "wizard tables are populated for both welcome variants" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    for ([_]?[]const u8{ null, "License terms" }) |license| {
        for ([_]bool{ false, true }) |has_main| {
            var db = Database.init(arena.allocator());
            _ = try addWizard(&db, "TestApp", license, has_main);
            try testing.expectEqual(license != null, db.getTable("ControlCondition") != null);
            try testing.expectEqual(@as(usize, 6), db.getTable("Dialog").?.rows.items.len);
            try testing.expect(db.getTable("InstallUISequence").?.rows.items.len >= 10);
            if (has_main) {
                try testing.expect(db.getTable("CheckBox") != null);
            }
        }
    }
}

test "every dialog references existing controls and tab order is one cycle" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    for ([_]bool{ false, true }) |has_main| {
        var db = Database.init(arena.allocator());
        _ = try addWizard(&db, "TestApp", "License terms", has_main);

        const dialogs = db.getTable("Dialog").?;
        const controls = db.getTable("Control").?;
        for (dialogs.rows.items) |d| {
            const name = d[dialogs.columnIndex("Dialog").?].string;
            var members: std.ArrayList([]const u8) = .empty;
            var next_of = std.StringHashMap([]const u8).init(arena.allocator());
            for (controls.rows.items) |c| {
                if (!std.mem.eql(u8, c[0].string, name)) continue;
                try members.append(arena.allocator(), c[1].string);
                try next_of.put(c[1].string, c[controls.columnIndex("Control_Next").?].string);
            }
            try testing.expect(members.items.len > 0);

            for ([_][]const u8{ "Control_First", "Control_Default", "Control_Cancel" }) |column| {
                const ref = d[dialogs.columnIndex(column).?].string;
                try testing.expect(next_of.contains(ref));
            }

            const first = d[dialogs.columnIndex("Control_First").?].string;
            var current = first;
            for (members.items) |_| current = next_of.get(current).?;
            try testing.expectEqualStrings(first, current);
            var visited: usize = 0;
            var walker = members.items[0];
            while (true) {
                visited += 1;
                walker = next_of.get(walker).?;
                if (std.mem.eql(u8, walker, members.items[0])) break;
            }
            try testing.expectEqual(members.items.len, visited);
        }
    }
}
