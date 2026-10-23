//! In-memory Windows Installer relational database model and binary serializer.
//!
//! How MSI stores relational tables inside a compound file:
//! - String deduplication (`_StringPool` and `_StringData`): Every string across
//!   all tables is interned into a global 1-based pool (`0` represents empty/NULL).
//!   `_StringPool` begins with a 4-byte codepage header followed by `(length: u16,
//!   ref_count: u16)` pairs; `_StringData` stores the raw concatenated string bytes
//!   without NUL terminators.
//! - Schema catalog (`_Tables` and `_Columns`): `_Tables` lists the name of every
//!   user table; `_Columns` records each column's 1-based index, name, and 16-bit
//!   type descriptor (`ColumnDef.typeBits`).
//! - Columnar table streams: Each non-empty table is written to its own stream in
//!   column-major order (all rows of column 1, then all rows of column 2, etc.)
//!   after sorting rows by their encoded primary key values.
//!
//! Memory management: All types in this module allocate from the `Allocator`
//! supplied at `init` and do not free individual allocations; callers should
//! pass an `ArenaAllocator`.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const cfbf = @import("cfbf.zig");
const stream_name = @import("stream_name.zig");

/// Fundamental storage kind of an MSI table column.
pub const Kind = enum { string, int, binary };

/// Schema definition of a single MSI table column.
pub const ColumnDef = struct {
    name: []const u8,
    kind: Kind,
    /// Declared column width: maximum character count for `.string` (`0` = unbounded),
    /// byte width (`2` or `4`) for `.int`, or `0` for `.binary`.
    size: u16,
    is_key: bool = false,
    is_nullable: bool = false,
    is_localizable: bool = false,

    /// Marks this column as part of the table's primary key.
    pub fn key(self: ColumnDef) ColumnDef {
        var c = self;
        c.is_key = true;
        return c;
    }

    /// Allows rows to omit a value (`NULL`) for this column.
    pub fn nullable(self: ColumnDef) ColumnDef {
        var c = self;
        c.is_nullable = true;
        return c;
    }

    /// Marks a string column as localizable in `_Columns.Type`.
    pub fn localizable(self: ColumnDef) ColumnDef {
        var c = self;
        c.is_localizable = true;
        return c;
    }

    /// Encodes the column's type and attribute flags into the 16-bit integer stored
    /// in the `_Columns.Type` catalog column.
    ///
    /// Bit layout:
    /// - `0x00FF`: column size (`size` characters for strings, `2` or `4` bytes for ints)
    /// - `0x0100`: column definition is valid/present
    /// - `0x0200`: localizable string text
    /// - `0x0400`: 2-byte width (16-bit integers and string pool identifiers)
    /// - `0x0800`: stream reference (string data or external binary stream)
    /// - `0x1000`: nullable column (may contain NULL values)
    /// - `0x2000`: primary key column
    pub fn typeBits(self: ColumnDef) u16 {
        var bits: u16 = 0x0100; // valid
        switch (self.kind) {
            .string => bits |= 0x0800 | 0x0400 | self.size,
            .int => bits |= self.size | (if (self.size == 2) @as(u16, 0x0400) else 0),
            .binary => bits |= 0x0800,
        }
        if (self.is_localizable) bits |= 0x0200;
        if (self.is_nullable) bits |= 0x1000;
        if (self.is_key) bits |= 0x2000;
        return bits;
    }
};

/// Defines a string column with maximum length `size` (`0` for unbounded text).
pub fn str(name: []const u8, size: u16) ColumnDef {
    return .{ .name = name, .kind = .string, .size = size };
}

/// Defines a signed integer column of `size` bytes (`2` for 16-bit, `4` for 32-bit).
pub fn int(name: []const u8, size: u16) ColumnDef {
    return .{ .name = name, .kind = .int, .size = size };
}

/// Defines a binary stream reference column (used by the `Icon` and `Binary` tables).
pub fn binary(name: []const u8) ColumnDef {
    return .{ .name = name, .kind = .binary, .size = 0 };
}

/// Schema definition of an MSI database table.
pub const TableDef = struct {
    name: []const u8,
    columns: []const ColumnDef,
};

/// Internal MSI catalog table listing the names of all user tables in the database.
const tables_def: TableDef = .{ .name = "_Tables", .columns = &.{str("Name", 64).key()} };

/// Internal MSI catalog table listing the schema of every column in every user table.
const columns_def: TableDef = .{ .name = "_Columns", .columns = &.{
    str("Table", 64).key(),
    int("Number", 2).key(),
    str("Name", 64),
    int("Type", 2),
} };

/// Cell value stored in a `Table` row.
pub const Value = union(enum) {
    none,
    int: i32,
    string: []const u8,

    /// Coerces a Zig integer, string slice/literal, `null`, or optional into a `Value`.
    pub fn from(val: anytype) Value {
        const T = @TypeOf(val);
        switch (@typeInfo(T)) {
            .null => return .none,
            .optional => return if (val) |v| from(v) else .none,
            .int, .comptime_int => return .{ .int = @intCast(val) },
            .pointer => return .{ .string = val },
            else => @compileError("Unsupported type for Value.from: " ++ @typeName(T)),
        }
    }
};

/// Deduplicated, reference-counted string pool backing the `_StringPool` and
/// `_StringData` streams of an MSI database.
pub const StringTable = struct {
    const Entry = struct { text: []const u8, refs: u16 };

    allocator: Allocator,
    entries: std.ArrayList(Entry) = .empty,
    ids: std.StringHashMapUnmanaged(u16) = .empty,

    pub fn init(allocator: Allocator) StringTable {
        return .{ .allocator = allocator };
    }

    /// Interns `text` in the string pool, increments its reference count, and
    /// returns its 1-based pool ID (`0` for the empty string).
    ///
    /// Returns `error.StringTooLong` if `text` exceeds 65,535 bytes, or
    /// `error.TooManyStrings` if the pool exceeds 65,534 unique non-empty strings.
    pub fn add(self: *StringTable, text: []const u8) !u16 {
        if (text.len == 0) return 0;
        if (text.len > std.math.maxInt(u16)) return error.StringTooLong;
        const gop = try self.ids.getOrPut(self.allocator, text);
        if (!gop.found_existing) {
            const next_id = std.math.cast(u16, self.entries.items.len + 1) orelse
                return error.TooManyStrings;
            const owned = try self.allocator.dupe(u8, text);
            gop.key_ptr.* = owned;
            gop.value_ptr.* = next_id;
            try self.entries.append(self.allocator, .{ .text = owned, .refs = 0 });
        }
        const entry = &self.entries.items[gop.value_ptr.* - 1];
        entry.refs +|= 1;
        return gop.value_ptr.*;
    }

    /// Returns the 1-based pool ID of `text` (which must have been previously
    /// registered via `add`), or `0` if `text` is empty.
    fn id(self: *const StringTable, text: []const u8) u16 {
        return if (text.len == 0) 0 else self.ids.get(text).?;
    }

    /// Serializes the interned strings into the `_StringPool` (4-byte little-endian
    /// `codepage` header followed by `(len: u16, refs: u16)` per entry) and
    /// `_StringData` (concatenated raw string bytes) stream payloads.
    pub fn buildStreams(
        self: *const StringTable,
        codepage: u16,
    ) !struct { pool: []u8, data: []u8 } {
        var pool: std.Io.Writer.Allocating = .init(self.allocator);
        var data: std.Io.Writer.Allocating = .init(self.allocator);
        try pool.writer.writeInt(u32, codepage, .little);
        for (self.entries.items) |e| {
            try pool.writer.writeInt(u16, @intCast(e.text.len), .little);
            try pool.writer.writeInt(u16, e.refs, .little);
            try data.writer.writeAll(e.text);
        }
        return .{ .pool = try pool.toOwnedSlice(), .data = try data.toOwnedSlice() };
    }
};

/// In-memory representation of a single MSI database table and its rows.
pub const Table = struct {
    def: TableDef,
    rows: std.ArrayList([]const Value) = .empty,
    allocator: Allocator,

    /// Appends a row from an anonymous struct whose field names match column names
    /// in `self.def`.
    ///
    /// Columns omitted from `row` default to `.none` (`NULL`). Returns
    /// `error.UnknownColumn` if a struct field does not match any column name, or
    /// `error.MissingValue` if a non-nullable column is omitted or set to `null`.
    pub fn addRow(self: *Table, row: anytype) !void {
        const fields = @typeInfo(@TypeOf(row)).@"struct".field_names;
        const cells = try self.allocator.alloc(Value, self.def.columns.len);
        @memset(cells, .none);
        inline for (fields) |name| {
            const col_idx = self.columnIndex(name) orelse return error.UnknownColumn;
            cells[col_idx] = Value.from(@field(row, name));
        }
        for (self.def.columns, cells) |col, *cell| {
            if (cell.* == .none and !col.is_nullable) return error.MissingValue;
            if (cell.* == .string) cell.string = try self.allocator.dupe(u8, cell.string);
        }
        try self.rows.append(self.allocator, cells);
    }

    /// Returns the zero-based index of the column named `name`, or `null` if not found.
    pub fn columnIndex(self: *const Table, name: []const u8) ?usize {
        for (self.def.columns, 0..) |col, i| {
            if (mem.eql(u8, col.name, name)) return i;
        }
        return null;
    }

    /// Interns every string cell in `self.rows` into `strings` so pool IDs and
    /// reference counts are finalized prior to sorting and serialization.
    fn internStrings(self: *const Table, strings: *StringTable) !void {
        for (self.rows.items) |row| {
            for (row) |cell| {
                if (cell == .string) _ = try strings.add(cell.string);
            }
        }
    }

    /// Encodes a single cell into its on-disk unsigned integer representation:
    /// - `.string`: 1-based string pool ID (`0` for empty or `NULL`).
    /// - `.binary`: `1` when present, `0` when `NULL` (the binary stream itself is
    ///   stored under `TableName.RowKey` in the compound file).
    /// - `.int`: biased unsigned integer where `0` is reserved for `NULL` and
    ///   non-null values have their sign bit flipped (`i + 0x8000` for 16-bit
    ///   columns, admitting `-32767..32767`; `i ^ 0x80000000` for 32-bit columns,
    ///   admitting `-2147483647..2147483647`).
    fn encodeCell(col: ColumnDef, cell: Value, strings: *const StringTable) !u32 {
        return switch (col.kind) {
            .string => switch (cell) {
                .none => 0,
                .string => |s| strings.id(s),
                .int => error.TypeMismatch,
            },
            .binary => switch (cell) {
                .none => 0,
                .string => 1,
                .int => error.TypeMismatch,
            },
            .int => switch (cell) {
                .none => 0,
                .string => error.TypeMismatch,
                .int => |i| if (col.size == 2) blk: {
                    if (i <= -0x8000 or i > 0x7fff) return error.ValueOutOfRange;
                    break :blk @intCast(i + 0x8000);
                } else blk: {
                    if (i == std.math.minInt(i32)) return error.ValueOutOfRange;
                    break :blk @as(u32, @bitCast(i)) ^ 0x80000000;
                },
            },
        };
    }

    /// Sorts `self.rows` in ascending order of their encoded primary key cells.
    ///
    /// Why this is required: Windows Installer binary-searches table streams by
    /// the raw on-disk representation of primary key columns (1-based string pool
    /// IDs and biased integers, NOT alphabetical string order). All strings must
    /// have been registered in `strings` via `internStrings` before calling this.
    fn sortByKey(self: *Table, strings: *const StringTable) void {
        const Context = struct {
            table: *const Table,
            strings: *const StringTable,

            fn lessThan(ctx: @This(), a: []const Value, b: []const Value) bool {
                for (ctx.table.def.columns, 0..) |col, c| {
                    if (!col.is_key) continue;
                    const ka = encodeCell(col, a[c], ctx.strings) catch 0;
                    const kb = encodeCell(col, b[c], ctx.strings) catch 0;
                    if (ka != kb) return ka < kb;
                }
                return false;
            }
        };
        std.sort.block(
            []const Value,
            self.rows.items,
            Context{ .table = self, .strings = strings },
            Context.lessThan,
        );
    }

    /// Serializes the table's cells in column-major order (all row values for
    /// column 0, followed by all row values for column 1, etc.) as required by
    /// MSI table streams. All strings must already be interned in `strings`.
    fn serialize(self: *const Table, strings: *const StringTable) ![]u8 {
        var out: std.Io.Writer.Allocating = .init(self.allocator);
        for (self.def.columns, 0..) |col, c| {
            for (self.rows.items) |row| {
                const bits = try encodeCell(col, row[c], strings);
                if (col.kind == .int and col.size == 4) {
                    try out.writer.writeInt(u32, bits, .little);
                } else {
                    try out.writer.writeInt(u16, @intCast(bits), .little);
                }
            }
        }
        return out.toOwnedSlice();
    }
};

/// In-memory collection of MSI tables and their shared string pool.
pub const Database = struct {
    allocator: Allocator,
    tables: std.ArrayList(*Table) = .empty,
    strings: StringTable,

    pub fn init(allocator: Allocator) Database {
        return .{ .allocator = allocator, .strings = StringTable.init(allocator) };
    }

    /// Creates a new empty table with schema `def`, registers it in the database,
    /// and returns a mutable pointer to it.
    pub fn addTable(self: *Database, def: TableDef) !*Table {
        const t = try self.allocator.create(Table);
        t.* = .{ .def = def, .allocator = self.allocator };
        try self.tables.append(self.allocator, t);
        return t;
    }

    /// Looks up a previously added table by its MSI table name, returning `null`
    /// if no such table exists.
    pub fn getTable(self: *const Database, name: []const u8) ?*Table {
        for (self.tables.items) |t| {
            if (mem.eql(u8, t.def.name, name)) return t;
        }
        return null;
    }

    /// Finalizes the database and adds `_Tables`, `_Columns`, `_StringPool`,
    /// `_StringData`, and one stream per non-empty table to `cf`.
    ///
    /// Empty tables are recorded in `_Tables` and `_Columns` (so queries against
    /// them succeed) but do not emit a table stream in the compound file. No further
    /// tables or rows should be added after calling `writeStreams`.
    pub fn writeStreams(self: *Database, cf: *cfbf.CompoundFile) !void {
        const user_tables = self.tables.items.len;
        const tables_t = try self.addTable(tables_def);
        const columns_t = try self.addTable(columns_def);
        for (self.tables.items[0..user_tables]) |t| {
            try tables_t.addRow(.{ .Name = t.def.name });
            for (t.def.columns, 1..) |col, number| {
                try columns_t.addRow(.{
                    .Table = t.def.name,
                    .Number = number,
                    .Name = col.name,
                    .Type = col.typeBits(),
                });
            }
        }

        // Rows are ordered by string ids, so intern everything first.
        for (self.tables.items) |t| try t.internStrings(&self.strings);
        for (self.tables.items) |t| {
            if (t.rows.items.len == 0) continue;
            t.sortByKey(&self.strings);
            const stream_id = try stream_name.encode(self.allocator, t.def.name, true);
            try cf.addStream(stream_id, try t.serialize(&self.strings));
        }
        const pool = try self.strings.buildStreams(1252);
        try cf.addStream(try stream_name.encode(self.allocator, "_StringPool", true), pool.pool);
        try cf.addStream(try stream_name.encode(self.allocator, "_StringData", true), pool.data);
    }
};

const testing = std.testing;

fn testArena() std.heap.ArenaAllocator {
    return std.heap.ArenaAllocator.init(testing.allocator);
}

test "ColumnDef type bits match the MSI encoding" {
    try testing.expectEqual(@as(u16, 0x2d48), str("A", 72).key().typeBits());
    try testing.expectEqual(@as(u16, 0x0f00), str("A", 0).localizable().typeBits());
    try testing.expectEqual(@as(u16, 0x1502), int("A", 2).nullable().typeBits());
    try testing.expectEqual(@as(u16, 0x0104), int("A", 4).typeBits());
    try testing.expectEqual(@as(u16, 0x0900), binary("A").typeBits());
}

test "Value.from conversion" {
    try testing.expectEqual(Value{ .int = 42 }, Value.from(42));
    try testing.expectEqual(Value.none, Value.from(null));
    try testing.expectEqualStrings("test", Value.from("test").string);

    const maybe_str: ?[]const u8 = "hello";
    try testing.expectEqualStrings("hello", Value.from(maybe_str).string);
    const none_str: ?[]const u8 = null;
    try testing.expectEqual(Value.none, Value.from(none_str));
}

test "StringTable deduplicates and counts references" {
    var arena = testArena();
    defer arena.deinit();
    var st = StringTable.init(arena.allocator());

    try testing.expectEqual(@as(u16, 1), try st.add("repeat"));
    try testing.expectEqual(@as(u16, 1), try st.add("repeat"));
    try testing.expectEqual(@as(u16, 2), try st.add("unique"));
    try testing.expectEqual(@as(u16, 0), try st.add(""));
    try testing.expectEqual(@as(u16, 2), st.entries.items[0].refs);
    try testing.expectEqual(@as(u16, 1), st.entries.items[1].refs);

    const big = try arena.allocator().alloc(u8, 70000);
    try testing.expectError(error.StringTooLong, st.add(big));
}

test "table serialization is columnar with biased integers" {
    var arena = testArena();
    defer arena.deinit();
    var db = Database.init(arena.allocator());

    const t = try db.addTable(.{ .name = "T", .columns = &.{
        str("Id", 72).key(),
        int("Small", 2),
        int("Big", 4).nullable(),
    } });
    try t.addRow(.{ .Id = "a", .Small = 5, .Big = 100000 });
    try t.addRow(.{ .Id = "b", .Small = -1 });

    try t.internStrings(&db.strings);
    const data = try t.serialize(&db.strings);
    try testing.expectEqual(@as(usize, 2 * 2 + 2 * 2 + 2 * 4), data.len);
    // Id column: string ids 1 and 2.
    try testing.expectEqual(@as(u16, 1), mem.readInt(u16, data[0..2], .little));
    try testing.expectEqual(@as(u16, 2), mem.readInt(u16, data[2..4], .little));
    // Small column: 5 and -1 with 0x8000 bias.
    try testing.expectEqual(@as(u16, 0x8005), mem.readInt(u16, data[4..6], .little));
    try testing.expectEqual(@as(u16, 0x7fff), mem.readInt(u16, data[6..8], .little));
    // Big column: 100000 with sign bit flipped, then NULL.
    try testing.expectEqual(@as(u32, 100000 ^ 0x80000000), mem.readInt(u32, data[8..12], .little));
    try testing.expectEqual(@as(u32, 0), mem.readInt(u32, data[12..16], .little));
}

test "rows are ordered by the string pool ids of their keys" {
    var arena = testArena();
    defer arena.deinit();
    var db = Database.init(arena.allocator());

    // "zebra" is interned before "apple", so it sorts first despite the spelling.
    const first = try db.addTable(.{ .name = "First", .columns = &.{str("Id", 72).key()} });
    try first.addRow(.{ .Id = "zebra" });
    try first.addRow(.{ .Id = "apple" });
    const second = try db.addTable(.{
        .name = "Second",
        .columns = &.{ str("Id", 72).key(), int("N", 2).key().nullable() },
    });
    try second.addRow(.{ .Id = "apple", .N = 2 });
    try second.addRow(.{ .Id = "zebra", .N = 1 });
    try second.addRow(.{ .Id = "apple", .N = -1 });
    try second.addRow(.{ .Id = "apple" });

    try first.internStrings(&db.strings);
    try second.internStrings(&db.strings);
    second.sortByKey(&db.strings);
    try testing.expectEqualStrings("zebra", second.rows.items[0][0].string);
    try testing.expectEqual(Value.none, second.rows.items[1][1]);
    try testing.expectEqual(@as(i32, -1), second.rows.items[2][1].int);
    try testing.expectEqual(@as(i32, 2), second.rows.items[3][1].int);
}

test "table rows are validated" {
    var arena = testArena();
    defer arena.deinit();
    var db = Database.init(arena.allocator());

    const t = try db.addTable(.{ .name = "T", .columns = &.{ str("Id", 72).key(), int("N", 2) } });
    try testing.expectError(error.MissingValue, t.addRow(.{ .Id = "a" }));
    try testing.expectError(error.UnknownColumn, t.addRow(.{ .Id = "a", .N = 1, .Typo = 2 }));
    try t.addRow(.{ .Id = "a", .N = 70000 });
    try t.internStrings(&db.strings);
    try testing.expectError(error.ValueOutOfRange, t.serialize(&db.strings));

    const u = try db.addTable(.{ .name = "U", .columns = &.{str("Id", 72).key()} });
    try u.addRow(.{ .Id = @as(i32, 3) });
    try u.internStrings(&db.strings);
    try testing.expectError(error.TypeMismatch, u.serialize(&db.strings));
}

test "writeStreams emits metadata and skips empty tables" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();
    var db = Database.init(a);

    const full = try db.addTable(.{ .name = "Full", .columns = &.{str("Id", 72).key()} });
    try full.addRow(.{ .Id = "x" });
    _ = try db.addTable(.{ .name = "Empty", .columns = &.{str("Id", 72).key()} });

    var cf = cfbf.CompoundFile.init(a);
    try db.writeStreams(&cf);
    const file = try cf.write(a);
    const reader = cfbf.Reader{ .data = file };

    for ([_][]const u8{ "_Tables", "_Columns", "_StringPool", "_StringData", "Full" }) |name| {
        const enc = try stream_name.encode(a, name, true);
        try testing.expect(try reader.readStream(a, enc) != null);
    }
    const empty = try stream_name.encode(a, "Empty", true);
    try testing.expect(try reader.readStream(a, empty) == null);
}
