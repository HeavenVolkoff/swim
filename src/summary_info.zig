//! OLE Property Set (`[MS-OLEPS]`) writer and verification reader for the
//! `\x05SummaryInformation` stream.
//!
//! Windows Installer inspects `\x05SummaryInformation` before opening any database
//! tables in order to determine the target CPU architecture and minimum language
//! (`PropertyId.template`), the package revision GUID (`PropertyId.revnumber`),
//! the minimum installer engine version (`PropertyId.pagecount`), and whether
//! payload files are compressed or require UAC elevation (`PropertyId.wordcount`).
//!
//! Stream layout (OLE property set stream with 1 section):
//! - Bytes `0..28`: Header (byte-order `0xFFFE`, format `0`,
//!   OS version indicator `0x00020005` = Windows NT 5.0, 16 zero bytes, section count `1`).
//! - Bytes `28..48`: Format identifier entry pairing the summary information format GUID
//!   with the byte offset (`48`) of the single property section.
//! - Bytes `48..`: Property section header (section byte size, property count),
//!   followed by `(property_id: u32, offset: u32)` entries,
//!   followed by the 4-byte-aligned property payloads.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Writer = std.Io.Writer;

/// Format identifier (`{F29F85E0-4FF9-1068-AB91-08002B27B3D9}`) for the standard
/// Summary Information property set.
pub const fmtid_summary_information = [16]u8{
    0xe0, 0x85, 0x9f, 0xf2, 0xf9, 0x4f, 0x68, 0x10,
    0xab, 0x91, 0x08, 0x00, 0x2b, 0x27, 0xb3, 0xd9,
};

/// Property variant type identifiers.
const TypeTag = enum(u32) {
    int16 = 2,
    int32 = 3,
    string = 30,
    filetime = 64,
};

/// Byte offset from the start of the stream to the first (and only) property section:
/// 28-byte header + one 20-byte format identifier entry = 48.
const section_offset: u32 = 48;

/// Standard property identifiers defined for the summary information property set
/// and interpreted by Windows Installer for package metadata.
pub const PropertyId = enum(u32) {
    /// Character set code page for strings (e.g. 1252 for Windows-1252).
    codepage = 1,
    /// Package type description (e.g. "Installation Database").
    title = 2,
    /// Product name.
    subject = 3,
    /// Manufacturer or publisher name.
    author = 4,
    /// Search keywords (e.g. "Installer").
    keywords = 5,
    /// Package description comment.
    comments = 6,
    /// Target platform architecture and language identifiers (e.g. "x64;1033").
    template = 7,
    /// Package revision code (unique UUID string per build).
    revnumber = 9,
    /// Package creation timestamp.
    create_dtm = 12,
    /// Package last-saved timestamp.
    lastsave_dtm = 13,
    /// Minimum Windows Installer version multiplied by 100 (e.g. 500 = v5.0).
    pagecount = 14,
    /// Package flags: bit 1 (2) indicates compressed files; bit 3 (8) indicates UAC compliance.
    wordcount = 15,
    /// Character count.
    charcount = 16,
    /// Generator tool name.
    appname = 18,
    /// Security level recommendation (2 indicates read-only recommended).
    security = 19,
    _,
};

/// A typed property value in a summary information property set.
///
/// Every serialized property value must have a total byte length that is a
/// multiple of 4 bytes so subsequent values in the section stay 32-bit aligned.
pub const PropertyValue = union(enum) {
    int16: i16,
    int32: i32,
    string: []const u8,
    filetime: u64,

    /// Writes the 4-byte type tag followed by the value payload padded to a
    /// 4-byte boundary.
    fn write(self: PropertyValue, w: *Writer) !void {
        switch (self) {
            .int16 => |v| {
                try w.writeInt(u32, @backingInt(TypeTag.int16), .little);
                try w.writeInt(i16, v, .little);
                try w.splatByteAll(0, 2); // Pad 2-byte integer to 4-byte alignment.
            },
            .int32 => |v| {
                try w.writeInt(u32, @backingInt(TypeTag.int32), .little);
                try w.writeInt(i32, v, .little);
            },
            .filetime => |v| {
                try w.writeInt(u32, @backingInt(TypeTag.filetime), .little);
                try w.writeInt(u64, v, .little);
            },
            .string => |s| {
                try w.writeInt(u32, @backingInt(TypeTag.string), .little);
                try w.writeInt(u32, @intCast(s.len + 1), .little);
                try w.writeAll(s);
                // Append 1 NUL terminator byte plus 0..3 padding bytes to reach
                // the next 4-byte boundary.
                try w.splatByteAll(0, 1 + (-%(s.len + 1)) % 4);
            },
        }
    }
};

/// A `(PropertyId, PropertyValue)` pair stored in a `SummaryInfo` section.
pub const Property = struct {
    id: PropertyId,
    value: PropertyValue,
};

/// In-memory representation of the `\x05SummaryInformation` property set.
pub const SummaryInfo = struct {
    allocator: Allocator,
    properties: std.ArrayList(Property) = .empty,

    pub fn init(allocator: Allocator) SummaryInfo {
        return .{ .allocator = allocator };
    }

    /// Sets or replaces the property identified by `id`.
    ///
    /// String slices inside `value` are borrowed and must remain valid until
    /// `write` completes.
    pub fn set(self: *SummaryInfo, id: PropertyId, value: PropertyValue) !void {
        for (self.properties.items) |*p| {
            if (p.id == id) {
                p.value = value;
                return;
            }
        }
        try self.properties.append(self.allocator, .{ .id = id, .value = value });
    }

    /// Returns the value previously stored for `id`, or `null` if not present.
    pub fn get(self: *const SummaryInfo, id: PropertyId) ?PropertyValue {
        for (self.properties.items) |p| {
            if (p.id == id) return p.value;
        }
        return null;
    }

    /// Serializes the property set into the `[MS-OLEPS]` binary format, returning
    /// a newly allocated byte slice owned by `allocator`.
    pub fn write(self: *const SummaryInfo, allocator: Allocator) ![]u8 {
        const sorted = try allocator.dupe(Property, self.properties.items);
        defer allocator.free(sorted);
        std.sort.pdq(Property, sorted, {}, struct {
            fn lessThan(_: void, a: Property, b: Property) bool {
                return @backingInt(a.id) < @backingInt(b.id);
            }
        }.lessThan);

        // Serialize values into a scratch buffer first so each value's section-relative
        // byte offset is known when writing the property directory header.
        var values: Writer.Allocating = .init(allocator);
        defer values.deinit();
        const index_size: u32 = @intCast(8 + 8 * sorted.len);
        const offsets = try allocator.alloc(u32, sorted.len);
        defer allocator.free(offsets);
        for (sorted, offsets) |p, *offset| {
            offset.* = index_size + @as(u32, @intCast(values.writer.end));
            try p.value.write(&values.writer);
        }

        const values_size: u32 = @intCast(values.writer.end);
        var out: Writer.Allocating = try .initCapacity(
            allocator,
            section_offset + index_size + values_size,
        );
        errdefer out.deinit();
        const w = &out.writer;
        try w.writeInt(u16, 0xfffe, .little); // byte-order: little-endian
        try w.writeInt(u16, 0, .little); // format version: 0
        try w.writeInt(u32, 0x00020005, .little); // system identifier: 32-bit NT 5.0
        try w.splatByteAll(0, 16); // zero-filled class identifier
        try w.writeInt(u32, 1, .little); // section count: 1
        try w.writeAll(&fmtid_summary_information);
        try w.writeInt(u32, section_offset, .little);

        try w.writeInt(u32, index_size + values_size, .little); // cbSection
        try w.writeInt(u32, @intCast(sorted.len), .little); // cProperties
        for (sorted, offsets) |p, offset| {
            try w.writeInt(u32, @backingInt(p.id), .little);
            try w.writeInt(u32, offset, .little);
        }
        try w.writeAll(values.writer.buffered());
        return out.toOwnedSlice();
    }

    /// Parses an `[MS-OLEPS]` property set stream from `bytes` for test verification.
    ///
    /// Returned `.string` slices borrow directly from `bytes`.
    pub fn read(allocator: Allocator, bytes: []const u8) !SummaryInfo {
        if (bytes.len < section_offset) return error.InvalidSummaryInfo;
        if (mem.readInt(u16, bytes[0..2], .little) != 0xfffe) return error.InvalidByteOrder;
        if (mem.readInt(u32, bytes[24..28], .little) < 1) return error.NoSections;
        const section_start = mem.readInt(u32, bytes[44..48], .little);
        if (section_start > bytes.len - 8) return error.InvalidSectionOffset;

        const sec = bytes[section_start..];
        var si = SummaryInfo.init(allocator);
        errdefer si.properties.deinit(allocator);
        for (0..mem.readInt(u32, sec[4..8], .little)) |i| {
            const entry = 8 + i * 8;
            if (entry + 8 > sec.len) return error.InvalidPropertyEntry;
            const id: PropertyId = @fromBackingInt(mem.readInt(u32, sec[entry..][0..4], .little));
            const at = mem.readInt(u32, sec[entry + 4 ..][0..4], .little);
            const value = try readValue(sec, at) orelse continue;
            try si.set(id, value);
        }
        return si;
    }

    /// Reads a single property value at section-relative offset `at`,
    /// returning `null` for unsupported property types or empty strings.
    fn readValue(sec: []const u8, at: usize) !?PropertyValue {
        if (at + 4 > sec.len) return error.InvalidValueOffset;
        const payload = sec[at + 4 ..];
        const raw_type = mem.readInt(u32, sec[at..][0..4], .little);
        switch (raw_type) {
            @backingInt(TypeTag.int16) => {
                return .{ .int16 = mem.readInt(i16, try need(payload, 2), .little) };
            },
            @backingInt(TypeTag.int32) => {
                return .{ .int32 = mem.readInt(i32, try need(payload, 4), .little) };
            },
            @backingInt(TypeTag.filetime) => {
                return .{ .filetime = mem.readInt(u64, try need(payload, 8), .little) };
            },
            @backingInt(TypeTag.string) => {
                const len = mem.readInt(u32, try need(payload, 4), .little);
                if (len == 0) return null;
                if (payload.len < 4 + @as(usize, len)) return error.UnexpectedEof;
                return .{ .string = payload[4..][0 .. len - 1] };
            },
            else => return null,
        }
    }

    /// Returns a pointer to the first `n` bytes of `payload`, or `error.UnexpectedEof`
    /// if `payload` is shorter than `n` bytes.
    fn need(payload: []const u8, comptime n: usize) !*const [n]u8 {
        if (payload.len < n) return error.UnexpectedEof;
        return payload[0..n];
    }
};

const testing = std.testing;

test "serialization round trip" {
    const allocator = testing.allocator;
    var si = SummaryInfo.init(allocator);
    defer si.properties.deinit(allocator);

    try si.set(.codepage, .{ .int16 = 1252 });
    try si.set(.title, .{ .string = "Installation Database" });
    try si.set(.title, .{ .string = "Replaced" }); // overwrite
    try si.set(.author, .{ .string = "Acme" }); // length + 1 is a multiple of 4: exactly one NUL
    try si.set(.pagecount, .{ .int32 = 500 });
    try si.set(.create_dtm, .{ .filetime = 133500000000000000 });

    const bytes = try si.write(allocator);
    defer allocator.free(bytes);
    try testing.expectEqual(@as(usize, 0), (bytes.len - section_offset) % 4);
    try testing.expectEqualSlices(u8, &fmtid_summary_information, bytes[28..44]);

    var back = try SummaryInfo.read(allocator, bytes);
    defer back.properties.deinit(allocator);
    try testing.expectEqual(@as(i16, 1252), back.get(.codepage).?.int16);
    try testing.expectEqualStrings("Replaced", back.get(.title).?.string);
    try testing.expectEqualStrings("Acme", back.get(.author).?.string);
    try testing.expectEqual(@as(i32, 500), back.get(.pagecount).?.int32);
    try testing.expectEqual(@as(u64, 133500000000000000), back.get(.create_dtm).?.filetime);
    try testing.expect(back.get(.keywords) == null);
}

test "invalid property sets are rejected" {
    const allocator = testing.allocator;
    try testing.expectError(error.InvalidSummaryInfo, SummaryInfo.read(allocator, "too short"));
    const zeros: [60]u8 = @splat(0);
    try testing.expectError(error.InvalidByteOrder, SummaryInfo.read(allocator, &zeros));
}
