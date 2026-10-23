//! Writer for a single-folder, uncompressed Microsoft Cabinet (`MSCF` / MS-CAB)
//! archive.
//!
//! Windows Installer requires payload files to be stored inside a cabinet archive
//! (embedded in the MSI compound file as a stream such as `cab1.cab` and referenced
//! by `#cab1.cab` in the `Media` table) or laid out loose on disk. Storing all
//! payload files in a single uncompressed folder keeps the archive layout simple:
//! 1. `CfHeader` (36 bytes): overall cabinet size, file table offset, and counts.
//! 2. `CfFolder` (8 bytes): offset of the first `CFDATA` block and block count.
//! 3. `CfFileHeader` + NUL-terminated name (16 + N bytes per file): uncompressed
//!    size and byte offset within the concatenated folder payload.
//! 4. `CfDataHeader` + raw payload chunk (8 + up to 32768 bytes per block).

const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const Allocator = mem.Allocator;

comptime {
    std.debug.assert(builtin.cpu.arch.endian() == .little);
}

/// Four-byte signature (`"MSCF"`) at the start of every MS-CAB header.
pub const mscf_magic = [4]u8{ 'M', 'S', 'C', 'F' };

/// Maximum uncompressed payload bytes per `CFDATA` block mandated by the MS-CAB
/// specification (`0x8000` = 32,768 bytes).
pub const max_block_size: usize = 32768;

/// A file entry queued for inclusion in a `Cabinet`.
pub const File = struct {
    /// Archive-internal identifier (matches the `File.File` primary key in MSI).
    name: []const u8,
    /// Raw uncompressed file contents.
    data: []const u8,
};

/// MS-CAB `CFHEADER` structure (fixed 36-byte prefix when `flags == 0`).
const CfHeader = extern struct {
    signature: [4]u8 = mscf_magic,
    reserved1: u32 = 0,
    /// Total size of the cabinet file in bytes.
    cbCabinet: u32,
    reserved2: u32 = 0,
    /// Byte offset from the start of the cabinet to the first `CfFileHeader`.
    coffFiles: u32,
    reserved3: u32 = 0,
    /// Cabinet format version 1.3 as required by the MS-CAB specification.
    versionMinor: u8 = 3,
    versionMajor: u8 = 1,
    /// Number of `CfFolder` entries (always 1 for our single-folder archive).
    cFolders: u16 = 1,
    /// Number of `CfFileHeader` entries in the cabinet.
    cFiles: u16,
    flags: u16 = 0,
    /// Arbitrary cabinet set ID linking multi-volume cabinets.
    setID: u16 = 0x1234,
    iCabinet: u16 = 0,
};

/// MS-CAB `CFFOLDER` structure describing one compression unit.
const CfFolder = extern struct {
    /// Byte offset from the start of the cabinet to the first `CfDataHeader` block.
    coffCabStart: u32,
    /// Number of `CfDataHeader` blocks belonging to this folder.
    cCFData: u16,
    /// Compression algorithm (0 indicates uncompressed data blocks).
    typeCompress: u16 = 0,
};

/// File metadata entry preceding each file name in the cabinet directory.
const CfFileHeader = extern struct {
    /// Uncompressed size of this file in bytes.
    cbFile: u32,
    /// Uncompressed byte offset of this file's start within the folder stream.
    uoffFolderStart: u32,
    /// Zero-based index of the folder containing this file.
    iFolder: u16 = 0,
    /// Fixed DOS date for reproducible builds.
    date: u16 = 0x5D4A,
    /// Fixed DOS time (16:00:00) for reproducible builds.
    time: u16 = 0x8000,
    /// File attributes: bit 5 (0x0020) marks standard archive status.
    attribs: u16 = 0x0020,
};

/// MS-CAB `CFDATA` block header preceding each up-to-32-KiB payload chunk.
const CfDataHeader = extern struct {
    /// Checksum computed over `cbData`, `cbUncomp`, and the block's payload bytes.
    csum: u32,
    /// Number of compressed bytes in this block (equals `cbUncomp` when uncompressed).
    cbData: u16,
    /// Number of uncompressed bytes in this block (at most `max_block_size`).
    cbUncomp: u16,
};

comptime {
    std.debug.assert(@sizeOf(CfHeader) == 36);
    std.debug.assert(@sizeOf(CfFolder) == 8);
    std.debug.assert(@sizeOf(CfFileHeader) == 16);
    std.debug.assert(@sizeOf(CfDataHeader) == 8);
}

/// Computes the MS-CAB `CHECKSUM` over `data` starting from `seed`.
///
/// Per the MS-CAB specification, full 4-byte groups are XORed as little-endian
/// 32-bit integers, whereas a trailing partial group of 1, 2, or 3 bytes is
/// packed in big-endian order (first remaining byte in the most significant
/// position of the partial word) before being XORed into the accumulator.
pub fn computeChecksum(data: []const u8, seed: u32) u32 {
    var csum = seed;
    var words = mem.window(u8, data, 4, 4);
    while (words.next()) |w| {
        csum ^= if (w.len == 4) mem.readInt(u32, w[0..4], .little) else blk: {
            var tail: u32 = 0;
            for (w) |byte| tail = (tail << 8) | byte;
            break :blk tail;
        };
    }
    return csum;
}

/// Builder for an in-memory Microsoft Cabinet archive.
pub const Cabinet = struct {
    allocator: Allocator,
    files: std.ArrayList(File) = .empty,

    pub fn init(allocator: Allocator) Cabinet {
        return .{ .allocator = allocator };
    }

    /// Appends a file to the cabinet in sequence order.
    ///
    /// Both `name` and `data` are borrowed slices and must remain valid until
    /// `write` completes.
    pub fn addFile(self: *Cabinet, name: []const u8, data: []const u8) !void {
        try self.files.append(self.allocator, .{ .name = name, .data = data });
    }

    /// Serializes the cabinet into a newly allocated byte slice owned by `allocator`.
    ///
    /// Returns `error.TooManyFiles` if more than 65,535 files were added, or
    /// `error.CabinetTooLarge` if the block count exceeds 65,535 (~2 GiB of payload)
    /// or total archive size exceeds `u32` (~4 GiB).
    pub fn write(self: *const Cabinet, allocator: Allocator) ![]u8 {
        var names_size: usize = 0;
        var folder_data: std.ArrayList(u8) = .empty;
        defer folder_data.deinit(allocator);
        for (self.files.items) |f| {
            names_size += f.name.len + 1;
            try folder_data.appendSlice(allocator, f.data);
        }

        const num_blocks = std.math.divCeil(
            usize,
            folder_data.items.len,
            max_block_size,
        ) catch unreachable;
        const files_size = self.files.items.len * @sizeOf(CfFileHeader) + names_size;
        const coff_files = @sizeOf(CfHeader) + @sizeOf(CfFolder);
        const coff_data = coff_files + files_size;
        const total_size = coff_data + num_blocks * @sizeOf(CfDataHeader) + folder_data.items.len;

        const header: CfHeader = .{
            .cbCabinet = std.math.cast(u32, total_size) orelse return error.CabinetTooLarge,
            .coffFiles = coff_files,
            .cFiles = std.math.cast(u16, self.files.items.len) orelse return error.TooManyFiles,
        };
        const folder: CfFolder = .{
            .coffCabStart = @intCast(coff_data),
            .cCFData = std.math.cast(u16, num_blocks) orelse return error.CabinetTooLarge,
        };

        var out: std.Io.Writer.Allocating = try .initCapacity(allocator, total_size);
        errdefer out.deinit();
        const w = &out.writer;
        try w.writeAll(mem.asBytes(&header));
        try w.writeAll(mem.asBytes(&folder));

        var folder_offset: u32 = 0;
        for (self.files.items) |f| {
            const file_header: CfFileHeader = .{
                .cbFile = @intCast(f.data.len),
                .uoffFolderStart = folder_offset,
            };
            try w.writeAll(mem.asBytes(&file_header));
            try w.writeAll(f.name);
            try w.writeByte(0);
            folder_offset += @intCast(f.data.len);
        }

        var blocks = mem.window(u8, folder_data.items, max_block_size, max_block_size);
        while (blocks.next()) |block| {
            const len: u16 = @intCast(block.len);
            var sizes: [4]u8 = undefined;
            mem.writeInt(u16, sizes[0..2], len, .little);
            mem.writeInt(u16, sizes[2..4], len, .little);
            const data_header: CfDataHeader = .{
                .csum = computeChecksum(&sizes, computeChecksum(block, 0)),
                .cbData = len,
                .cbUncomp = len,
            };
            try w.writeAll(mem.asBytes(&data_header));
            try w.writeAll(block);
        }
        return out.toOwnedSlice();
    }
};

const testing = std.testing;

test "checksum handles every tail length" {
    try testing.expectEqual(@as(u32, 0x04030201), computeChecksum(&.{ 1, 2, 3, 4 }, 0));
    try testing.expectEqual(@as(u32, 0x04030201 ^ 5), computeChecksum(&.{ 1, 2, 3, 4, 5 }, 0));
    try testing.expectEqual(
        @as(u32, 0x04030201 ^ 0x0506),
        computeChecksum(&.{ 1, 2, 3, 4, 5, 6 }, 0),
    );
    try testing.expectEqual(
        @as(u32, 0x04030201 ^ 0x050607),
        computeChecksum(&.{ 1, 2, 3, 4, 5, 6, 7 }, 0),
    );
    try testing.expectEqual(@as(u32, 0xFF), computeChecksum(&.{}, 0xFF));
}

test "multi-block cabinet is self-consistent" {
    const allocator = testing.allocator;
    var cab = Cabinet.init(allocator);
    defer cab.files.deinit(allocator);

    const big = try allocator.alloc(u8, 70000);
    defer allocator.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i);
    try cab.addFile("small.txt", "Hello World from Cabinet!");
    try cab.addFile("big.dat", big);

    const out = try cab.write(allocator);
    defer allocator.free(out);

    const header = mem.bytesToValue(CfHeader, out[0..@sizeOf(CfHeader)]);
    try testing.expectEqualSlices(u8, &mscf_magic, &header.signature);
    try testing.expectEqual(out.len, header.cbCabinet);
    try testing.expectEqual(@as(u16, 2), header.cFiles);

    const folder = mem.bytesToValue(CfFolder, out[@sizeOf(CfHeader)..][0..@sizeOf(CfFolder)]);
    try testing.expectEqual(@as(u16, 3), folder.cCFData);

    // Walk the data blocks, verifying checksums and reassembling the folder.
    var folder_bytes: std.ArrayList(u8) = .empty;
    defer folder_bytes.deinit(allocator);
    var offset: usize = folder.coffCabStart;
    for (0..folder.cCFData) |_| {
        const dh = mem.bytesToValue(CfDataHeader, out[offset..][0..@sizeOf(CfDataHeader)]);
        const block = out[offset + @sizeOf(CfDataHeader) ..][0..dh.cbData];
        try testing.expectEqual(dh.cbData, dh.cbUncomp);
        const expected_csum = computeChecksum(out[offset + 4 ..][0..4], computeChecksum(block, 0));
        try testing.expectEqual(dh.csum, expected_csum);
        try folder_bytes.appendSlice(allocator, block);
        offset += @sizeOf(CfDataHeader) + block.len;
    }
    try testing.expectEqual(out.len, offset);
    try testing.expectEqualStrings("Hello World from Cabinet!", folder_bytes.items[0..25]);
    try testing.expectEqualSlices(u8, big, folder_bytes.items[25..]);
}

test "empty cabinet is valid" {
    const allocator = testing.allocator;
    var cab = Cabinet.init(allocator);
    const out = try cab.write(allocator);
    defer allocator.free(out);
    try testing.expectEqual(@as(usize, @sizeOf(CfHeader) + @sizeOf(CfFolder)), out.len);
    try testing.expectEqual(out.len, mem.readInt(u32, out[8..12], .little));
}
