//! Compound File Binary Format (MS-CFB v3) writer and verification reader.
//!
//! An `.msi` package is an OLE Compound File containing a single flat root
//! storage (`Root Entry`) whose children are the database table streams, the
//! `\x05SummaryInformation` property set stream, the embedded cabinet stream,
//! and any icon streams.
//!
//! Disk layout emitted by `CompoundFile.write`:
//! 1. 512-byte `CfbfHeader` ( precedes sector 0; carries the first 109 DIFAT entries).
//! 2. Mini stream sectors (holds concatenated 64-byte mini-sectors for all streams
//!    smaller than `mini_stream_cutoff` = 4096 bytes).
//! 3. Mini-FAT sectors (allocation table for 64-byte mini-sectors).
//! 4. Directory sectors (128-byte `DirEntry` records organized as a balanced
//!    red-black binary search tree under `Root Entry`).
//! 5. Regular stream sectors (for streams of 4096 bytes or larger).
//! 6. FAT sectors (allocation table for 512-byte sectors).
//! 7. DIFAT sectors (only present when the file requires more than 109 FAT sectors).
//!
//! Because every stream and table is allocated as a single contiguous run of
//! sectors via `allocChain`, stream data can be copied directly into its target
//! sector range without scattering writes across fragmented chains.

const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const Allocator = mem.Allocator;

comptime {
    std.debug.assert(builtin.cpu.arch.endian() == .little);
}

/// Size in bytes of a regular CFBF v3 sector (`1 << 9` = 512).
pub const sector_size: usize = 512;

/// Size in bytes of a mini-sector inside the mini stream (`1 << 6` = 64).
pub const mini_sector_size: usize = 64;

/// Streams strictly smaller than 4096 bytes are stored in the root entry's mini
/// stream rather than occupying full 512-byte sectors.
pub const mini_stream_cutoff: usize = 4096;

/// Number of 32-bit sector IDs that fit in one 512-byte FAT or DIFAT sector (128).
const entries_per_sector = sector_size / 4;

/// Number of FAT sector IDs stored directly inside the 512-byte `CfbfHeader`.
const header_difat_entries = 109;

/// Maximum number of UTF-16 code units in a directory entry name (excluding the
/// mandatory terminating NUL code unit, which brings the field to 32 `u16`s).
const max_name_units = 31;

/// Reserved sector IDs and directory stream IDs.
pub const Sector = struct {
    /// Unallocated sector marker.
    pub const free: u32 = 0xFFFFFFFF;
    /// Final sector marker in an allocation chain.
    pub const end_of_chain: u32 = 0xFFFFFFFE;
    /// Sector occupied by the File Allocation Table.
    pub const fat: u32 = 0xFFFFFFFD;
    /// Sector occupied by the Double-Indirect File Allocation Table.
    pub const difat: u32 = 0xFFFFFFFC;
    /// Sentinel identifier indicating an empty child or sibling branch in a directory entry.
    pub const no_stream: u32 = 0xFFFFFFFF;
};

/// Directory entry type tag (`DirEntry.obj_type`).
pub const ObjectType = enum(u8) {
    unknown = 0,
    storage = 1,
    stream = 2,
    root = 5,
};

/// Signature at the start of every compound file (`\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1`).
pub const magic = [8]u8{ 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };

/// Standard class identifier (`{000C1084-0000-0000-C000-000000000046}`) identifying the
/// root storage as an installer database package.
pub const msi_root_clsid = [16]u8{
    0x84, 0x10, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
};

/// 128-byte MS-CFB directory entry (`DirEntry`) describing either `Root Entry`,
/// a child stream, or an unused directory slot.
pub const DirEntry = extern struct {
    /// UTF-16LE entry name padded with NULs.
    name: [32]u16 = @splat(0),
    /// Length of the entry name in bytes, including the terminating NUL `u16`
    /// (`(utf16_len + 1) * 2`), or 0 for an unused directory entry.
    name_len: u16 = 0,
    obj_type: ObjectType = .unknown,
    /// Red-black tree node color (`0` = red, `1` = black). Because `linkTree`
    /// builds a balanced binary search tree of minimum height, coloring every
    /// node black (`1`) satisfies the red-black equal-black-height invariant
    /// unless a reader insists on strictly alternating bottom-level red nodes
    /// (Windows `ole32.dll` accepts all-black balanced trees).
    color: u8 = 1,
    left_sibling: u32 = Sector.no_stream,
    right_sibling: u32 = Sector.no_stream,
    child: u32 = Sector.no_stream,
    clsid: [16]u8 = @splat(0),
    state_bits: u32 = 0,
    creation_time: [2]u32 = @splat(0),
    modified_time: [2]u32 = @splat(0),
    /// First sector of the stream (in the mini-stream for streams `< 4096` bytes,
    /// in the main file for larger streams, or the first sector of the mini-stream
    /// itself when `obj_type == .root`).
    starting_sector: u32 = Sector.end_of_chain,
    /// Size of the stream in bytes (for `Root Entry`, the byte length of the mini stream).
    stream_size: u64 = 0,

    /// Populates `name` and `name_len` from a UTF-16LE slice (without a trailing NUL),
    /// returning `error.StreamNameTooLong` if `name` exceeds 31 UTF-16 code units.
    fn setName(self: *DirEntry, name: []const u16) !void {
        if (name.len > max_name_units) return error.StreamNameTooLong;
        @memcpy(self.name[0..name.len], name);
        self.name_len = @intCast((name.len + 1) * 2);
    }
};

/// 512-byte MS-CFB v3 file header located at byte offset 0 of the compound file.
pub const CfbfHeader = extern struct {
    magic: [8]u8 = magic,
    clsid: [16]u8 = @splat(0),
    minor_version: u16 = 0x003E,
    major_version: u16 = 3,
    byte_order: u16 = 0xFFFE,
    /// Log2 of `sector_size` (`1 << 9 == 512`).
    sector_shift: u16 = 9,
    /// Log2 of `mini_sector_size` (`1 << 6 == 64`).
    mini_sector_shift: u16 = 6,
    reserved: [6]u8 = @splat(0),
    /// Must be 0 in CFBF v3 (only v4 tracks directory sector count in the header).
    num_dir_sectors: u32 = 0,
    num_fat_sectors: u32,
    first_dir_sector: u32,
    transaction_sig: u32 = 0,
    mini_stream_cutoff: u32 = mini_stream_cutoff,
    first_minifat_sector: u32,
    num_minifat_sectors: u32,
    first_difat_sector: u32,
    num_difat_sectors: u32,
    /// Sector numbers of the first 109 FAT sectors (`Sector.free` for unused slots).
    difat_entries: [header_difat_entries]u32 = @splat(Sector.free),
};

comptime {
    std.debug.assert(@sizeOf(DirEntry) == 128);
    std.debug.assert(@sizeOf(CfbfHeader) == sector_size);
}

/// Compares two UTF-16LE directory entry names according to the MS-CFB specification
/// (Section 2.6.4): shorter names always sort before longer names, and names of
/// equal length are compared code-unit by code-unit after uppercasing characters.
///
/// Why this matters: Windows `ole32.dll` searches the directory binary search tree
/// using this exact ordering, so sorting by standard lexicographical order would
/// make streams invisible to Windows Installer.
pub fn entryNameCmp(a: []const u16, b: []const u16) std.math.Order {
    if (a.len != b.len) return std.math.order(a.len, b.len);
    for (a, b) |ca, cb| {
        const ua: u16 = if (ca < 128) std.ascii.toUpper(@intCast(ca)) else ca;
        const ub: u16 = if (cb < 128) std.ascii.toUpper(@intCast(cb)) else cb;
        if (ua != ub) return std.math.order(ua, ub);
    }
    return .eq;
}

/// A named binary stream queued for inclusion in a `CompoundFile`.
pub const Stream = struct {
    name: []const u16,
    data: []const u8,

    fn lessThan(_: void, a: Stream, b: Stream) bool {
        return entryNameCmp(a.name, b.name) == .lt;
    }
};

/// Returns the number of `unit`-sized sectors required to hold `len` bytes.
fn sectorsFor(len: usize, unit: usize) usize {
    return std.math.divCeil(usize, len, unit) catch unreachable;
}

/// Reserves a contiguous run of `count` sectors in `table` (a FAT or mini-FAT),
/// linking each sector to `sector + 1` and marking the last sector with
/// `Sector.end_of_chain`. Returns the starting sector index (or `Sector.end_of_chain`
/// when `count == 0`).
fn allocChain(table: *std.ArrayList(u32), allocator: Allocator, count: usize) !u32 {
    if (count == 0) return Sector.end_of_chain;
    const start: u32 = @intCast(table.items.len);
    for (1..count) |i| try table.append(allocator, start + @as(u32, @intCast(i)));
    try table.append(allocator, Sector.end_of_chain);
    return start;
}

/// Recursively links the pre-sorted slice `dir[lo..hi]` into a height-balanced
/// binary search tree via `left_sibling` and `right_sibling`, returning the
/// directory entry index of the subtree's root (or `Sector.no_stream` if empty).
fn linkTree(dir: []DirEntry, lo: usize, hi: usize) u32 {
    if (lo >= hi) return Sector.no_stream;
    const mid = lo + (hi - lo) / 2;
    dir[mid].left_sibling = linkTree(dir, lo, mid);
    dir[mid].right_sibling = linkTree(dir, mid + 1, hi);
    return @intCast(mid);
}

/// Returns the byte slice in the output file corresponding to `count` contiguous
/// 512-byte sectors beginning at sector number `start` (accounting for the
/// 512-byte `CfbfHeader` before sector 0).
fn sectorRegion(out: []u8, start: u32, count: usize) []u8 {
    return out[(1 + @as(usize, start)) * sector_size ..][0 .. count * sector_size];
}

/// Serializes `values` as little-endian `u32` entries into the `count` sectors
/// starting at `start`, pre-filling any trailing unused slots with `Sector.free`
/// (`0xFFFFFFFF`).
fn putU32s(out: []u8, start: u32, count: usize, values: []const u32) void {
    const region = sectorRegion(out, start, count);
    @memset(region, 0xFF);
    for (values, 0..) |v, i| mem.writeInt(u32, region[i * 4 ..][0..4], v, .little);
}

/// Builder for a CFBF v3 compound file containing a single flat root storage.
pub const CompoundFile = struct {
    allocator: Allocator,
    streams: std.ArrayList(Stream) = .empty,

    pub fn init(allocator: Allocator) CompoundFile {
        return .{ .allocator = allocator };
    }

    /// Registers a stream under `Root Entry`.
    ///
    /// Both `name` (UTF-16LE code units without a trailing NUL) and `data` are
    /// borrowed and must outlive the `write` call.
    pub fn addStream(self: *CompoundFile, name: []const u16, data: []const u8) !void {
        try self.streams.append(self.allocator, .{ .name = name, .data = data });
    }

    /// Serializes the compound file into a newly allocated byte slice owned by `allocator`.
    ///
    /// Returns `error.StreamNameTooLong` if any stream name exceeds 31 UTF-16 code
    /// units, or `error.DuplicateStreamName` if two streams compare equal under
    /// `entryNameCmp`.
    pub fn write(self: *const CompoundFile, allocator: Allocator) ![]u8 {
        const streams = try allocator.dupe(Stream, self.streams.items);
        defer allocator.free(streams);
        std.sort.block(Stream, streams, {}, Stream.lessThan);
        for (streams[0..streams.len -| 1], streams[1..]) |a, b| {
            if (entryNameCmp(a.name, b.name) == .eq) return error.DuplicateStreamName;
        }

        // Build the directory (`Root Entry` at index 0 followed by sorted stream
        // entries). Streams strictly smaller than 4096 bytes are packed into the
        // root entry's mini stream in 64-byte mini-sectors.
        var dir: std.ArrayList(DirEntry) = .empty;
        defer dir.deinit(allocator);
        var mini_data: std.ArrayList(u8) = .empty;
        defer mini_data.deinit(allocator);
        var minifat: std.ArrayList(u32) = .empty;
        defer minifat.deinit(allocator);

        var root: DirEntry = .{ .obj_type = .root, .clsid = msi_root_clsid };
        try root.setName(std.unicode.utf8ToUtf16LeStringLiteral("Root Entry"));
        try dir.append(allocator, root);

        for (streams) |s| {
            var entry: DirEntry = .{ .obj_type = .stream, .stream_size = s.data.len };
            try entry.setName(s.name);
            if (s.data.len > 0 and s.data.len < mini_stream_cutoff) {
                const count = sectorsFor(s.data.len, mini_sector_size);
                entry.starting_sector = try allocChain(&minifat, allocator, count);
                try mini_data.appendSlice(allocator, s.data);
                try mini_data.appendNTimes(allocator, 0, count * mini_sector_size - s.data.len);
            }
            try dir.append(allocator, entry);
        }
        dir.items[0].child = linkTree(dir.items, 1, dir.items.len);

        // Allocate 512-byte sectors in file order: mini stream, mini-FAT,
        // directory, and large streams (>= 4096 bytes).
        var fat: std.ArrayList(u32) = .empty;
        defer fat.deinit(allocator);

        const mini_sectors = sectorsFor(mini_data.items.len, sector_size);
        dir.items[0].starting_sector = try allocChain(&fat, allocator, mini_sectors);
        dir.items[0].stream_size = mini_data.items.len;
        const minifat_sectors = sectorsFor(minifat.items.len * 4, sector_size);
        const minifat_start = try allocChain(&fat, allocator, minifat_sectors);
        const dir_sectors = sectorsFor(dir.items.len * @sizeOf(DirEntry), sector_size);
        const dir_start = try allocChain(&fat, allocator, dir_sectors);
        for (streams, dir.items[1..]) |s, *entry| {
            if (s.data.len >= mini_stream_cutoff) {
                const count = sectorsFor(s.data.len, sector_size);
                entry.starting_sector = try allocChain(&fat, allocator, count);
            }
        }

        // Compute the fixed point for FAT and DIFAT sector counts: the FAT must
        // include entries for its own sectors (`Sector.fat`) as well as any DIFAT
        // sectors (`Sector.difat`) needed when `num_fat > 109`. Each DIFAT sector
        // holds 127 FAT sector numbers plus 1 chaining pointer at the end.
        var num_fat: u32 = 1;
        var num_difat: u32 = 0;
        while (true) {
            const beyond_header = if (num_fat > header_difat_entries)
                num_fat - header_difat_entries
            else
                0;
            num_difat = @intCast(sectorsFor(beyond_header, entries_per_sector - 1));
            if (num_fat * entries_per_sector >= fat.items.len + num_fat + num_difat) break;
            num_fat += 1;
        }
        const fat_start: u32 = @intCast(fat.items.len);
        const difat_start = fat_start + num_fat;
        try fat.appendNTimes(allocator, Sector.fat, num_fat);
        try fat.appendNTimes(allocator, Sector.difat, num_difat);

        const out = try allocator.alloc(u8, (1 + fat.items.len) * sector_size);
        errdefer allocator.free(out);
        @memset(out, 0);

        var header: CfbfHeader = .{
            .num_fat_sectors = num_fat,
            .first_dir_sector = dir_start,
            .first_minifat_sector = minifat_start,
            .num_minifat_sectors = @intCast(minifat_sectors),
            .first_difat_sector = if (num_difat > 0) difat_start else Sector.end_of_chain,
            .num_difat_sectors = num_difat,
        };
        for (0..@min(num_fat, header_difat_entries)) |i| {
            header.difat_entries[i] = fat_start + @as(u32, @intCast(i));
        }
        @memcpy(out[0..sector_size], mem.asBytes(&header));

        for (0..num_difat) |k| {
            var entries: [entries_per_sector]u32 = @splat(Sector.free);
            for (entries[0 .. entries_per_sector - 1], 0..) |*e, j| {
                const fat_index = header_difat_entries + k * (entries_per_sector - 1) + j;
                if (fat_index < num_fat) e.* = fat_start + @as(u32, @intCast(fat_index));
            }
            entries[entries_per_sector - 1] = if (k + 1 < num_difat)
                difat_start + @as(u32, @intCast(k + 1))
            else
                Sector.end_of_chain;
            putU32s(out, difat_start + @as(u32, @intCast(k)), 1, &entries);
        }

        putU32s(out, fat_start, num_fat, fat.items);
        if (minifat_sectors > 0) putU32s(out, minifat_start, minifat_sectors, minifat.items);

        const dir_region = sectorRegion(out, dir_start, dir_sectors);
        const unused: DirEntry = .{ .color = 0, .starting_sector = 0 };
        for (0..dir_sectors * sector_size / @sizeOf(DirEntry)) |i| {
            const entry = if (i < dir.items.len) dir.items[i] else unused;
            const slot = dir_region[i * @sizeOf(DirEntry) ..][0..@sizeOf(DirEntry)];
            @memcpy(slot, mem.asBytes(&entry));
        }

        if (mini_sectors > 0) {
            const region = sectorRegion(out, dir.items[0].starting_sector, mini_sectors);
            @memcpy(region[0..mini_data.items.len], mini_data.items);
        }
        for (streams, dir.items[1..]) |s, entry| {
            if (s.data.len >= mini_stream_cutoff) {
                const count = sectorsFor(s.data.len, sector_size);
                const region = sectorRegion(out, entry.starting_sector, count);
                @memcpy(region[0..s.data.len], s.data);
            }
        }
        return out;
    }
};

/// Minimal MS-CFB v3 reader used by tests to verify that generated compound files
/// follow the specification and can be traversed via FAT, DIFAT, and mini-FAT chains.
pub const Reader = struct {
    data: []const u8,

    /// Looks up a stream named `name` (matched via `entryNameCmp`) and returns its
    /// contents in a newly allocated slice owned by `allocator`, or `null` if the
    /// buffer is not a valid CFBF header or contains no matching stream.
    pub fn readStream(self: Reader, allocator: Allocator, name: []const u16) !?[]u8 {
        if (self.data.len < sector_size or !mem.eql(u8, self.data[0..8], &magic)) return null;
        var arena_state = std.heap.ArenaAllocator.init(allocator);
        defer arena_state.deinit();
        const a = arena_state.allocator();

        const header = mem.bytesToValue(CfbfHeader, self.data[0..sector_size]);
        const fat = try self.readFat(a, header);
        const dir_bytes = try chain(
            a,
            self.data,
            sector_size,
            sector_size,
            fat,
            header.first_dir_sector,
            null,
        );

        var root: ?DirEntry = null;
        var found: ?DirEntry = null;
        var offset: usize = 0;
        while (offset + @sizeOf(DirEntry) <= dir_bytes.len) : (offset += @sizeOf(DirEntry)) {
            const entry = mem.bytesToValue(DirEntry, dir_bytes[offset..][0..@sizeOf(DirEntry)]);
            if (entry.obj_type == .root) root = entry;
            if (entry.obj_type == .stream and entry.name_len >= 2 and
                entry.name_len <= @sizeOf(@TypeOf(entry.name)) and entry.name_len % 2 == 0 and
                entryNameCmp(entry.name[0 .. entry.name_len / 2 - 1], name) == .eq)
            {
                found = entry;
                break;
            }
        }
        const entry = found orelse return null;
        const size = std.math.cast(usize, entry.stream_size) orelse return error.InvalidStreamSize;
        if (size == 0) return try allocator.alloc(u8, 0);

        const bytes = if (size >= mini_stream_cutoff)
            try chain(a, self.data, sector_size, sector_size, fat, entry.starting_sector, size)
        else blk: {
            const mini_start = (root orelse return null).starting_sector;
            const mini_stream = try chain(
                a,
                self.data,
                sector_size,
                sector_size,
                fat,
                mini_start,
                null,
            );
            const minifat_bytes = try chain(
                a,
                self.data,
                sector_size,
                sector_size,
                fat,
                header.first_minifat_sector,
                null,
            );
            const minifat = try a.alloc(u32, minifat_bytes.len / 4);
            for (minifat, 0..) |*e, i| {
                e.* = mem.readInt(u32, minifat_bytes[i * 4 ..][0..4], .little);
            }
            break :blk try chain(
                a,
                mini_stream,
                0,
                mini_sector_size,
                minifat,
                entry.starting_sector,
                size,
            );
        };
        return try allocator.dupe(u8, bytes);
    }

    /// Reads all streams stored under Root Entry, returning an allocated slice of
    /// `Stream` objects owned by `allocator`.
    pub fn readAllStreams(self: Reader, allocator: Allocator) ![]Stream {
        if (self.data.len < sector_size or !mem.eql(u8, self.data[0..8], &magic)) {
            return error.InvalidCfbfHeader;
        }
        var arena_state = std.heap.ArenaAllocator.init(allocator);
        defer arena_state.deinit();
        const a = arena_state.allocator();

        const header = mem.bytesToValue(CfbfHeader, self.data[0..sector_size]);
        const fat = try self.readFat(a, header);
        const dir_bytes = try chain(
            a,
            self.data,
            sector_size,
            sector_size,
            fat,
            header.first_dir_sector,
            null,
        );

        var list: std.ArrayList(Stream) = .empty;
        errdefer {
            for (list.items) |s| {
                allocator.free(s.name);
                allocator.free(s.data);
            }
            list.deinit(allocator);
        }

        var offset: usize = 0;
        while (offset + @sizeOf(DirEntry) <= dir_bytes.len) : (offset += @sizeOf(DirEntry)) {
            const entry = mem.bytesToValue(DirEntry, dir_bytes[offset..][0..@sizeOf(DirEntry)]);
            if (entry.obj_type == .stream and entry.name_len >= 2 and
                entry.name_len <= @sizeOf(@TypeOf(entry.name)) and entry.name_len % 2 == 0)
            {
                const u16_name = entry.name[0 .. entry.name_len / 2 - 1];
                const content = (try self.readStream(allocator, u16_name)) orelse continue;
                errdefer allocator.free(content);

                const name_copy = try allocator.dupe(u16, u16_name);
                errdefer allocator.free(name_copy);

                try list.append(allocator, .{ .name = name_copy, .data = content });
            }
        }

        return list.toOwnedSlice(allocator);
    }

    /// Reconstructs the complete File Allocation Table by walking the 109 header
    /// DIFAT slots followed by any chained DIFAT sectors.
    fn readFat(self: Reader, a: Allocator, header: CfbfHeader) ![]u32 {
        var fat_sectors: std.ArrayList(u32) = .empty;
        for (header.difat_entries) |s| if (s != Sector.free) try fat_sectors.append(a, s);
        var difat = header.first_difat_sector;
        var hops: usize = 0;
        const max_sectors = self.data.len / sector_size;
        while (difat != Sector.end_of_chain and difat != Sector.free) : (hops += 1) {
            if (hops > max_sectors) return error.InvalidChain;
            const sec = try self.sector(difat);
            for (0..entries_per_sector - 1) |i| {
                const s = mem.readInt(u32, sec[i * 4 ..][0..4], .little);
                if (s != Sector.free) try fat_sectors.append(a, s);
            }
            difat = mem.readInt(u32, sec[sector_size - 4 ..][0..4], .little);
        }

        const fat = try a.alloc(u32, fat_sectors.items.len * entries_per_sector);
        for (fat_sectors.items, 0..) |s, n| {
            const sec = try self.sector(s);
            for (0..entries_per_sector) |i| {
                fat[n * entries_per_sector + i] = mem.readInt(u32, sec[i * 4 ..][0..4], .little);
            }
        }
        return fat;
    }

    /// Returns the 512-byte slice for regular sector `n`, or `error.InvalidSector`
    /// if `n` points past the end of `self.data`.
    fn sector(self: Reader, n: u32) ![]const u8 {
        const start = (1 + @as(usize, n)) * sector_size;
        if (start + sector_size > self.data.len) return error.InvalidSector;
        return self.data[start..][0..sector_size];
    }
};

/// Follows a sector or mini-sector chain through `table` starting at `start` and
/// concatenates each `unit`-byte block from `source[base + n * unit ..]`.
///
/// When `size` is non-null, stops once `size` bytes have been gathered and
/// truncates the final sector's padding to `size`. Guards against cycles in
/// malformed tables by bounding the hop count to `table.len`.
fn chain(
    a: Allocator,
    source: []const u8,
    base: usize,
    unit: usize,
    table: []const u32,
    start: u32,
    size: ?usize,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var current = start;
    var hops: usize = 0;
    while (current != Sector.end_of_chain and
        (size == null or out.items.len < size.?)) : (hops += 1)
    {
        if (hops > table.len) return error.InvalidChain;
        const offset = base + @as(usize, current) * unit;
        if (offset + unit > source.len or current >= table.len) return error.InvalidChain;
        try out.appendSlice(a, source[offset..][0..unit]);
        current = table[current];
    }
    if (size) |s| {
        if (out.items.len < s) return error.InvalidChain;
        out.shrinkRetainingCapacity(s);
    }
    return out.items;
}

const testing = std.testing;

fn utf16(comptime s: []const u8) []const u16 {
    return std.unicode.utf8ToUtf16LeStringLiteral(s);
}

test "round trip of small, boundary and large streams" {
    const allocator = testing.allocator;
    var cf = CompoundFile.init(allocator);
    defer cf.streams.deinit(allocator);

    const small = "Hello, small stream in mini FAT!";
    const boundary = try allocator.alloc(u8, mini_stream_cutoff);
    defer allocator.free(boundary);
    @memset(boundary, 0x55);
    const large = try allocator.alloc(u8, 5000);
    defer allocator.free(large);
    @memset(large, 0x42);

    try cf.addStream(utf16("small"), small);
    try cf.addStream(utf16("empty"), "");
    try cf.addStream(utf16("boundary"), boundary);
    try cf.addStream(utf16("large"), large);

    const output = try cf.write(allocator);
    defer allocator.free(output);
    try testing.expectEqualSlices(u8, &magic, output[0..8]);
    try testing.expectEqual(@as(usize, 0), output.len % sector_size);

    const reader = Reader{ .data = output };
    const cases = [_]struct { []const u16, []const u8 }{
        .{ utf16("small"), small },
        .{ utf16("empty"), "" },
        .{ utf16("boundary"), boundary },
        .{ utf16("large"), large },
    };
    for (cases) |c| {
        const got = (try reader.readStream(allocator, c[0])).?;
        defer allocator.free(got);
        try testing.expectEqualSlices(u8, c[1], got);
    }
    try testing.expect(try reader.readStream(allocator, utf16("nope")) == null);
}

test "files needing DIFAT sectors round trip" {
    const allocator = testing.allocator;
    var cf = CompoundFile.init(allocator);
    defer cf.streams.deinit(allocator);

    // 8 MiB needs ~129 FAT sectors, more than the 109 the header can index.
    const big = try allocator.alloc(u8, 8 * 1024 * 1024);
    defer allocator.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i *% 2654435761 >> 7);
    try cf.addStream(utf16("big"), big);
    try cf.addStream(utf16("tail"), "after the big one");

    const output = try cf.write(allocator);
    defer allocator.free(output);
    const header = mem.bytesToValue(CfbfHeader, output[0..sector_size]);
    try testing.expect(header.num_fat_sectors > header_difat_entries);
    try testing.expect(header.num_difat_sectors > 0);

    const reader = Reader{ .data = output };
    const got = (try reader.readStream(allocator, utf16("big"))).?;
    defer allocator.free(got);
    try testing.expectEqualSlices(u8, big, got);
    const tail = (try reader.readStream(allocator, utf16("tail"))).?;
    defer allocator.free(tail);
    try testing.expectEqualStrings("after the big one", tail);
}

test "invalid input is rejected" {
    const allocator = testing.allocator;

    var cf = CompoundFile.init(allocator);
    defer cf.streams.deinit(allocator);
    const too_long = @as([32]u16, @splat('a'));
    try cf.addStream(&too_long, "x");
    try testing.expectError(error.StreamNameTooLong, cf.write(allocator));

    cf.streams.clearRetainingCapacity();
    try cf.addStream(utf16("dup"), "1");
    try cf.addStream(utf16("DUP"), "2");
    try testing.expectError(error.DuplicateStreamName, cf.write(allocator));

    var bad_magic: [sector_size + 8]u8 = @splat(0);
    bad_magic[0] = 0xFF;
    const bad_reader: Reader = .{ .data = &bad_magic };
    const short_reader: Reader = .{ .data = "too short" };
    try testing.expect(try bad_reader.readStream(allocator, utf16("x")) == null);
    try testing.expect(try short_reader.readStream(allocator, utf16("x")) == null);
}

test "entryNameCmp orders by length then case-insensitively" {
    try testing.expectEqual(std.math.Order.lt, entryNameCmp(utf16("abc"), utf16("abcd")));
    try testing.expectEqual(std.math.Order.gt, entryNameCmp(utf16("abcd"), utf16("abc")));
    try testing.expectEqual(std.math.Order.eq, entryNameCmp(utf16("abc"), utf16("ABC")));
    try testing.expectEqual(std.math.Order.lt, entryNameCmp(utf16("abc"), utf16("abd")));
}
