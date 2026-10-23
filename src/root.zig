//! Root library module for `swim`, exposing the building blocks of a Windows
//! Installer (`.msi`) package.
//!
//! Architecture overview:
//! - High-level assembly: `builder` validates a package configuration and
//!   orchestrates all lower-level encoders into a finished `.msi` image.
//! - Relational database: `table` implements the in-memory MSI database and its
//!   binary columnar serialization; `schema` defines standard MSI tables and
//!   action sequences; `ui` populates the installer wizard dialogs.
//! - Binary container formats: `cfbf` writes the outer OLE Compound File Binary
//!   Format (MS-CFB) container; `stream_name` mangles table and stream names;
//!   `summary_info` writes the OLE `\x05SummaryInformation` property stream
//!   (MS-OLEPS); `cab` packs payload files into an embedded MS-CAB archive.

const std = @import("std");

/// MSI compound-file stream name compression (`CompressStreamName`).
pub const stream_name = @import("stream_name.zig");
/// Compound File Binary Format (MS-CFB v3) container writer and test reader.
pub const cfbf = @import("cfbf.zig");
/// Microsoft Cabinet (MS-CAB) archive writer.
pub const cab = @import("cab.zig");
/// OLE `\x05SummaryInformation` property set stream writer and test reader.
pub const summary_info = @import("summary_info.zig");
/// In-memory MSI relational table model, string pool, and columnar serializer.
pub const table = @import("table.zig");
/// Standard Windows Installer table schemas and action sequence definitions.
pub const schema = @import("schema.zig");
/// High-level MSI package validator and builder.
pub const builder = @import("builder.zig");
/// Built-in Windows Installer UI wizard dialogs, controls, and RTF conversion.
pub const ui = @import("ui.zig");
/// Windows Authenticode code signing engine for MSI packages and PE binaries.
pub const authenticode = @import("authenticode.zig");

test {
    std.testing.refAllDecls(@This());
}
