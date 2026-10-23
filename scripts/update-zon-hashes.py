#!/usr/bin/env python3

"""Utility script to recalculate and update dependency hashes in build.zig.zon.

This script parses all `.url` fields under `.dependencies` in `build.zig.zon`, runs
`zig fetch <url>` to compute the expected cryptographic package hash, and updates the
corresponding `.hash` field if mismatched.
"""

import os
import re
import subprocess
import sys


def get_zig_binary() -> str:
    # Use ZIG environment variable if defined, otherwise check PATH
    return os.environ.get("ZIG", "zig")


def fetch_hash(zig_bin: str, url: str) -> str:
    res = subprocess.run([zig_bin, "fetch", url], capture_output=True, check=False, text=True)
    if res.returncode != 0:
        sys.stderr.write(f"Failed to fetch {url}:\n{res.stderr}\n")
        raise RuntimeError(f"zig fetch failed for {url}")
    # Output may contain warnings on stderr, but hash is on stdout
    output = res.stdout.strip().splitlines()
    if not output:
        raise RuntimeError(f"No hash returned by zig fetch for {url}")
    return output[-1].strip()


def update_build_zig_zon(file_path: str = "build.zig.zon") -> bool:
    if not os.path.isfile(file_path):
        sys.stderr.write(f"File not found: {file_path}\n")
        sys.exit(1)

    zig_bin = get_zig_binary()
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Pattern to match dependency blocks with url and hash:
    # .dep_name = .{
    #     .url = "...",
    #     .hash = "...",
    # },
    pattern = re.compile(
        r'(\.url\s*=\s*"(https?://[^"]+)",\s*\n\s*\.hash\s*=\s*")([^"]+)(")',
        re.MULTILINE,
    )

    modified = False

    def replacer(match: re.Match) -> str:
        nonlocal modified
        prefix = match.group(1)
        url = match.group(2)
        old_hash = match.group(3)
        suffix = match.group(4)

        sys.stdout.write(f"Checking dependency: {url}\n")
        new_hash = fetch_hash(zig_bin, url)

        if new_hash != old_hash:
            sys.stdout.write(f"Updating hash:\n  old: {old_hash}\n  new: {new_hash}\n")
            modified = True
            return f"{prefix}{new_hash}{suffix}"
        else:
            sys.stdout.write("Hash is up-to-date.\n")
            return match.group(0)

    new_content = pattern.sub(replacer, content)

    if modified:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(new_content)
        sys.stdout.write(f"Successfully updated {file_path}\n")
    else:
        sys.stdout.write("All dependency hashes in build.zig.zon are valid.\n")

    return modified


if __name__ == "__main__":
    zon_file = sys.argv[1] if len(sys.argv) > 1 else "build.zig.zon"
    update_build_zig_zon(zon_file)
