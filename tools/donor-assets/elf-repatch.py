#!/usr/bin/env python3
"""ELF repatcher — rewrite a hardcoded prefix baked into Termux's bootstrap.

WHY THIS EXISTS
----------------
Every ELF binary and shared library in a stock Termux bootstrap was linked
against the sysroot `/data/data/com.termux/files/usr`. Two places in the ELF
carry that path as a literal, load-bearing string:

  1. PT_INTERP  — the dynamic loader path for an executable (e.g.
     `/data/data/com.termux/files/usr/lib/ld-android.so` on the ABIs where
     Termux's toolchain sets one — not all of them do, and this script does
     not care which; it patches whatever it finds).
  2. DT_RUNPATH / DT_RPATH — the dynamic section's library search path
     (`/data/data/com.termux/files/usr/lib`), consulted by the ELF loader for
     every DT_NEEDED entry that isn't found elsewhere first.

Godwall's own userland lives at `/data/local/tmp/godwall/usr` (see
docs/LINUX-SUBSYSTEM.md for why: API 29 W^X makes the app's own data dir
non-executable for files the app writes, so the prefix has to be somewhere
writable AND executable, and /data/local/tmp — owned by uid 2000 — is that
place). Move the prefix without rewriting these two fields and the loader
looks for its interpreter and its libraries in a path that no longer holds
them: nothing execs, nothing links. This tool makes that rewrite exact.

WHY PROGRAM HEADERS, NOT SECTION HEADERS
------------------------------------------
Section headers are linker/debugger metadata; a binary that has been fully
stripped of them still runs, because the OS loader and the dynamic linker
never consult them — only the program header table (PT_INTERP, PT_LOAD,
PT_DYNAMIC) and the dynamic section it points to. Driving this patcher off
section headers would break on any bootstrap package stripped that way. So
every lookup below — including translating DT_STRTAB's virtual address into
a file offset — walks program headers only, the same information the loader
itself uses. If it works for the loader, it works for this tool.

WHY IN-PLACE, NEVER GROWING A STRING
--------------------------------------
An ELF string table entry is a null-terminated run of bytes at a fixed file
offset that other structures point to *by that offset*. There is no free
space to grow into: extending a string would either overwrite the start of
the next string or require moving everything after it, which shifts every
subsequent file offset in the ELF and is a full relink, not a patch. Godwall
sidesteps the problem by construction: `/data/local/tmp/godwall/usr` (27
bytes) is shorter than `/data/data/com.termux/files/usr` (32 bytes), so the
new path always fits in the old string's byte budget with room to null-pad.
This tool enforces that as a hard precondition and refuses to run backwards
(new prefix longer than old) rather than silently truncating or corrupting a
shared string table.

USAGE
-----
  elf-repatch.py --old-prefix /data/data/com.termux/files/usr \\
                  --new-prefix /data/local/tmp/godwall/usr \\
                  [--dry-run] [--verbose] \\
                  <file-or-directory> [...]

Directories are walked recursively. Every regular file is inspected; ELF
files are patched at PT_INTERP and DT_RUNPATH/DT_RPATH, and as a convenience
this tool also rewrites `#!`-shebang lines in plain-text scripts, because a
bootstrap ships both — a busybox applet with a bad RUNPATH and a `pip`
wrapper with a bad shebang fail the exact same way, "nothing loads".

Exit status is nonzero if any match was found that did not fit the
new-prefix budget, or if any file could not be parsed as claimed. A partial,
half-patched binary is worse than a build that stops and says why, so this
tool never continues past an error it can't account for.
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
from dataclasses import dataclass, field

ELF_MAGIC = b"\x7fELF"

PT_INTERP = 3
PT_LOAD = 1
PT_DYNAMIC = 2

DT_NULL = 0
DT_STRTAB = 5
DT_RPATH = 15
DT_RUNPATH = 29


class PatchError(Exception):
    """A file claimed to be ELF but could not be safely patched."""


@dataclass
class FileReport:
    path: str
    is_elf: bool = False
    interp_patched: bool = False
    runpath_patched: bool = False
    shebang_patched: bool = False
    skipped_reason: str = ""


@dataclass
class Summary:
    scanned: int = 0
    elf_files: int = 0
    patched: int = 0
    unchanged: int = 0
    errors: list = field(default_factory=list)


def _read_cstring(buf: bytes, offset: int) -> bytes:
    end = buf.index(b"\x00", offset)
    return buf[offset:end]


def _replace_cstring_in_place(
    buf: bytearray, offset: int, max_len: int, old: bytes, new_full: bytes, what: str,
) -> None:
    """Overwrite the null-terminated string at `offset` with `new_full`.

    `max_len` is the budget available WITHOUT disturbing whatever follows
    (a segment's p_filesz for PT_INTERP, or "up to the original null
    terminator" for a string-table entry). Refuses, loudly, if the
    replacement does not fit — see the module docstring for why this can
    never be "just truncate it".
    """
    if len(new_full) + 1 > max_len:
        raise PatchError(
            f"{what}: replacement {new_full!r} ({len(new_full) + 1} bytes incl. "
            f"NUL) does not fit the original {max_len}-byte budget at offset "
            f"{offset:#x} — refusing to truncate a loader path"
        )
    buf[offset : offset + len(new_full)] = new_full
    # NUL-terminate, then zero the vacated tail so no stale suffix of the old
    # path is readable by anything that (incorrectly) walked past the NUL.
    pad_start = offset + len(new_full)
    pad_end = offset + max_len
    buf[pad_start:pad_end] = b"\x00" * (pad_end - pad_start)


class ElfFile:
    """Minimal ELF32/ELF64 program-header walker — just enough to find
    PT_INTERP and PT_DYNAMIC and translate a virtual address to a file
    offset via PT_LOAD. Not a general ELF library on purpose."""

    def __init__(self, buf: bytearray, path: str):
        self.buf = buf
        self.path = path
        if buf[:4] != ELF_MAGIC:
            raise PatchError(f"{path}: not an ELF file (bad magic)")
        ei_class = buf[4]
        ei_data = buf[5]
        if ei_class not in (1, 2):
            raise PatchError(f"{path}: unknown EI_CLASS {ei_class}")
        if ei_data not in (1, 2):
            raise PatchError(f"{path}: unknown EI_DATA {ei_data}")
        self.is64 = ei_class == 2
        self.endian = "<" if ei_data == 1 else ">"
        self._parse_header()
        self._parse_program_headers()

    def _parse_header(self) -> None:
        e = self.endian
        if self.is64:
            # e_ident(16) e_type(H) e_machine(H) e_version(I) e_entry(Q)
            # e_phoff(Q) e_shoff(Q) e_flags(I) e_ehsize(H) e_phentsize(H)
            # e_phnum(H) e_shentsize(H) e_shnum(H) e_shstrndx(H)
            fmt = e + "16xHHIQQQIHHHHHH"
            size = struct.calcsize(fmt)
            (_, _, _, _, phoff, shoff, _, _, phentsize, phnum,
             shentsize, shnum, shstrndx) = struct.unpack_from(fmt, self.buf, 0)
        else:
            fmt = e + "16xHHIIIIIHHHHHH"
            size = struct.calcsize(fmt)
            (_, _, _, _, phoff, shoff, _, _, phentsize, phnum,
             shentsize, shnum, shstrndx) = struct.unpack_from(fmt, self.buf, 0)
        if len(self.buf) < size:
            raise PatchError(f"{self.path}: truncated ELF header")
        self.phoff, self.phentsize, self.phnum = phoff, phentsize, phnum

    def _parse_program_headers(self) -> None:
        e = self.endian
        self.segments = []  # list of dict: type, offset, filesz, vaddr, memsz
        for i in range(self.phnum):
            off = self.phoff + i * self.phentsize
            if self.is64:
                # p_type(I) p_flags(I) p_offset(Q) p_vaddr(Q) p_paddr(Q)
                # p_filesz(Q) p_memsz(Q) p_align(Q)
                p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _align = (
                    struct.unpack_from(e + "IIQQQQQQ", self.buf, off)
                )
            else:
                # p_type(I) p_offset(I) p_vaddr(I) p_paddr(I) p_filesz(I)
                # p_memsz(I) p_flags(I) p_align(I)
                p_type, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _flags, _align = (
                    struct.unpack_from(e + "IIIIIIII", self.buf, off)
                )
            self.segments.append(dict(
                type=p_type, offset=p_offset, vaddr=p_vaddr,
                filesz=p_filesz, memsz=p_memsz,
            ))

    def interp_segment(self):
        for seg in self.segments:
            if seg["type"] == PT_INTERP:
                return seg
        return None

    def dynamic_segment(self):
        for seg in self.segments:
            if seg["type"] == PT_DYNAMIC:
                return seg
        return None

    def vaddr_to_offset(self, vaddr: int) -> int:
        for seg in self.segments:
            if seg["type"] != PT_LOAD:
                continue
            if seg["vaddr"] <= vaddr < seg["vaddr"] + seg["memsz"]:
                return seg["offset"] + (vaddr - seg["vaddr"])
        raise PatchError(f"{self.path}: vaddr {vaddr:#x} not covered by any PT_LOAD segment")

    def dynamic_entries(self):
        """Yield (index, tag, val, entry_file_offset) for each PT_DYNAMIC entry."""
        seg = self.dynamic_segment()
        if seg is None:
            return
        e = self.endian
        entsize = 16 if self.is64 else 8
        count = seg["filesz"] // entsize
        for i in range(count):
            off = seg["offset"] + i * entsize
            if self.is64:
                tag, val = struct.unpack_from(e + "qQ", self.buf, off)
            else:
                tag, val = struct.unpack_from(e + "iI", self.buf, off)
            if tag == DT_NULL:
                return
            yield i, tag, val, off


def patch_interp(elf: ElfFile, old: bytes, new: bytes, report: FileReport) -> None:
    seg = elf.interp_segment()
    if seg is None:
        return
    raw = bytes(elf.buf[seg["offset"] : seg["offset"] + seg["filesz"]])
    current = _read_cstring(raw, 0) if b"\x00" in raw else raw
    if not current.startswith(old):
        return
    new_full = new + current[len(old):]
    _replace_cstring_in_place(
        elf.buf, seg["offset"], seg["filesz"], old, new_full,
        f"{elf.path}: PT_INTERP",
    )
    report.interp_patched = True


def patch_runpath(elf: ElfFile, old: bytes, new: bytes, report: FileReport) -> None:
    strtab_vaddr = None
    rpath_entries = []  # (val_offset_into_strtab, dyn_entry_file_offset, tag)
    for _i, tag, val, _off in elf.dynamic_entries():
        if tag == DT_STRTAB:
            strtab_vaddr = val
        elif tag in (DT_RPATH, DT_RUNPATH):
            rpath_entries.append((val, tag))
    if not rpath_entries:
        return
    if strtab_vaddr is None:
        raise PatchError(f"{elf.path}: has DT_RPATH/DT_RUNPATH but no DT_STRTAB")
    strtab_off = elf.vaddr_to_offset(strtab_vaddr)

    for str_index, tag in rpath_entries:
        entry_off = strtab_off + str_index
        raw_tail = bytes(elf.buf[entry_off : entry_off + 4096])
        if b"\x00" not in raw_tail:
            raise PatchError(f"{elf.path}: RPATH/RUNPATH string at {entry_off:#x} has no NUL within 4096 bytes")
        current = _read_cstring(bytes(elf.buf), entry_off)
        if not current.startswith(old):
            continue
        new_full = new + current[len(old):]
        budget = len(current) + 1  # up to and including the original NUL
        tag_name = "DT_RUNPATH" if tag == DT_RUNPATH else "DT_RPATH"
        _replace_cstring_in_place(
            elf.buf, entry_off, budget, old, new_full,
            f"{elf.path}: {tag_name}",
        )
        report.runpath_patched = True


def patch_shebang(buf: bytes, old: bytes, new: bytes) -> bytes | None:
    """Rewrite a `#!<old-prefix>/...` shebang line. Not ELF, no size limit —
    scripts aren't a fixed-layout format, so the whole file is rewritten."""
    if not buf.startswith(b"#!"):
        return None
    nl = buf.find(b"\n")
    first_line = buf[: nl if nl != -1 else len(buf)]
    if old not in first_line:
        return None
    patched_line = first_line.replace(old, new, 1)
    rest = buf[nl:] if nl != -1 else b""
    return patched_line + rest


def process_file(path: str, old: bytes, new: bytes, dry_run: bool, verbose: bool) -> FileReport:
    report = FileReport(path=path)
    with open(path, "rb") as f:
        original = f.read()

    if original[:4] == ELF_MAGIC:
        report.is_elf = True
        buf = bytearray(original)
        try:
            elf = ElfFile(buf, path)
            patch_interp(elf, old, new, report)
            patch_runpath(elf, old, new, report)
        except PatchError:
            raise
        if bytes(buf) != original and not dry_run:
            with open(path, "wb") as f:
                f.write(buf)
        return report

    patched = patch_shebang(original, old, new)
    if patched is not None:
        report.shebang_patched = True
        if not dry_run:
            with open(path, "wb") as f:
                f.write(patched)
    else:
        report.skipped_reason = "no match"
    return report


def iter_regular_files(paths: list[str]):
    for p in paths:
        if os.path.islink(p):
            continue
        if os.path.isfile(p):
            yield p
        elif os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
                for name in files:
                    fp = os.path.join(root, name)
                    if not os.path.islink(fp):
                        yield fp


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--old-prefix", required=True)
    parser.add_argument("--new-prefix", required=True)
    parser.add_argument("--dry-run", action="store_true", help="report what would change; write nothing")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("paths", nargs="+", help="files or directories to patch")
    args = parser.parse_args(argv)

    old = args.old_prefix.encode("ascii")
    new = args.new_prefix.encode("ascii")
    if len(new) > len(old):
        print(
            f"error: new prefix ({len(new)} bytes, '{args.new_prefix}') is longer than "
            f"old prefix ({len(old)} bytes, '{args.old_prefix}') — an ELF string table "
            "entry cannot grow in place; this tool only shrinks or holds steady",
            file=sys.stderr,
        )
        return 2

    summary = Summary()
    for path in iter_regular_files(args.paths):
        summary.scanned += 1
        try:
            report = process_file(path, old, new, args.dry_run, args.verbose)
        except PatchError as exc:
            summary.errors.append(str(exc))
            print(f"error: {exc}", file=sys.stderr)
            continue
        if report.is_elf:
            summary.elf_files += 1
        changed = report.interp_patched or report.runpath_patched or report.shebang_patched
        if changed:
            summary.patched += 1
            if args.verbose:
                bits = []
                if report.interp_patched:
                    bits.append("PT_INTERP")
                if report.runpath_patched:
                    bits.append("DT_RUNPATH/DT_RPATH")
                if report.shebang_patched:
                    bits.append("shebang")
                print(f"patched {path}: {', '.join(bits)}")
        else:
            summary.unchanged += 1

    verb = "would patch" if args.dry_run else "patched"
    print(
        f"\n{summary.scanned} files scanned, {summary.elf_files} ELF, "
        f"{summary.patched} {verb}, {summary.unchanged} unchanged, "
        f"{len(summary.errors)} errors"
    )
    return 1 if summary.errors else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
