#!/usr/bin/env python3
import json
import os
import pathlib
import stat
import sys
import tarfile
import unicodedata
import zipfile


MAX_ENTRIES = 200_000
MAX_PATH = 4096
MAX_SOURCE_BYTES = 4096


def fail():
    raise ValueError("archive rejected")


def normalized(path):
    return unicodedata.normalize("NFC", path).casefold()


def safe_name(name):
    if not isinstance(name, str) or not name or len(name) > MAX_PATH:
        fail()
    if any(unicodedata.category(ch) in ("Cc", "Cf", "Cs") for ch in name) or "\\" in name or name.startswith("/"):
        fail()
    if name.endswith("/"):
        name = name[:-1]
    parts = name.split("/")
    if any(not part or part in (".", "..") for part in parts):
        fail()
    return parts


def read_outer(path, stage, max_bytes, scratch):
    required = {"sign": {"unsigned.tar.gz", "source.json"}, "finalize": {"signed.tar.gz", "verification.json"}}[stage]
    allowed = required | ({"template.dmg"} if stage == "sign" else set())
    with zipfile.ZipFile(path) as archive:
        items = archive.infolist()
        if not len(required) <= len(items) <= len(allowed) or len(items) > 4:
            fail()
        names = set()
        total = 0
        for item in items:
            parts = safe_name(item.filename)
            if len(parts) != 1 or item.is_dir():
                fail()
            mode = item.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if kind not in (0, stat.S_IFREG) or item.flag_bits & 1 or item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                fail()
            key = normalized(item.filename)
            if key in names:
                fail()
            names.add(key)
            if item.filename not in allowed or item.file_size < 0 or item.file_size > max_bytes:
                fail()
            if item.filename == "source.json" and item.file_size > MAX_SOURCE_BYTES:
                fail()
            total += item.file_size
            if total > max_bytes:
                fail()
        archive_names = {item.filename for item in items}
        if not required <= archive_names or archive_names - allowed:
            fail()
        selected = "unsigned.tar.gz" if stage == "sign" else "signed.tar.gz"
        target = os.path.join(scratch, selected)
        with archive.open(selected) as src, open(target, "xb") as dst:
            copied = 0
            while True:
                block = src.read(1024 * 1024)
                if not block:
                    break
                copied += len(block)
                if copied > max_bytes:
                    fail()
                dst.write(block)
        if copied != archive.getinfo(selected).file_size:
            fail()
        if stage == "sign":
            source_bytes = bytearray()
            with archive.open("source.json") as src, open(os.path.join(scratch, "source.json"), "xb") as dst:
                copied = 0
                while True:
                    block = src.read(4096)
                    if not block:
                        break
                    copied += len(block)
                    if copied > MAX_SOURCE_BYTES:
                        fail()
                    source_bytes.extend(block)
                    dst.write(block)
            if copied != archive.getinfo("source.json").file_size:
                fail()
            try:
                json.loads(source_bytes.decode("utf-8"), object_pairs_hook=unique_object)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                fail()
        return target


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail()
        result[key] = value
    return result


def unpack_tar(archive_path, destination, bundle_name, max_bytes):
    root = os.path.abspath(destination)
    os.makedirs(root, mode=0o700, exist_ok=True)
    entries = []
    seen = set()
    spellings = {}
    total = 0
    with tarfile.open(archive_path, "r|gz") as archive:
        for member in archive:
            if len(entries) >= MAX_ENTRIES:
                fail()
            parts = safe_name(member.name)
            if parts[0] != bundle_name:
                fail()
            normalized_path = normalized("/".join(parts))
            if normalized_path in seen:
                fail()
            seen.add(normalized_path)
            for index in range(1, len(parts) + 1):
                raw_prefix = "/".join(parts[:index])
                key_prefix = normalized(raw_prefix)
                if key_prefix in spellings and spellings[key_prefix] != raw_prefix:
                    fail()
                spellings[key_prefix] = raw_prefix
            if not (member.isdir() or member.isfile() or member.issym()):
                fail()
            if member.isfile():
                if member.size < 0:
                    fail()
                total += member.size
                if total > max_bytes:
                    fail()
            if member.issym():
                target = member.linkname
                if not target or target.startswith("/") or "\\" in target or any(unicodedata.category(ch) in ("Cc", "Cf", "Cs") for ch in target):
                    fail()
                resolved = pathlib.PurePosixPath(*parts[:-1], target)
                stack = []
                for part in resolved.parts:
                    if part in ("", "."):
                        continue
                    if part == "..":
                        if not stack:
                            fail()
                        stack.pop()
                    else:
                        stack.append(part)
                if not stack or stack[0] != bundle_name:
                    fail()
            try:
                filtered = tarfile.data_filter(member, root)
                if filtered.name != member.name or filtered.linkname != member.linkname:
                    fail()
            except (OSError, tarfile.TarError):
                fail()
            entries.append((member, parts))
        if not entries or not any(len(parts) == 1 and member.isdir() for member, parts in entries):
            fail()

    with tarfile.open(archive_path, "r|gz") as archive:
        for member in archive:
            parts = safe_name(member.name)
            target = os.path.abspath(os.path.join(root, *parts))
            if os.path.commonpath((root, target)) != root:
                fail()
            if member.isdir():
                os.makedirs(target, mode=0o700, exist_ok=True)
            elif member.isfile():
                os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
                stream = archive.extractfile(member)
                if stream is None:
                    fail()
                with stream, open(target, "xb") as output:
                    remaining = member.size
                    while remaining:
                        block = stream.read(min(1024 * 1024, remaining))
                        if not block:
                            fail()
                        output.write(block)
                        remaining -= len(block)

    for member, parts in entries:
        if member.issym():
            target = os.path.abspath(os.path.join(root, *parts))
            os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
            os.symlink(member.linkname, target)
    for member, parts in sorted(entries, key=lambda item: len(item[1]), reverse=True):
        target = os.path.abspath(os.path.join(root, *parts))
        if member.isdir() and os.path.isdir(target) and not os.path.islink(target):
            os.chmod(target, 0o755)
        elif member.isfile():
            os.chmod(target, 0o755 if member.mode & 0o111 else 0o644)
    return total


def main():
    if sys.version_info < (3, 12):
        fail()
    config = json.loads(sys.argv[1])
    archive_path, scratch = sys.argv[2], sys.argv[3]
    outer = read_outer(archive_path, config["stage"], config["max_artifact_bytes"], scratch)
    expanded = unpack_tar(outer, config["destination"], config["bundle_name"], config["max_unpacked_bytes"])
    print(json.dumps({"archive": outer, "unpacked_bytes": expanded}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("archive rejected", file=sys.stderr)
        sys.exit(2)
