import json
import os
import pathlib
import stat
import sys
import zipfile

from unpack import MAX_ENTRIES, normalized, safe_name


def fail():
    raise ValueError('disk image archive rejected')


def selected_file(archive_path, destination, selected, required, allowed, maximum):
    with zipfile.ZipFile(archive_path) as archive:
        items = archive.infolist()
        if len(items) > len(allowed):
            fail()
        names = set()
        total = 0
        for item in items:
            if len(safe_name(item.filename)) != 1 or item.filename not in allowed or item.filename in names:
                fail()
            names.add(item.filename)
            kind = stat.S_IFMT(item.external_attr >> 16)
            if item.is_dir() or kind not in (0, stat.S_IFREG) or item.flag_bits & 1:
                fail()
            if item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                fail()
            total += item.file_size
            if item.file_size < 0 or total > maximum:
                fail()
        if not required <= names or selected not in names:
            fail()
        with archive.open(selected) as source, open(destination, 'xb') as target:
            length = 0
            for block in iter(lambda: source.read(1024 * 1024), b''):
                length += len(block)
                if length > maximum:
                    fail()
                target.write(block)
        if length != archive.getinfo(selected).file_size:
            fail()


def inspect_product(archive_path, bundle_name, maximum):
    total = 0
    seen = set()
    ancestors = set()
    nondirectories = set()
    spellings = {}
    with zipfile.ZipFile(archive_path, metadata_encoding='utf-8') as archive:
        items = archive.infolist()
        if not items or len(items) > MAX_ENTRIES:
            fail()
        for item in items:
            parts = safe_name(item.filename)
            if parts[0] == '__MACOSX':
                if len(parts) > 1 and parts[1] not in (bundle_name, '._' + bundle_name):
                    fail()
            elif parts[0] != bundle_name:
                fail()
            key = normalized('/'.join(parts))
            if key in seen or item.flag_bits & 1:
                fail()
            seen.add(key)
            for index in range(1, len(parts) + 1):
                prefix = '/'.join(parts[:index])
                folded = normalized(prefix)
                if folded in spellings and spellings[folded] != prefix:
                    fail()
                spellings[folded] = prefix
            total += item.file_size
            if item.file_size < 0 or total > maximum:
                fail()
            kind = stat.S_IFMT(item.external_attr >> 16)
            if kind not in (0, stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK):
                fail()
            if item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                fail()
            if not item.is_dir():
                nondirectories.add(key)
            for index in range(1, len(parts)):
                ancestors.add(normalized('/'.join(parts[:index])))
            if kind == stat.S_IFLNK:
                if parts[0] != bundle_name or item.file_size > 4096:
                    fail()
                target = archive.read(item).decode('utf-8', errors='strict')
                if not target or target.startswith('/') or '\\' in target:
                    fail()
                stack = parts[:-1].copy()
                for part in pathlib.PurePosixPath(target).parts:
                    if part in ('', '.'):
                        continue
                    if part == '..':
                        if len(stack) <= 1:
                            fail()
                        stack.pop()
                    else:
                        safe_name(part)
                        stack.append(part)
                if not stack or stack[0] != bundle_name:
                    fail()
        if nondirectories & ancestors or not any(name.startswith(normalized(bundle_name) + '/') for name in seen):
            fail()


def main():
    if sys.version_info < (3, 12):
        fail()
    config = json.loads(sys.argv[1])
    source, destination = sys.argv[2:4]
    mode = config['mode']
    if mode == 'template':
        selected_file(source, destination, 'template.dmg', {'unsigned.tar.gz', 'source.json', 'template.dmg'}, {'unsigned.tar.gz', 'source.json', 'template.dmg'}, config['max_bytes'])
    elif mode == 'product':
        selected_file(source, destination, 'product.zip', {'product.zip', 'verification.json'}, {'product.zip', 'verification.json'}, config['max_bytes'])
        inspect_product(destination, config['bundle_name'], config['max_unpacked_bytes'])
    elif mode == 'signed':
        selected_file(source, destination, 'signed.dmg', {'signed.dmg', 'verification.json'}, {'signed.dmg', 'verification.json'}, config['max_bytes'])
    else:
        fail()


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('disk image archive rejected', file=sys.stderr)
        sys.exit(2)
