"""Bounded, non-executing evidence collection. No target imports or network."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import signal
import stat
import sys
import time
import unicodedata
from urllib.parse import unquote_to_bytes

MIB = 1024 * 1024
DEFAULTS = {
    "entries": 10_000,
    "file_bytes": 5 * MIB,
    "total_bytes": 100 * MIB,
    "layers": 3,
    "decoded_bytes": 5 * MIB,
    "seconds": 60,
}


class EvidenceError(ValueError):
    pass


class LimitReached(EvidenceError):
    pass


def signature(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class Inspector:
    def __init__(self, root: str, limits: dict[str, int] | None = None):
        self.limits = dict(DEFAULTS)
        if limits:
            if set(limits) - set(DEFAULTS):
                raise EvidenceError("unknown limit")
            self.limits.update(limits)
        if any(not isinstance(v, int) or isinstance(v, bool) or v <= 0
               or v > DEFAULTS[k] for k, v in self.limits.items()):
            raise EvidenceError("limits must be positive integers no greater than defaults")
        self.started = time.monotonic()
        self.entries = 0
        self.bytes_read = 0
        self.items: list[dict] = []
        self.diagnostics: list[str] = []
        self.partial = False
        self.root_fd = -1
        if (not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY")
                or os.open not in os.supports_dir_fd
                or os.stat not in os.supports_dir_fd
                or os.stat not in os.supports_follow_symlinks
                or os.scandir not in os.supports_fd):
            raise EvidenceError("POSIX no-follow descriptor-relative access is required")
        self.root_fd = self._root(root)
        self.device = os.fstat(self.root_fd).st_dev

    def _root(self, root: str) -> int:
        if not root.startswith("/") or ".." in root.split("/"):
            raise EvidenceError("root must be absolute without parent traversal")
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for component in PurePosixPath(root).parts[1:]:
                self.check_time()
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def close(self) -> None:
        if self.root_fd >= 0:
            os.close(self.root_fd)
            self.root_fd = -1

    def check_time(self) -> None:
        if time.monotonic() - self.started >= self.limits["seconds"]:
            raise LimitReached("helper deadline reached")

    def skip(self, path: str, reason: str) -> None:
        self.partial = True
        self.items.append({"path": path, "status": "skipped", "reason": reason})

    def _read(self, parent: int, name: str) -> bytes:
        self.check_time()
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            raise EvidenceError("not a regular file (links and special files are refused)")
        if before.st_nlink != 1:
            raise EvidenceError("multiply linked file refused")
        if before.st_dev != self.device:
            raise EvidenceError("cross-device file refused")
        if before.st_size > self.limits["file_bytes"]:
            raise LimitReached("file byte limit reached")
        if before.st_size > self.limits["total_bytes"] - self.bytes_read:
            raise LimitReached("total inspected byte limit reached")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            opened = os.fstat(fd)
            if signature(opened) != signature(before):
                raise EvidenceError("file changed before opening")
            chunks = []
            remaining = before.st_size
            while remaining:
                self.check_time()
                chunk = os.read(fd, min(remaining, 64 * 1024))
                if not chunk:
                    raise EvidenceError("file shortened during reading")
                self.bytes_read += len(chunk)
                chunks.append(chunk)
                remaining -= len(chunk)
            self.check_time()
            if (signature(os.fstat(fd)) != signature(before)
                    or signature(os.stat(name, dir_fd=parent, follow_symlinks=False))
                    != signature(before)):
                raise EvidenceError("file changed during reading")
            return b"".join(chunks)
        finally:
            os.close(fd)

    def read_relative(self, path: str) -> bytes:
        parts = path.split("/")
        if (not path or path.startswith("/") or "\\" in path
                or any(part in ("", ".", "..") for part in parts)):
            raise EvidenceError("file must be a confined non-empty relative path")
        parent = os.dup(self.root_fd)
        try:
            for component in parts[:-1]:
                self.check_time()
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=parent)
                if os.fstat(child).st_dev != self.device:
                    os.close(child)
                    raise EvidenceError("cross-device directory refused")
                os.close(parent)
                parent = child
            return self._read(parent, parts[-1])
        finally:
            os.close(parent)

    def inventory(self) -> None:
        try:
            self._walk(self.root_fd, "", 0)
        except LimitReached as exc:
            self.partial = True
            self.diagnostics.append(str(exc))

    def _walk(self, directory: int, prefix: str, depth: int) -> None:
        self.check_time()
        if depth > 128:
            self.skip(prefix, "directory depth limit reached")
            return
        initial = os.fstat(directory)
        names = []
        with os.scandir(directory) as scan:
            for entry in scan:
                self.check_time()
                self.entries += 1
                if self.entries > self.limits["entries"]:
                    raise LimitReached("entry limit reached; remaining enumeration omitted")
                names.append(entry.name)
        for name in sorted(names):
            self.check_time()
            path = f"{prefix}/{name}" if prefix else name
            try:
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    if info.st_dev != self.device:
                        self.skip(path, "cross-device directory refused")
                        continue
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=directory)
                    try:
                        if signature(os.fstat(child)) != signature(info):
                            raise EvidenceError("directory changed before opening")
                        self._walk(child, path, depth + 1)
                        if signature(os.stat(name, dir_fd=directory, follow_symlinks=False)) != signature(info):
                            raise EvidenceError("directory changed during traversal")
                    finally:
                        os.close(child)
                else:
                    data = self._read(directory, name)
                    try:
                        data.decode("utf-8")
                        kind = "utf-8"
                    except UnicodeDecodeError:
                        kind = "binary-or-non-utf8"
                    self.items.append({"path": path, "status": "inspected",
                                       "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                                       "content_kind": kind})
            except LimitReached as exc:
                if "deadline" in str(exc) or "entry limit" in str(exc):
                    raise
                self.skip(path, str(exc))
            except (OSError, EvidenceError) as exc:
                self.skip(path, f"{type(exc).__name__}: {exc}")
        if signature(os.fstat(directory)) != signature(initial):
            self.skip(prefix or ".", "directory changed during enumeration")

    def unicode(self, path: str) -> None:
        data = self.read_relative(path)
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            self.skip(path, f"UTF-8 analysis unavailable at byte {exc.start}")
            return
        occurrences = []
        count = offset = 0
        line = column = 1
        for character in text:
            self.check_time()
            category = unicodedata.category(character)
            if category == "Cf" or (category == "Cc" and character not in "\n\r\t"):
                count += 1
                if len(occurrences) < 256:
                    occurrences.append({"byte_offset": offset, "line": line, "column": column,
                                        "code_point": f"U+{ord(character):04X}",
                                        "name": unicodedata.name(character, "UNNAMED CONTROL")})
            offset += len(character.encode("utf-8"))
            if character == "\n":
                line += 1
                column = 1
            else:
                column += 1
        self.items.append({"path": path, "status": "inspected", "bytes": len(data),
                           "sha256": hashlib.sha256(data).hexdigest(),
                           "control_count": count, "occurrences": occurrences,
                           "detail_truncated": count > len(occurrences)})
        if count > len(occurrences):
            self.partial = True
            self.diagnostics.append("Unicode occurrence detail limited to 256; count is complete")

    def decode(self, path: str, encodings: list[str], preview: bool = False) -> None:
        if not encodings or len(encodings) > self.limits["layers"]:
            raise EvidenceError("specify one to three ordered transforms within layer limit")
        data = self.read_relative(path)
        original = hashlib.sha256(data).hexdigest()
        transforms = []
        cumulative = 0
        item = {"path": path, "status": "partial", "original_sha256": original,
                "input_bytes": len(data), "transforms": transforms,
                "cumulative_decoded_bytes": 0}
        self.items.append(item)
        for encoding in encodings:
            self.check_time()
            available = self.limits["decoded_bytes"] - cumulative
            if encoding == "base64":
                compact = data.translate(None, b" \t\n\r\v\f")
                padding = len(compact) - len(compact.rstrip(b"="))
                estimated = len(compact) // 4 * 3 - min(padding, 2)
                if estimated > available:
                    raise LimitReached("cumulative decoded byte limit reached")
                try:
                    result = base64.b64decode(compact, validate=True)
                except binascii.Error as exc:
                    raise EvidenceError(f"invalid base64: {exc}") from exc
            elif encoding == "hex":
                compact = data.strip()
                if len(compact) % 2 or re.search(rb"[^0-9a-fA-F]", compact):
                    raise EvidenceError("invalid hexadecimal input")
                if len(compact) // 2 > available:
                    raise LimitReached("cumulative decoded byte limit reached")
                result = binascii.unhexlify(compact)
            elif encoding == "percent":
                if any(byte > 127 for byte in data) or re.search(rb"%(?![0-9a-fA-F]{2})", data):
                    raise EvidenceError("percent input must be ASCII with valid escapes")
                expected = len(data) - 2 * data.count(b"%")
                if expected > available:
                    raise LimitReached("cumulative decoded byte limit reached")
                result = unquote_to_bytes(data)
            else:
                raise EvidenceError(f"unsupported transform: {encoding}")
            cumulative += len(result)
            if cumulative > self.limits["decoded_bytes"]:
                raise LimitReached("cumulative decoded byte limit reached")
            self.check_time()
            transforms.append({"encoding": encoding, "input_sha256": hashlib.sha256(data).hexdigest(),
                               "output_sha256": hashlib.sha256(result).hexdigest(),
                               "output_bytes": len(result)})
            item["cumulative_decoded_bytes"] = cumulative
            data = result
        item["status"] = "inspected"
        if preview:
            item["preview"] = data[:256].decode("utf-8", errors="backslashreplace")
            item["preview_truncated"] = len(data) > 256

    def report(self) -> dict:
        return {"schema_version": 1, "coverage": "partial" if self.partial else "complete",
                "limits": self.limits, "entries_encountered": self.entries,
                "input_bytes_read": self.bytes_read, "items": self.items,
                "diagnostics": self.diagnostics}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    for key in DEFAULTS:
        parser.add_argument(f"--{key.replace('_', '-')}", type=int)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("inventory")
    unicode_parser = subparsers.add_parser("unicode")
    unicode_parser.add_argument("path")
    decode_parser = subparsers.add_parser("decode")
    decode_parser.add_argument("path")
    decode_parser.add_argument("--encoding", action="append", required=True,
                               choices=("base64", "hex", "percent"))
    decode_parser.add_argument("--preview", action="store_true")
    args = parser.parse_args(argv)
    inspector = None
    previous_handler = None

    def deadline(_signum: int, _frame: object) -> None:
        raise LimitReached("helper deadline reached")

    try:
        limits = {key: getattr(args, key) for key in DEFAULTS if getattr(args, key) is not None}
        if any(value <= 0 or value > DEFAULTS[key] for key, value in limits.items()):
            raise EvidenceError("limits must be positive integers no greater than defaults")
        if not hasattr(signal, "setitimer"):
            raise EvidenceError("POSIX deadline enforcement is required")
        previous_handler = signal.signal(signal.SIGALRM, deadline)
        signal.setitimer(signal.ITIMER_REAL, limits.get("seconds", DEFAULTS["seconds"]))
        inspector = Inspector(args.root, limits)
        if args.command == "inventory":
            inspector.inventory()
        elif args.command == "unicode":
            inspector.unicode(args.path)
        else:
            inspector.decode(args.path, args.encoding, args.preview)
        report = inspector.report()
        code = 1 if inspector.partial else 0
    except LimitReached as exc:
        report = inspector.report() if inspector else {"schema_version": 1, "items": []}
        report.update(coverage="partial", error=str(exc))
        code = 1
    except (OSError, EvidenceError) as exc:
        report = inspector.report() if inspector else {"schema_version": 1, "items": []}
        report.update(coverage="failed", error=f"{type(exc).__name__}: {exc}")
        code = 2
    finally:
        if previous_handler is not None:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)
        if inspector:
            inspector.close()
    print(json.dumps(report, ensure_ascii=True, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
