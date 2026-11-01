from contextlib import contextmanager
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
from tempfile import TemporaryDirectory
from threading import Lock
import unicodedata
import zipfile
import zlib

from passguard.scanner.errors import failure
from passguard.scanner.models import (
    Finding, MAX_FILE_BYTES, MAX_FILES, MAX_FINDINGS, MAX_TOTAL_BYTES,
    MAX_UPLOAD_BYTES, ScanResult, SkippedFile,
)


INFRA = Path(__file__).resolve().parents[3] / "infra/scanner"
MAX_REPORT_BYTES = 2 * 1024 * 1024
EXCLUDED_PARTS = {".git", ".local", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}


def archive_path(info: zipfile.ZipInfo) -> str:
    name = info.orig_filename
    if (name != info.filename or "\\" in name or ":" in name or len(name) > 240
            or any(unicodedata.category(c).startswith("C") for c in name)):
        raise failure("unsafe_archive_path")
    name = name[:-1] if name.endswith("/") else name
    parts = name.split("/")
    if not name or len(parts) > 20 or any(p in ("", ".", "..") for p in parts) or PurePosixPath(name).is_absolute():
        raise failure("unsafe_archive_path")
    if any(p.casefold() in EXCLUDED_PARTS for p in parts):
        raise failure("excluded_directory")
    return name


class SourceScanner:
    def __init__(self, binary="/usr/local/bin/gitleaks", config=INFRA / "gitleaks.toml", template=INFRA / "metadata.tmpl"):
        self.binary, self.config, self.template = str(binary), str(config), str(template)
        self.lock = Lock()

    @contextmanager
    def slot(self):
        if not self.lock.acquire(blocking=False):
            raise failure("scanner_busy")
        try:
            yield
        finally:
            self.lock.release()

    def scan(self, archive: bytes) -> ScanResult:
        if len(archive) > MAX_UPLOAD_BYTES:
            raise failure("archive_too_large")
        # All input and temporary detector metadata live in a private tmpfs
        # directory. The scanner container has no Vault/DB identity or mounts.
        with TemporaryDirectory(prefix="passguard-scan-") as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir(mode=0o700)
            files, skipped, size = self._stage(archive, source)
            if not files:
                raise failure("no_source_files")
            report = root / "metadata.jsonl"
            command = [
                self.binary, "dir", str(source), "--config", self.config,
                "--report-format", "template", "--report-template", self.template,
                "--report-path", str(report), "--redact=100", "--exit-code=10",
                "--ignore-gitleaks-allow", "--gitleaks-ignore-path", str(root / "no-ignores"),
                "--max-archive-depth=0", "--max-decode-depth=2", "--timeout=20",
                "--no-banner", "--no-color", "--log-level=error",
            ]
            try:
                result = subprocess.run(
                    command, cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=25, check=False,
                    env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/nonexistent",
                         "GOMEMLIMIT": "192MiB", "GOMAXPROCS": "2"},
                )
            except subprocess.TimeoutExpired:
                raise failure("scanner_timeout") from None
            except OSError:
                raise failure("scanner_unavailable") from None
            # Gitleaks can use code 1 for a PARTIAL scan. A distinct finding
            # code ensures operational errors never become clean results.
            if result.returncode not in (0, 10):
                raise failure("scanner_unavailable")
            findings = self._findings(report, files)
            if (result.returncode == 10) != bool(findings):
                raise failure("scanner_unavailable")
            return ScanResult(files_scanned=len(files), bytes_scanned=size,
                              findings=findings, skipped_files=skipped)

    @staticmethod
    def _stage(archive: bytes, source: Path):
        files, skipped, seen = {}, [], set()
        size, count, declared_total = 0, 0, 0
        try:
            with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
                entries = bundle.infolist()
                if len(entries) > MAX_FILES * 2:
                    raise failure("archive_limits")
                for info in entries:
                    path = archive_path(info)
                    if path.casefold() in seen:
                        raise failure("unsafe_archive_path")
                    seen.add(path.casefold())
                    mode = stat.S_IFMT(info.external_attr >> 16)
                    if (mode not in (0, stat.S_IFREG, stat.S_IFDIR) or info.flag_bits & 1
                            or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
                        raise failure("invalid_archive")
                    if info.is_dir():
                        continue
                    if mode == stat.S_IFDIR:
                        raise failure("invalid_archive")
                    count += 1
                    declared_total += info.file_size
                    if count > MAX_FILES or info.file_size > MAX_FILE_BYTES or declared_total > MAX_TOTAL_BYTES:
                        raise failure("archive_limits")
                    with bundle.open(info) as stream:
                        content = stream.read(MAX_FILE_BYTES + 1)
                    if len(content) != info.file_size or len(content) > MAX_FILE_BYTES:
                        raise failure("archive_limits")
                    file_id = f"file_{count:04d}"
                    try:
                        content.decode("utf-8-sig")
                        if b"\x00" in content:
                            raise UnicodeError
                    except UnicodeError:
                        skipped.append(SkippedFile(file_id=file_id, path=path, reason="binary_or_non_utf8"))
                        continue
                    # Generated flat names prevent uploaded .gitleaksignore,
                    # config files, symlinks and filenames from controlling
                    # the detector. Keep a safe extension for content rules.
                    suffix = PurePosixPath(path).suffix
                    suffix = suffix if re.fullmatch(r"\.[a-zA-Z0-9]{1,12}", suffix) else ".txt"
                    staged = file_id + suffix
                    (source / staged).write_bytes(content)
                    files[staged] = {"file_id": file_id, "path": path,
                                     "lines": content.count(b"\n") + 1}
                    size += len(content)
        except (zipfile.BadZipFile, NotImplementedError, RuntimeError, OSError, EOFError, ValueError, zlib.error):
            raise failure("invalid_archive") from None
        return files, skipped, size

    @staticmethod
    def _findings(report: Path, files: dict) -> list[Finding]:
        try:
            if report.stat().st_size > MAX_REPORT_BYTES:
                raise failure("too_many_findings")
            raw = report.read_text(encoding="utf-8")
            findings, seen = [], set()
            for row in raw.splitlines():
                if not row.strip():
                    continue
                item = json.loads(row)
                if set(item) != {"file", "rule_id", "line", "end_line"}:
                    raise ValueError
                file = files[item["file"]]
                rule, line, end = item["rule_id"], item["line"], item["end_line"]
                if not isinstance(rule, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,100}", rule):
                    raise ValueError
                if type(line) is not int or type(end) is not int or not 1 <= line <= end <= file["lines"]:
                    raise ValueError
                key = (item["file"], rule, line, end)
                if key in seen:
                    continue
                seen.add(key)
                if len(findings) >= MAX_FINDINGS:
                    raise failure("too_many_findings")
                kind = ("password" if rule == "passguard-hardcoded-password" else
                        "private_key" if "private-key" in rule else
                        "token" if any(part in rule for part in ("token", "api-key", "access-key")) else "credential")
                findings.append(Finding(id=f"F{len(findings)+1:04d}", file_id=file["file_id"], path=file["path"],
                                        line=line, end_line=end, rule_id=rule, kind=kind))
            return findings
        except (OSError, UnicodeError, ValueError, TypeError, KeyError):
            raise failure("scanner_unavailable") from None
