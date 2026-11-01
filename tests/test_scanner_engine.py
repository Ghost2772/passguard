import io
import json
from pathlib import Path
import stat
import subprocess
import zipfile

import pytest

from passguard.scanner.engine import SourceScanner
from passguard.scanner.errors import ScanError
from passguard.scanner.models import MAX_FILE_BYTES, MAX_FILES


def bundle(items):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, content in items:
            archive.writestr(path, content)
    return output.getvalue()


def fake_detector(monkeypatch, rows, code=10):
    def run(command, **kwargs):
        report = Path(command[command.index("--report-path") + 1])
        report.write_text("\n".join(json.dumps(row) for row in rows))
        return subprocess.CompletedProcess(command, code)
    monkeypatch.setattr("passguard.scanner.engine.subprocess.run", run)


@pytest.mark.parametrize("name", ["../escape.py", "/root.py", "C:/code.py", "a\\code.py", "a//code.py", "a/./code.py", "a/\x00code.py", "a/\ncode.py"])
def test_rejects_paths_without_echoing_input(name, tmp_path):
    archive = bundle([(name.replace("\x00", "Z"), "x = 1")])
    if "\x00" in name:
        # ZipFile.writestr strips NUL itself; emulate an untrusted producer.
        archive = archive.replace(b"a/Zcode.py", b"a/\x00code.py")
    with pytest.raises(ScanError) as error:
        SourceScanner._stage(archive, tmp_path)
    assert error.value.code == "unsafe_archive_path"
    assert name not in str(error.value)
    assert not list(tmp_path.iterdir())


def test_rejects_symlinks_instead_of_following_them(tmp_path):
    info = zipfile.ZipInfo("linked.py")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(ScanError) as error:
        SourceScanner._stage(bundle([(info, "/run/identity/secret_id")]), tmp_path)
    assert error.value.code == "invalid_archive"


@pytest.mark.parametrize("items", [
    [("same.py", "a"), ("SAME.py", "b")],
    [("project/.local/key", "private")],
    [("project/.git/config", "private")],
    [("node_modules/pkg.js", "private")],
])
def test_rejects_duplicates_and_operator_state(items, tmp_path):
    with pytest.raises(ScanError):
        SourceScanner._stage(bundle(items), tmp_path)


def test_rejects_small_zip_with_oversized_decompressed_file(tmp_path):
    archive = bundle([("large.py", "x" * (MAX_FILE_BYTES + 1))])
    assert len(archive) < 10000
    with pytest.raises(ScanError) as error:
        SourceScanner._stage(archive, tmp_path)
    assert error.value.code == "archive_limits"


def test_rejects_too_many_small_files(tmp_path):
    with pytest.raises(ScanError) as error:
        SourceScanner._stage(bundle([(f"f{i}.py", "") for i in range(MAX_FILES + 1)]), tmp_path)
    assert error.value.code == "archive_limits"


def test_uploaded_detector_config_and_ignore_files_have_no_special_names(tmp_path):
    files, skipped, _ = SourceScanner._stage(bundle([
        (".gitleaksignore", "*:password:1"), (".gitleaks.toml", "invalid TOML"),
        ("main.py", "x = 1"), ("picture.png", b"\x89PNG\0\xff"),
    ]), tmp_path)
    assert not (tmp_path / ".gitleaksignore").exists()
    assert not (tmp_path / ".gitleaks.toml").exists()
    assert len(files) == 3 and len(skipped) == 1
    assert skipped[0].reason == "binary_or_non_utf8"


def test_only_metadata_survives_scan_and_temporary_files_are_removed(monkeypatch, tmp_path):
    fake_detector(monkeypatch, [{"file": "file_0001.py", "rule_id": "passguard-hardcoded-password", "line": 1, "end_line": 1}])
    result = SourceScanner().scan(bundle([("src/app.py", 'password = "synthetic-sensitive-value"')]))
    serialized = result.model_dump_json()
    assert "synthetic-sensitive-value" not in serialized
    assert result.findings[0].path == "src/app.py"
    assert result.findings[0].kind == "password"
    assert result.findings[0].status == "suspected"


@pytest.mark.parametrize("row", [
    {"file": "file_0001.py", "rule_id": "generic-api-key", "line": 1, "end_line": 1, "Secret": "private-value"},
    {"file": "outside.py", "rule_id": "generic-api-key", "line": 1, "end_line": 1},
    {"file": "file_0001.py", "rule_id": "generic-api-key", "line": 300, "end_line": 300},
])
def test_unexpected_detector_fields_or_locations_fail_closed(monkeypatch, row):
    fake_detector(monkeypatch, [row])
    with pytest.raises(ScanError) as error:
        SourceScanner().scan(bundle([("app.py", "x = 1")]))
    assert error.value.code == "scanner_unavailable"
    assert "private-value" not in str(error.value)


def test_partial_detector_scan_is_not_accepted_as_clean(monkeypatch):
    fake_detector(monkeypatch, [], code=1)
    with pytest.raises(ScanError) as error:
        SourceScanner().scan(bundle([("app.py", "x = 1")]))
    assert error.value.code == "scanner_unavailable"


def test_timeout_cleans_up_source_and_hides_detector_output(monkeypatch):
    directories = []
    def expired(command, **kwargs):
        directories.append(Path(kwargs["cwd"]))
        raise subprocess.TimeoutExpired(command, 25, output=b"private-value", stderr=b"private-value")
    monkeypatch.setattr("passguard.scanner.engine.subprocess.run", expired)
    with pytest.raises(ScanError) as error:
        SourceScanner().scan(bundle([("app.py", 'password = "synthetic-value"')]))
    assert error.value.code == "scanner_timeout"
    assert "private-value" not in str(error.value)
    assert all(not directory.exists() for directory in directories)


def test_concurrent_scan_is_rejected_without_waiting():
    scanner = SourceScanner()
    with scanner.slot():
        with pytest.raises(ScanError) as error:
            with scanner.slot():
                pytest.fail("Second scanner should not start")
    assert error.value.code == "scanner_busy"
    with scanner.slot():
        pass
