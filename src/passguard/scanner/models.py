from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_TOTAL_BYTES = 20 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_FILES = 1000
MAX_FINDINGS = 1000
SCANNER_VERSION = "8.30.1"


class SafeModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Finding(SafeModel):
    id: str = Field(pattern=r"^F[0-9]{4}$")
    file_id: str = Field(pattern=r"^file_[0-9]{4}$")
    path: str = Field(min_length=1, max_length=240)
    line: int = Field(ge=1, le=MAX_FILE_BYTES + 1)
    end_line: int = Field(ge=1, le=MAX_FILE_BYTES + 1)
    rule_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,100}$")
    kind: Literal["password", "private_key", "token", "credential"]
    severity: Literal["high"] = "high"
    status: Literal["suspected"] = "suspected"


class SkippedFile(SafeModel):
    file_id: str = Field(pattern=r"^file_[0-9]{4}$")
    path: str = Field(min_length=1, max_length=240)
    reason: Literal["binary_or_non_utf8"]


class ScanResult(SafeModel):
    engine: Literal["gitleaks"] = "gitleaks"
    engine_version: Literal["8.30.1"] = SCANNER_VERSION
    scope: Literal["source_snapshot"] = "source_snapshot"
    files_scanned: int = Field(ge=1, le=MAX_FILES)
    bytes_scanned: int = Field(ge=0, le=MAX_TOTAL_BYTES)
    findings: list[Finding] = Field(max_length=MAX_FINDINGS)
    skipped_files: list[SkippedFile] = Field(max_length=MAX_FILES)
