from enum import Enum
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from passguard.scanner.models import MAX_FINDINGS, ScanResult


class Role(str, Enum):
    admin = "admin"
    operator = "operator"
    auditor = "auditor"


class UserView(BaseModel):
    id: UUID
    username: str
    role: Role
    active: bool
    created_at: datetime


class AuthView(BaseModel):
    user: UserView
    csrf_token: str


class UserListView(BaseModel):
    items: list[UserView]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(StrictModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")
    password: SecretStr

    @field_validator("username")
    @classmethod
    def normalized(cls, value):
        return value.lower()

    @field_validator("password")
    @classmethod
    def bounded(cls, value):
        if not 1 <= len(value.get_secret_value()) <= 128:
            raise ValueError("Пароль должен содержать от 1 до 128 символов")
        return value


class CreateUserRequest(LoginRequest):
    role: Role

    @field_validator("password")
    @classmethod
    def minimum(cls, value):
        if len(value.get_secret_value()) < 15:
            raise ValueError("Новый пароль должен содержать не менее 15 символов")
        return value


class UpdateUserRequest(StrictModel):
    role: Role | None = None
    active: bool | None = None

    @model_validator(mode="after")
    def nonempty(self):
        if self.role is None and self.active is None:
            raise ValueError("Укажи роль или состояние пользователя")
        return self


class ChangePasswordRequest(StrictModel):
    current_password: SecretStr
    new_password: SecretStr

    @field_validator("current_password")
    @classmethod
    def old_length(cls, value):
        if not 1 <= len(value.get_secret_value()) <= 128:
            raise ValueError("Недопустимая длина текущего пароля")
        return value

    @field_validator("new_password")
    @classmethod
    def new_length(cls, value):
        if not 15 <= len(value.get_secret_value()) <= 128:
            raise ValueError("Новый пароль должен содержать от 15 до 128 символов")
        return value


class RotationReason(str, Enum):
    scheduled = "scheduled"
    suspected_exposure = "suspected_exposure"
    manual_test = "manual_test"


class RotationRequest(StrictModel):
    idempotency_key: UUID
    reason: RotationReason = RotationReason.manual_test


class ScanSummaryView(BaseModel):
    id: UUID
    actor_id: UUID
    created_at: datetime
    findings_count: int = Field(ge=0, le=MAX_FINDINGS)
    engine: str
    engine_version: str
    files_scanned: int


class ScanListView(BaseModel):
    items: list[ScanSummaryView]


class ScanReportView(BaseModel):
    id: UUID
    actor_id: UUID
    created_at: datetime
    findings_count: int = Field(ge=0, le=MAX_FINDINGS)
    result: ScanResult
