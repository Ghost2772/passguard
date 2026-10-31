from pathlib import Path

import pytest

from scripts.prepare import prepare
from passguard.config import Settings


@pytest.fixture(scope="session")
def material(tmp_path_factory):
    root = tmp_path_factory.mktemp("credentials")
    prepare(root)
    return root


@pytest.fixture
def identity(tmp_path):
    directory = tmp_path / "identity"
    directory.mkdir()
    (directory / "role_id").write_text("unit-role")
    (directory / "secret_id").write_text("unit-identity-only")
    return directory


@pytest.fixture
def settings(material, identity):
    return Settings(
        vault_addr="https://vault:8200",
        ca_file=material / "pki/ca.crt",
        identity_dir=identity,
        db_host="postgres",
        db_port=5432,
        db_name="coursework",
        db_ca_file=material / "pki/ca.crt",
    )
