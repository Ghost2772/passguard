import os
import ssl

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
import pytest

from scripts.prepare import prepare


def test_prepare_does_not_replace_existing_material(material):
    password = (material / "bootstrap/postgres_password").read_bytes()
    certificate = (material / "pki/ca.crt").read_bytes()
    assert prepare(material) is False
    assert (material / "bootstrap/postgres_password").read_bytes() == password
    assert (material / "pki/ca.crt").read_bytes() == certificate


def test_partial_setup_is_not_silently_replaced(tmp_path):
    (tmp_path / "pki").mkdir()
    (tmp_path / "pki/ca.crt").write_text("existing-material")
    with pytest.raises(RuntimeError, match="незавершённая"):
        prepare(tmp_path)
    assert (tmp_path / "pki/ca.crt").read_text() == "existing-material"


def test_server_certificates_are_signed_for_expected_hosts(material):
    ca = x509.load_pem_x509_certificate((material / "pki/ca.crt").read_bytes())
    for service in ("vault", "postgres"):
        certificate = x509.load_pem_x509_certificate((material / f"pki/{service}.crt").read_bytes())
        ca.public_key().verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert service in names.get_values_for_type(x509.DNSName)
        assert "localhost" in names.get_values_for_type(x509.DNSName)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(material / f"pki/{service}.crt", material / f"bootstrap/{service}.key")


@pytest.mark.skipif(os.name == "nt", reason="Unix file permissions")
def test_private_material_has_restrictive_permissions(material):
    for filename in ("operator/ca.key", "bootstrap/vault.key", "bootstrap/postgres.key", "bootstrap/postgres_password"):
        assert (material / filename).stat().st_mode & 0o777 == 0o600
