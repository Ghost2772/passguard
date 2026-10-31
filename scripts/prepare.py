"""Generate local TLS material and the one-time PostgreSQL bootstrap password."""

from datetime import datetime, timedelta, timezone
import ipaddress
from pathlib import Path
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from scripts.common import state_dir, write_private


def private_key_bytes(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def prepare(root: Path) -> bool:
    marker = root / "prepared"
    required = [
        root / "pki/ca.crt",
        root / "pki/vault.crt",
        root / "pki/postgres.crt",
        root / "bootstrap/vault.key",
        root / "bootstrap/postgres.key",
        root / "bootstrap/postgres_password",
        root / "operator/ca.key",
    ]
    if marker.is_file():
        if not all(path.is_file() for path in required):
            raise RuntimeError("Подготовка повреждена: часть локальных файлов отсутствует. Автозамена отключена.")
        return False
    if any(path.exists() for path in required):
        raise RuntimeError("Обнаружена незавершённая подготовка. Сначала проверь локальные файлы.")

    for name in ["bootstrap", "operator", "pki", "identities/demo", "identities/rotator"]:
        directory = root / name
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o700 if name in ("bootstrap", "operator") else 0o755)
    root.chmod(0o755)
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PassGuard local coursework CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    write_private(root / "operator/ca.key", private_key_bytes(ca_key))
    (root / "pki/ca.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (root / "pki/ca.crt").chmod(0o644)
    for service in ("vault", "postgres"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, service)]))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(service),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(True, False, True, False, False, False, False, False, False),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        write_private(root / f"bootstrap/{service}.key", private_key_bytes(key))
        path = root / f"pki/{service}.crt"
        path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        path.chmod(0o644)
    write_private(root / "bootstrap/postgres_password", secrets.token_urlsafe(36))
    write_private(marker, "prepared\n")
    return True


def main() -> None:
    created = prepare(state_dir())
    print("Локальные сертификаты и начальные данные созданы." if created else "Подготовка уже выполнена, файлы сохранены.")
    print("Секретные значения скрыты; файлы находятся вне Git в .local/.")


if __name__ == "__main__":
    main()
