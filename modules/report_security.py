"""Password-based encryption for generated reports."""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
VAULT_PATH = ROOT / ".work" / "report_vault.json"
MAGIC = b"NDAYENC1"
VERIFIER_CONTEXT = b"nday-nexus-report-vault-v1"
_ACTIVE_KEY = None


class ReportSecurityError(RuntimeError):
    """Raised when a report vault cannot be unlocked or read."""


def _derive_key(password: str, salt: bytes) -> bytes:
    if len(password) < 12:
        raise ReportSecurityError("Use a report password with at least 12 characters.")
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**15, r=8, p=1,
                          dklen=32, maxmem=64 * 1024 * 1024)


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(data)
    try:
        temporary.chmod(0o600)
    except OSError:
        pass
    os.replace(temporary, path)


def _vault_data() -> dict:
    try:
        data = json.loads(VAULT_PATH.read_text())
        if data.get("format") != 1 or data.get("kdf") != "scrypt":
            raise ReportSecurityError("Report vault format is unsupported.")
        return data
    except FileNotFoundError:
        raise ReportSecurityError("Report vault has not been initialized.")
    except (OSError, json.JSONDecodeError) as exc:
        raise ReportSecurityError(f"Cannot read report vault settings: {exc}") from exc


def create_vault(password: str) -> bytes:
    """Create a vault and return its encryption key."""
    if VAULT_PATH.exists():
        raise ReportSecurityError("The report vault already exists; enter its password to unlock it.")
    salt = secrets.token_bytes(16)
    key = _derive_key(password, salt)
    verifier = hmac.new(key, VERIFIER_CONTEXT, hashlib.sha256).hexdigest()
    metadata = {"format": 1, "kdf": "scrypt", "salt": base64.b64encode(salt).decode(),
                "verifier": verifier}
    _write_private(VAULT_PATH, (json.dumps(metadata, indent=2) + "\n").encode())
    return key


def unlock_vault(password: str) -> bytes:
    metadata = _vault_data()
    try:
        salt = base64.b64decode(metadata["salt"], validate=True)
        expected = metadata["verifier"]
    except (KeyError, ValueError) as exc:
        raise ReportSecurityError("Report vault settings are invalid.") from exc
    key = _derive_key(password, salt)
    actual = hmac.new(key, VERIFIER_CONTEXT, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise ReportSecurityError("Incorrect report password.")
    return key


def _validate_key(key: bytes) -> bytes:
    metadata = _vault_data()
    actual = hmac.new(key, VERIFIER_CONTEXT, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(actual, metadata.get("verifier", "")):
        raise ReportSecurityError("The supplied report key does not unlock this vault.")
    return key


def set_active_key(key: bytes) -> None:
    global _ACTIVE_KEY
    _ACTIVE_KEY = _validate_key(key)


def clear_active_key() -> None:
    global _ACTIVE_KEY
    _ACTIVE_KEY = None


def get_active_key() -> bytes:
    if _ACTIVE_KEY:
        return _ACTIVE_KEY
    encoded = os.environ.get("NDAY_REPORT_KEY")
    if encoded:
        try:
            key = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise ReportSecurityError("NDAY_REPORT_KEY is not valid base64.") from exc
        return _validate_key(key)
    password = os.environ.get("NDAY_REPORT_PASSWORD")
    if password:
        if VAULT_PATH.exists():
            return unlock_vault(password)
        return create_vault(password)
    raise ReportSecurityError(
        "Reports are password-protected. Unlock the dashboard or set NDAY_REPORT_PASSWORD for CLI runs."
    )


def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    return MAGIC + nonce + AESGCM(key).encrypt(nonce, data, MAGIC)


def decrypt_bytes(data: bytes, key: bytes) -> bytes:
    if not data.startswith(MAGIC) or len(data) < len(MAGIC) + 12 + 16:
        raise ReportSecurityError("Encrypted report has an invalid format or is truncated.")
    nonce = data[len(MAGIC):len(MAGIC) + 12]
    try:
        return AESGCM(key).decrypt(nonce, data[len(MAGIC) + 12:], MAGIC)
    except Exception as exc:
        raise ReportSecurityError("Report authentication failed; check the password or file integrity.") from exc


def save_report_bytes(cve_id: str, extension: str, data: bytes, key: bytes | None = None) -> Path:
    key = _validate_key(key or get_active_key())
    _validate_cve_id(cve_id)
    if extension not in ("json", "txt"):
        raise ValueError("Report extension must be json or txt.")
    path = REPORTS / f"{cve_id}.{extension}.enc"
    REPORTS.mkdir(parents=True, exist_ok=True)
    _write_private(path, encrypt_bytes(data, key))
    return path


def read_report_bytes(cve_id: str, extension: str, key: bytes | None = None) -> bytes:
    if extension not in ("json", "txt"):
        raise ValueError("Report extension must be json or txt.")
    key = _validate_key(key or get_active_key())
    _validate_cve_id(cve_id)
    encrypted = REPORTS / f"{cve_id}.{extension}.enc"
    if encrypted.is_file():
        return decrypt_bytes(encrypted.read_bytes(), key)
    legacy = REPORTS / f"{cve_id}.{extension}"
    if legacy.is_file():
        return legacy.read_bytes()
    raise FileNotFoundError(encrypted)


def save_encrypted_artifact(path: Path, data: bytes, key: bytes | None = None) -> Path:
    key = _validate_key(key or get_active_key())
    encrypted_path = path.with_name(path.name + ".enc")
    _write_private(encrypted_path, encrypt_bytes(data, key))
    return encrypted_path


def read_encrypted_artifact(path: Path, key: bytes | None = None) -> bytes:
    key = _validate_key(key or get_active_key())
    return decrypt_bytes(path.read_bytes(), key)


def _validate_cve_id(cve_id: str) -> None:
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
        raise ValueError("Invalid CVE identifier.")


def read_json_report(cve_id: str) -> dict:
    return json.loads(read_report_bytes(cve_id, "json").decode("utf-8"))


def encrypt_legacy_reports(key: bytes) -> int:
    """Encrypt existing JSON/text reports and remove their plaintext copies."""
    key = _validate_key(key)
    count = 0
    if REPORTS.is_dir():
        for source in sorted(REPORTS.iterdir()):
            if source.suffix not in (".json", ".txt") or not source.is_file():
                continue
            target = source.with_name(source.name + ".enc")
            _write_private(target, encrypt_bytes(source.read_bytes(), key))
            source.unlink()
            count += 1
    artifacts = ROOT / ".work" / "artifacts"
    if artifacts.is_dir():
        for source in artifacts.glob("*/blind_hypothesis.json"):
            _write_private(source.with_name(source.name + ".enc"), encrypt_bytes(source.read_bytes(), key))
            source.unlink()
            count += 1
        for source in artifacts.glob("*/blind_hypothesis.md"):
            _write_private(source.with_name(source.name + ".enc"), encrypt_bytes(source.read_bytes(), key))
            source.unlink()
            count += 1
    return count
