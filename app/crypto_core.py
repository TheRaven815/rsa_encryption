"""RSA cryptography service layer."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


@dataclass
class KeyInfo:
    key_size: str
    exponent: str
    modulus: str
    fingerprint: str
    has_private: str


def compute_fingerprint(public_key_pem: bytes) -> str:
    digest = hashlib.sha256(public_key_pem).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, 32, 2))


class RSACore:
    def __init__(self) -> None:
        self.private_key = None
        self.public_key = None

    @property
    def has_private(self) -> bool:
        return self.private_key is not None

    @property
    def has_public(self) -> bool:
        return self.public_key is not None

    def generate(self, bits: int) -> None:
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits,
            backend=default_backend(),
        )
        self.public_key = self.private_key.public_key()

    def export_private_pem(self, password: bytes | None = None) -> bytes:
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            encryption,
        )

    def export_public_pem(self) -> bytes:
        return self.public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def load_private_pem(self, data: bytes, password: bytes | None = None) -> None:
        self.private_key = serialization.load_pem_private_key(
            data,
            password=password,
            backend=default_backend(),
        )
        self.public_key = self.private_key.public_key()

    def load_public_pem(self, data: bytes) -> None:
        self.public_key = serialization.load_pem_public_key(
            data,
            backend=default_backend(),
        )

    def encrypt(self, plaintext: str) -> str:
        raw = plaintext.encode("utf-8")
        key_len = self.public_key.key_size // 8
        max_chunk = key_len - 66

        encrypted_chunks: list[bytes] = []
        start = 0
        while start < len(raw):
            chunk = raw[start : start + max_chunk]
            encrypted = self.public_key.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            encrypted_chunks.append(encrypted)
            start += max_chunk

        output = len(encrypted_chunks).to_bytes(4, "big")
        for block in encrypted_chunks:
            output += len(block).to_bytes(4, "big") + block

        return base64.b64encode(output).decode("ascii")

    def decrypt(self, ciphertext_b64: str) -> str:
        data = base64.b64decode(ciphertext_b64.encode("ascii"))
        count = int.from_bytes(data[:4], "big")

        pos = 4
        parts: list[bytes] = []
        for _ in range(count):
            block_len = int.from_bytes(data[pos : pos + 4], "big")
            pos += 4
            block = data[pos : pos + block_len]
            pos += block_len

            plain = self.private_key.decrypt(
                block,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            parts.append(plain)

        return b"".join(parts).decode("utf-8")

    def key_info(self) -> dict[str, str]:
        if not self.has_public:
            return {}

        public_pem = self.export_public_pem()
        numbers = self.public_key.public_numbers()
        info = KeyInfo(
            key_size=f"{self.public_key.key_size} bits",
            exponent=str(numbers.e),
            modulus=hex(numbers.n)[:48] + "…",
            fingerprint=compute_fingerprint(public_pem),
            has_private="Yes ✓" if self.has_private else "No (public only)",
        )
        return {
            "Key Size": info.key_size,
            "Exponent": info.exponent,
            "Modulus": info.modulus,
            "Fingerprint (SHA-256)": info.fingerprint,
            "Has Private Key": info.has_private,
        }
