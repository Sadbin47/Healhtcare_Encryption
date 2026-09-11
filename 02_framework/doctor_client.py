"""Doctor-side envelope recovery.

This module is intentionally independent of the HTTP server.  A doctor client
downloads the encrypted envelope, keeps its private key locally, and performs
AES-GCM decryption after verifying the envelope's authenticated metadata.
"""

from __future__ import annotations

try:
    from .crypto.aes_gcm import decrypt_record
    from .crypto.ecc_protection import ALGORITHM as ECC_ALGORITHM, recover_aes_key as recover_ecc
    from .crypto.envelope import EncryptedEnvelope, record_aad
    from .crypto.mlkem_protection import ALGORITHM as MLKEM_ALGORITHM, recover_aes_key as recover_mlkem
except ImportError:  # pragma: no cover
    from crypto.aes_gcm import decrypt_record
    from crypto.ecc_protection import ALGORITHM as ECC_ALGORITHM, recover_aes_key as recover_ecc
    from crypto.envelope import EncryptedEnvelope, record_aad
    from crypto.mlkem_protection import ALGORITHM as MLKEM_ALGORITHM, recover_aes_key as recover_mlkem


def decrypt_envelope(envelope: EncryptedEnvelope, private_key: object) -> bytes:
    """Recover the envelope AES key and decrypt locally on the doctor device."""

    if not isinstance(envelope, EncryptedEnvelope):
        raise TypeError("envelope must be an EncryptedEnvelope")
    aad = record_aad(envelope.record_id, envelope.key_protection, envelope.key_reference)
    if envelope.key_protection == ECC_ALGORITHM:
        aes_key = recover_ecc(envelope.wrapped_key, private_key)
    elif envelope.key_protection == MLKEM_ALGORITHM:
        aes_key = recover_mlkem(envelope.wrapped_key, private_key)
    else:
        raise ValueError("unsupported envelope key-protection algorithm")
    return decrypt_record(envelope.nonce, envelope.ciphertext, envelope.tag, aes_key, aad)


class DoctorClient:
    """Minimal local key-custody facade for callers integrating the API."""

    def __init__(self, private_key: object) -> None:
        self._private_key = private_key

    def decrypt(self, envelope: EncryptedEnvelope) -> bytes:
        return decrypt_envelope(envelope, self._private_key)
