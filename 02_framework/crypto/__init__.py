"""Reusable cryptographic primitives for the healthcare encryption framework."""

from .aes_gcm import decrypt_record, encrypt_record, generate_key as generate_aes_key
from .ecc_protection import (
    generate_key_pair as generate_ecc_key_pair,
    protect_aes_key as protect_aes_key_ecc,
    recover_aes_key as recover_aes_key_ecc,
)
from .envelope import EncryptedEnvelope, record_aad
from .mlkem_protection import (
    generate_key_pair as generate_mlkem_key_pair,
    protect_aes_key as protect_aes_key_mlkem,
    recover_aes_key as recover_aes_key_mlkem,
)

__all__ = [
    "EncryptedEnvelope",
    "decrypt_record",
    "encrypt_record",
    "generate_aes_key",
    "generate_ecc_key_pair",
    "generate_mlkem_key_pair",
    "protect_aes_key_ecc",
    "protect_aes_key_mlkem",
    "recover_aes_key_ecc",
    "recover_aes_key_mlkem",
    "record_aad",
]
