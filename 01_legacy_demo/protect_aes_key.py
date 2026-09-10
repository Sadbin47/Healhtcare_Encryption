from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os


# 1. Read the AES key
with open("aes_key.txt", "r") as f:
    aes_key = base64.b64decode(f.read().strip())


# 2. Read the ECC private key
with open("ecc_private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )


# 3. Read the ECC public key
with open("ecc_public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(
        f.read()
    )


# 4. Create an ECDH shared secret
shared_secret = private_key.exchange(
    ec.ECDH(),
    public_key
)


# 5. Derive a wrapping key using HKDF
wrapping_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"AES key protection"
).derive(shared_secret)


# 6. Generate a random nonce
nonce = os.urandom(12)


# 7. Protect the AES key using AES-GCM
protected_aes_key = AESGCM(wrapping_key).encrypt(
    nonce,
    aes_key,
    None
)


# 8. Save the protected AES key
with open("protected_aes_key.bin", "wb") as f:
    f.write(nonce + protected_aes_key)


print("AES key protected successfully using ECC!")
print("Protected AES key saved to protected_aes_key.bin")