from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import base64
import os


# 1. Read the existing AES-256 key
with open("aes_key.txt", "r") as f:
    aes_key = base64.b64decode(f.read().strip())

print("AES key loaded successfully.")


# 2. Generate ML-KEM-768 key pair
private_key = mlkem.MLKEM768PrivateKey.generate()
public_key = private_key.public_key()

print("ML-KEM-768 key pair generated.")


# 3. Encapsulate using the ML-KEM public key
shared_secret, ciphertext = public_key.encapsulate()

print("ML-KEM encapsulation completed.")


# 4. Derive a 256-bit AES wrapping key using HKDF
wrapping_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"ML-KEM AES-256 key protection"
).derive(shared_secret)

print("Wrapping key derived successfully.")


# 5. Protect the AES-256 key using AES-GCM
nonce = os.urandom(12)

protected_aes_key = AESGCM(wrapping_key).encrypt(
    nonce,
    aes_key,
    None
)

print("AES key protected successfully using ML-KEM.")


# 6. Save ML-KEM private key
with open("mlkem_private_key.bin", "wb") as f:
    f.write(private_key.private_bytes_raw())


# 7. Save ML-KEM public key
with open("mlkem_public_key.bin", "wb") as f:
    f.write(public_key.public_bytes_raw())


# 8. Save ML-KEM ciphertext
with open("mlkem_ciphertext.bin", "wb") as f:
    f.write(ciphertext)


# 9. Save protected AES key
#    nonce + encrypted AES key
with open("mlkem_protected_aes_key.bin", "wb") as f:
    f.write(nonce + protected_aes_key)


# 10. Display results
print()
print("ML-KEM AES KEY PROTECTION COMPLETED")
print("Private key      : mlkem_private_key.bin")
print("Public key       : mlkem_public_key.bin")
print("Ciphertext       : mlkem_ciphertext.bin")
print("Protected AES key: mlkem_protected_aes_key.bin")