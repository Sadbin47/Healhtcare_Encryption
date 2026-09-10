from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os

# Read the AES key
with open("aes_key.txt", "r") as f:
    key = base64.b64decode(f.read().strip())

# Read the EHR CSV
with open("EHR.csv", "rb") as f:
    data = f.read()

# Create AES-GCM object
aes = AESGCM(key)

# Generate a random nonce
nonce = os.urandom(12)

# Encrypt the EHR
encrypted_data = aes.encrypt(nonce, data, None)

# Save nonce + encrypted data
with open("encrypted_EHR.bin", "wb") as f:
    f.write(nonce + encrypted_data)

print("EHR encrypted successfully!")
print("Encrypted file: encrypted_EHR.bin")