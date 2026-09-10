from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# 1. Load ML-KEM private key
with open("mlkem_private_key.bin", "rb") as f:
    private_key_seed = f.read()

private_key = mlkem.MLKEM768PrivateKey.from_seed_bytes(
    private_key_seed
)

print("ML-KEM private key loaded.")


# 2. Load ML-KEM ciphertext
with open("mlkem_ciphertext.bin", "rb") as f:
    mlkem_ciphertext = f.read()

print("ML-KEM ciphertext loaded.")


# 3. Recover ML-KEM shared secret
shared_secret = private_key.decapsulate(
    mlkem_ciphertext
)

print("Shared secret recovered.")


# 4. Derive the wrapping key
wrapping_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"ML-KEM AES-256 key protection"
).derive(shared_secret)

print("Wrapping key recovered.")


# 5. Load protected AES key
with open("mlkem_protected_aes_key.bin", "rb") as f:
    protected_data = f.read()

# First 12 bytes = AES-GCM nonce
nonce = protected_data[:12]

# Remaining bytes = protected AES key
protected_aes_key = protected_data[12:]


# 6. Recover original AES-256 key
aes_key = AESGCM(wrapping_key).decrypt(
    nonce,
    protected_aes_key,
    None
)

print("AES key recovered successfully.")


# 7. Load encrypted EHR file
with open("encrypted_EHR.bin", "rb") as f:
    encrypted_EHR_data = f.read()

# First 12 bytes = AES-GCM nonce
ehr_nonce = encrypted_EHR_data[:12]

# Remaining bytes = encrypted EHR + authentication tag
ehr_ciphertext = encrypted_EHR_data[12:]


# 8. Decrypt EHR record
ehr_data = AESGCM(aes_key).decrypt(
    ehr_nonce,
    ehr_ciphertext,
    None
)

print("EHR record decrypted successfully.")


# 9. Save ML-KEM decrypted EHR as CSV
output_file = "EHR_decrypted_mlkem.csv"

with open(output_file, "wb") as f:
    f.write(ehr_data)


# 10. Final result
print()
print("ML-KEM DECRYPTION COMPLETED")
print("Decrypted file:", output_file)