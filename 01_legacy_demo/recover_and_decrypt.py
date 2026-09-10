from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# 1. Load ECC private key
with open("ecc_private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )


# 2. Load ECC public key
with open("ecc_public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(
        f.read()
    )


# 3. Create the same ECDH shared secret
shared_secret = private_key.exchange(
    ec.ECDH(),
    public_key
)


# 4. Derive the same wrapping key
wrapping_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"AES key protection"
).derive(shared_secret)


# 5. Read protected AES key
with open("protected_aes_key.bin", "rb") as f:
    protected_data = f.read()


# 6. Separate nonce and encrypted AES key
nonce = protected_data[:12]
encrypted_aes_key = protected_data[12:]


# 7. Recover the original AES key
aes_key = AESGCM(wrapping_key).decrypt(
    nonce,
    encrypted_aes_key,
    None
)

print("AES key recovered successfully!")


# 8. Read encrypted EHR file
with open("encrypted_EHR.bin", "rb") as f:
    encrypted_EHR_data = f.read()


# 9. Separate EHR-file nonce
ehr_nonce = encrypted_EHR_data[:12]
ciphertext = encrypted_EHR_data[12:]


# 10. Decrypt EHR record
ehr_data = AESGCM(aes_key).decrypt(
    ehr_nonce,
    ciphertext,
    None
)


# 11. Save decrypted EHR as CSV
with open("EHR_decrypted.csv", "wb") as f:
    f.write(ehr_data)


print("EHR decrypted successfully!")
print("Saved as: EHR_decrypted.csv")