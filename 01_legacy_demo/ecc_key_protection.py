from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Generate ECC private key
private_key = ec.generate_private_key(ec.SECP256R1())

# Get the corresponding public key
public_key = private_key.public_key()

# Save private key
with open("ecc_private_key.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# Save public key
with open("ecc_public_key.pem", "wb") as f:
    f.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("ECC key pair generated successfully!")
print("Private key saved to ecc_private_key.pem")
print("Public key saved to ecc_public_key.pem")