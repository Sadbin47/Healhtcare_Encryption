from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

# Generate a random 256-bit AES key
key = AESGCM.generate_key(bit_length=256)

# Save the key to a text file
with open("aes_key.txt", "w") as f:
    f.write(base64.b64encode(key).decode())

print("AES-256 key generated successfully!")
print("AES key saved to aes_key.txt")