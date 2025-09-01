from jwk import JWK

# This example demonstrates how to encrypt and decrypt data using JSON Web Key (JWK).
# A JWK is a JSON data structure that represents a cryptographic key.
# Note: Shared secret keys (oct) do not support encryption - only RSA keys do.

from jwk import JWK_RSA

# Sample payload
payload = b"This is a secret message."

# Create an RSA JWK for encryption and decryption
jwk = JWK_RSA.create(bits=2048, use="enc")

# Encrypt the payload
encrypted_payload = jwk.encrypt(payload)
print("Encrypted Payload:", encrypted_payload)

# Decrypt the payload
decrypted_payload = jwk.decrypt(encrypted_payload)
print("Decrypted Payload:", decrypted_payload.decode('utf-8'))