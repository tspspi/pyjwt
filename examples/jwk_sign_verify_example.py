from jwk import JWK

# This example demonstrates how to sign and verify data using JSON Web Key (JWK).
# A JWK is a JSON data structure that represents a cryptographic key.

from jwk import JWK_Shared

# Sample payload
payload = b"This is a message to be signed."

# Create a shared secret JWK for signing and verifying
jwk = JWK_Shared.create(secret=b"secret", use="sig")

# Sign the payload
signature = jwk.sign(payload)
print("Signature:", signature.hex())

# Verify the signature
is_valid = jwk.verify(payload, signature)
print("Is the signature valid?", is_valid)