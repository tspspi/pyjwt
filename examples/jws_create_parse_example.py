from jws import JWS
from keystore import Keystore

# This example demonstrates how to create and parse a JSON Web Signature (JWS).
# A JWS is a compact, URL-safe means of representing signed content using JSON-based data structures.

from jwk import JWK_Shared

# Sample payload
payload = {"sub": "1234567890", "name": "John Doe", "admin": True}

# Create a JWK for signing
jwk = JWK_Shared.create(secret=b"secret", use="sig", key_id="test-key")

# Create a keystore and add the key
keystore = Keystore()
keystore.add(jwk)

# Create a JWS (note: signaturekeys parameter expects JWK, not keystore)
jws = JWS.create(payload, signaturekeys=jwk, compact=True)
print("Created JWS:", jws.to_json())

# Parse the JWS
parsed_jws = JWS.parse(jws.to_json(), keystore=keystore)
print("Parsed Payload:", parsed_jws.get_payload())