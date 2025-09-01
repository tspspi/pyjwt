import json
from jwe import JWE
from keystore import Keystore
from jwk import JWK_RSA

# This example demonstrates how to create and parse a JSON Web Encryption (JWE).
# A JWE is a compact, URL-safe means of representing encrypted content using JSON-based data structures.

# Sample payload
payload = {"sub": "1234567890", "name": "John Doe", "admin": True}

# Create a keystore and add an RSA JWK
keystore = Keystore()
jwk_rsa = JWK_RSA.create(bits=2048, key_ops=["encrypt", "decrypt"], key_id="RSA test key")
keystore.add(jwk_rsa)

# Create a JWE
jwe = JWE.create(payload, [jwk_rsa], compact=False)
print("Created JWE:", jwe.to_json(indent=4))

# Parse the JWE
parsed_jwe = JWE.parse(jwe.to_json(), keystore=keystore)
print("Parsed Payload:", json.dumps(parsed_jwe.get_payload(), indent=2))