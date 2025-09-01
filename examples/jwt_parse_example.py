from jwt import parse_jwt
from keystore import Keystore
from jwk import JWK_Shared
from jws import JWS

# This example demonstrates how to create and parse a JSON Web Token (JWT).
# A JWT is a compact, URL-safe means of representing claims to be transferred between two parties.

# Create a JWK for signing
jwk = JWK_Shared.create(secret=b"my-secret-key", use="sig", key_id="test-key")

# Create a keystore and add the key
keystore = Keystore()
keystore.add(jwk)

# Create sample JWT payload (claims)
payload = {
    "sub": "1234567890",
    "name": "John Doe", 
    "admin": True,
    "iat": 1516239022
}

# Create a JWT (which is a JWS with typ: JWT)
jwt = JWS.create(payload, signaturekeys=jwk, compact=True)
jwt_token = jwt.to_json()

print("Created JWT:", jwt_token)

# Parse the JWT token
parsed_jwt = parse_jwt(jwt_token, keystore=keystore)
print("Parsed JWT payload:", parsed_jwt.get_payload())