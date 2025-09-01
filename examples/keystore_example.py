from keystore import Keystore

# This example demonstrates how to add keys and iterate over keys in a keystore.
# A keystore is a secure storage for cryptographic keys.

from jwk import JWK_Shared

# Create a keystore
keystore = Keystore()

# Create JWK objects and add them to the keystore
jwk1 = JWK_Shared.create(secret=b"secret1", key_id="key1", use="sig")
jwk2 = JWK_Shared.create(secret=b"secret2", key_id="key2", use="sig")

keystore.add(jwk1)
keystore.add(jwk2)

# Iterate over keys by ID
print("Iterating by ID 'key1':")
for key_entry in keystore.iterate_by_id("key1"):
    print(f"Key ID: {key_entry['key'].get_id()}")
    print(f"Key JSON: {key_entry['key'].to_json()}")

# Iterate over all keys
print("\nIterating over all keys:")
for key_entry in keystore.iterate():
    print(f"Key ID: {key_entry['key'].get_id()}")
    print(f"Key JSON: {key_entry['key'].to_json()}")