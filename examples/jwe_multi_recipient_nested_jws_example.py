from jwe import JWE
from jws import JWS
from keystore import Keystore
from jwk import JWK_RSA
from jwt import parse_jwt
import json

# This example demonstrates JWE with multiple recipients and nested JWS signature.
# It shows a complete flow where:
# 1. A sender signs a message (inner JWS layer)
# 2. The signed message is encrypted for multiple recipients (outer JWE layer)
# 3. Each recipient can decrypt and verify the signature

print("=== JWE Multi-Recipient with Nested JWS Example ===\n")

# Step 1: Create RSA keys for sender and multiple recipients
print("Step 1: Creating RSA keys...")

# Sender's key for signing
sender_key = JWK_RSA.create(bits=2048, use="sig", key_id="sender-key")
print(f"Created sender key: {sender_key.get_id()}")

# Multiple recipient keys for encryption
alice_key = JWK_RSA.create(bits=2048, use="enc", key_id="alice-key")
bob_key = JWK_RSA.create(bits=2048, use="enc", key_id="bob-key")  
charlie_key = JWK_RSA.create(bits=2048, use="enc", key_id="charlie-key")

print(f"Created recipient keys: {alice_key.get_id()}, {bob_key.get_id()}, {charlie_key.get_id()}")

# Step 2: Create original message payload
original_message = {
    "from": "sender@example.com",
    "to": ["alice@example.com", "bob@example.com", "charlie@example.com"],
    "subject": "Confidential Meeting Notes",
    "message": "The quarterly review meeting is scheduled for next Monday at 2 PM.",
    "timestamp": "2024-01-15T10:30:00Z",
    "classification": "confidential"
}

print(f"\nStep 2: Original message:\n{json.dumps(original_message, indent=2)}")

# Step 3: Create inner JWS layer (sender signs the message)
print(f"\nStep 3: Creating signed JWS with sender's key...")
signed_jws = JWS.create(
    payload=original_message,
    signaturekeys=sender_key,
    compact=True
)

jws_token = signed_jws.to_json()
print(f"Created JWS token: {jws_token[:80]}...")

# Step 4: Create outer JWE layer with multiple recipients
print(f"\nStep 4: Creating JWE with multiple recipients...")
recipient_keys = [alice_key, bob_key, charlie_key]

encrypted_jwe = JWE.create(
    payload=signed_jws,  # The JWS token becomes the payload
    recipient_keys=recipient_keys,
    compact=False,  # Must use JSON serialization for multiple recipients
    cty="JWT"  # Content type indicates nested JWT/JWS
)

jwe_json = encrypted_jwe.to_json(indent=2)
print(f"Created JWE with {len(recipient_keys)} recipients")
print(f"JWE structure:\n{jwe_json}")

# Step 5: Create keystores for each recipient to simulate decryption
print(f"\nStep 5: Simulating decryption by each recipient...")

recipients = [
    ("Alice", alice_key),
    ("Bob", bob_key), 
    ("Charlie", charlie_key)
]

for recipient_name, recipient_key in recipients:
    print(f"\n--- {recipient_name}'s decryption process ---")
    
    # Create keystore with recipient's private key
    recipient_keystore = Keystore()
    recipient_keystore.add(recipient_key)
    
    # Decrypt the JWE
    decrypted_jwe = JWE.parse(jwe_json, keystore=recipient_keystore)
    decrypted_jws = decrypted_jwe.get_payload()
    
    if decrypted_jws is not None:
        print(f"✅ {recipient_name} successfully decrypted JWE")
        
        # Create keystore with sender's public key for signature verification
        verification_keystore = Keystore()
        verification_keystore.add(sender_key)  # In practice, this would be sender's public key
        
        # Verify the inner JWS signature
        verified_jws = JWS.parse(decrypted_jws.to_json(), keystore=verification_keystore)
        final_payload = verified_jws.get_payload()
        
        print(f"✅ {recipient_name} successfully verified sender's signature")
        print(f"📄 Final decrypted message for {recipient_name}:")
        print(json.dumps(final_payload, indent=2))
    else:
        print(f"❌ {recipient_name} failed to decrypt: No valid key for decryption")

# Step 6: Demonstrate that a non-recipient cannot decrypt
print(f"\n--- Unauthorized access attempt ---")
unauthorized_key = JWK_RSA.create(bits=2048, use="enc", key_id="unauthorized-key")
unauthorized_keystore = Keystore()
unauthorized_keystore.add(unauthorized_key)

unauthorized_jwe = JWE.parse(jwe_json, keystore=unauthorized_keystore)
if unauthorized_jwe.get_payload() is not None:
    print("❌ Security breach! Unauthorized key was able to decrypt")
else:
    print("✅ Security maintained: Unauthorized key cannot decrypt the message")

print(f"\n=== Example completed successfully! ===")
print(f"Summary:")
print(f"- 1 sender with signing key")
print(f"- 3 recipients with encryption keys") 
print(f"- Message signed by sender (inner JWS)")
print(f"- Signed message encrypted for all recipients (outer JWE)")
print(f"- Each recipient can decrypt and verify authenticity")
print(f"- Non-recipients cannot access the content")