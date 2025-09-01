# Documentation: JSON Web Keys

The following document summarizes the JWK implementation.
The JWK classes are the base for all other operations like
JSON Web Tokens, JSON Web Signatures and JSON Web Encryption.
They actually contain the signing, verification and cryptography
primitives. Each JWK itself canbe serialized into a JSON
structure itself - optionally including the private key.

Each JWK can have:

* A usage like ```sig``` or ```enc```. This can limit the key
  usage to signature or encryption operations
* A more detailed ```key_ops``` list that controls if the key
  can be used for:
   * ```sign```: Signing data (requires private key)
   * ```verify```: Verify the validitiy of a signature (not the trust)
   * ```encrypt``` or ```decrypt```
   * ```wrapKey``` and ```unwrapKey```
   * ```deriveKey``` and ```deriveBits```
* An optional ```alg``` parameter that limits the usage of the key
  for a given algorithm.

## Currently supported algorithms

| Class | Algorithm | Usage |
| --- | --- | --- |
| ```JWK_Shared``` | ```HS256```, ```HS384```, ```HS512``` | ```sign```, ```verify``` |
| ```JWK_RSA``` | ```PS256```, ```PS384```, ```PS512``` | ```sign```, ```verify``` |
| ```JWK_RSA``` | ```RS256```, ```RS384```, ```RS512``` | ```sign```, ```verify``` |
| ```JWK_RSA``` | ```RSA1_5```, ```RSA-OAEP```, ```RSA-OAEP-256``` | ```encrypt```, ```decrypt``` |

## Generic interface

```
```python
class JWK:
    def get_id(self)
    def sign(self, payload, alg = None)
    def verify(self, payload, signature, alg = None)
    def encrypt(self, payload, alg = None)
    def decrypt(self, payload, alg = None)

    @staticmethod
    def from_json(jdata)
```
```

## Shared Key / Octet

The shared key interface is used for HMACs and cryptography with
a shared key. Those operations are more performant than public key
schemas but require the key to be present on all components of the
system. In contrast to public key schemas this increases the attack
surface (number of components that can leak a key that is capable
of signing tokens). Signatures are usually smaller and verification
as well as signature a little bit faster.

```
class JWK_Shared:
   def get_sign_alg(self)
   def to_json(self, indent = None)

   @staticmethod
   def from_json(jsondata)

   @staticmethod
   def create(secret = None, key_id = None, use = None, key_ops = None, alg = None)
```

To create a new random key:

```
newkey = JWK_Shared.create()
```

To wrap a real shared secret:

```
newkey = JWK_Shared.create("my shared key")
```

## RSA Keys

RSA keys support PSS and PKCS#1 v1.5 signatures as well as RSA-OAEP and PKCS#1 v1.5
encryption. It's prefered to use PSS and RSA-OAEP-256 (those are also the default algorithms).
RSA is more secure to shared keys in most cases.

```
class JWK_RSA:
   def get_sign_alg(self)
   def to_json(self, indent = None)

   @staticmethod
   def from_json(jsondata)

   @staticmethod
   def create(bits = 4096, key_id = None, use = None, key_ops = None, alg = None)
```

Creating a new RSA key:

```
newkey = JWK_RSA.create(
    bits = 4096,
    key_id = "Test Key",
    key_ops = [ "sign", "verify", "encrypt", "decrypt" ]
)
```

