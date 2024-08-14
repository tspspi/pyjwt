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

## Generic interface

```
class JWK:
   def get_id(self)
   def sign(self, payload, alg = None)
   def verify(self, payload, signature, alg = None)
```

## Shared Key / Octet

The shared key interface is used for HMACs and cryptography with
a shared key. Those operations are more performant than public key
schemas but require the key to be present on all components of the
system. In contrast to public key schemas this increases the attack
surface (number of components that can leak a key that is capable
of signing tokens). Signatures are usually smaller.

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
newkey = JWK_RSA()
```

