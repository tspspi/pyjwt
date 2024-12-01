# JSON Web Token

This is an implementation of JSON web tokens.

## Overview

* [JSON Web Keys](./jwk.md) wraps the keys (and internally also the
  signature and encryption primitives) used by this library
* [JSON Web Signatures](./jws.md) provide signature operations including
  signing of JSON Web Tokens as well as the verification of signatures
* [JSON Web Encryption](./jwe.md) provides encryption operations for
  single and multiple recipients
* [JSON Web Token](./jwt.md) provides a generic parsing method that works
  independent of the token type
* [Keystore](./keystore.md) provides an library specific keystore
  implementation that is capable of importing and exporting as well
  as indexing JWK structures.
