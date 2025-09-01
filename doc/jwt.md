# JSON Web Token

This is a generic parsing component that determines the type of the token
and performs the correct (JWS, JWE, or JWK) deserialization. It is used
internally and serves as the entry point that applications should utilize.

```
result = parse_jwt(data, keystore=None)
```
