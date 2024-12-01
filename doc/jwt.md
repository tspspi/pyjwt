# JSON Web Token

This is a generic parsing component that determines the type of the token
and performs the correct (JWS, JWE or JWK) deserialization. This is used
internally as well as it's the entry point that applications should utilize

```
result = parse_jwt(data, keystore=None)
```
