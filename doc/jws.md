# JSON Web Signature (JWS)

The JWS subsystem allows to sign arbitrary payload (most of the time it will
be again JSON payload). The JWS module supports compact and JSON serialization.
When utilizing JSON serialization multiple signatures are possible per payload.
This is for example utilized for key certifications.

## Creating a new signature

To sign new payload one utilizes the ```JWS.create``` method:

```
JWS.create(
    payload,
    signaturekeys,
    payloadtype = "JWT",
    payloadcontenttype = None,
    compact = False,
    add_kids = True,
    alg = None
)
```

* ```payload``` is the payload that should be signed. Some payloads are automatically
  recognizes:
   * ```dict``` is automatically serialized into JSON, if no ```payloadcontenttype```
     is specified its automatically set to ```application/json```
   * ```str``` is serialized as string. If no content type is set it's set to ```text/plain```
   * Byte sequences are serialized into base64 encoded octet strings, the content type
     is automatically set to ```application/octet-string```
   * ```JWS```, ```JWE``` and ```JWK``` objects are stored in their JSON serialization,
     the ```payloadcontentype``` is set to ```JWT``` or ```jwk+json``` as specified in the RFC.
* ```signaturekeys``` can be either a single JWK or a list of JWKs that should be
  used to sign the payload
* ```payloadtype``` should not be changed
* ```compact``` selects either JSON serialization (False) or compact serialization (True).
  Keep in mind that in compact serialization only a single signature key can be used.
* ```add_kids``` enabled adding key IDs to the signature header for easier selection of the
  key (True) or disables it for enhanced privacy (False)

## Adding signatures to an existing JWS

For JSON serialization one can add additional signatures to an already existing JWS:

```
jws.add_signature(
    key,
    add_kids = True,
    alg = None
)
```

This can be used to sign data that is already existing (for example to certify key validity)

## Accessing payload

This can be done using the ```get_payload()``` method. Payload is automatically deserialized
if it's one of the supported data types.

## Outputting serialized data

Outputting is done using ```to_json``` - also for compact serialization. Note that in compact
serialization no JSON is outputted, only a string.

```
jws.to_json(
    indent = None
)
```

The ```indent``` parameter can be used to trigger pretty printed output and specifies the number
of spaces to use for indention.

## Parsing a JWS

A JWS can directly be pased using ```JWS.parse(data, keystore=None)```. Usually it's a better
idea to use the generic ```parse_jwt``` method when one parses a JWT though.

## ToDo

* Implementing key expiration and other specified flags during validation
* Allowing access to valid state of all signatures from outside without accessing private variables
