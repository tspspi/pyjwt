# JSON Web Encryption (JWE)

The JWE module implements the encryption layer. This can be used with or without
the signature layer to provide confidentiality.

Currently this module supports the following content encryption mechanisms:

* ```A128GCM```
* ```A192GCM```
* ```A256GCM```
* ```A128CBC-HS256```
* ```A192CBC-HS384```
* ```A256CBC-HS512```

## Encrypting payload

Encrypting new data can be done using the `create` method. Note that in compact
serialization, only a single recipient can be used, whereas in JSON serialization,
multiple recipients can be utilized.

```
JWE.create(
    payload,
    recipient_keys,
    cty = None,
    alg = None,
    enc = None,
    compact = False,
    add_kids = True,
    typ = "JWT"
)
```

* ```payload``` is the payload that should be supported. Different payload types
  are threatened differently:
   * ```dict``` is serialized into a JSON dictionary, if no ```cty``` is specified
     it is set to ```application/json```
   * ```JWS``` and ```JWE``` is properly serialized and the ```cty``` set to ```JWT```
   * ```str``` is encoded as raw string, the ```cty``` is set to ```text/plain```
   * A ```bytes``` payload is base64 encoded, the ```cty``` is set to ```application/octet-stream```
   * ```JWK``` is serialized properly, ```cty``` is set to ```json+jwk```
* ```recipient_keys``` can be either a single key or a list of keys for which the
  encryption should be performed. These should either be JWKs that contain public keys
  or a shared key of a recipient.
* ```alg``` and ```enc``` can be utilized to perform algorithm and encryption mechanism
  selection
* ```compact``` selects either single recipient compact serialization (True) or JSON serialization
  that supports also multiple recipients (False)
* ```add_kids``` controls the inclusion of the key IDs in the protected header. If they are
  present recipients are faster selecting recipient keys but it's of course also leaked who
  the recipients of a message is. If they are not included a recipient has to try all
  of it's known private keys to determine if he is capable of decoding a message which may
  lead to significant computational load.
* ```typ``` should always be ```JWT```

## Serializing

To serialize a JWE object one utilizes the ```to_json(indent = None)``` method. This
is also used for serialization in case compact serialization is used. In this case no
JSON is returned but only a compact string.

## Parsing

One can explicitly parse a JWE using the static `parse` method:

```
JWE.parse(
    jdata,
    keystore = None
)
```

In case a ```keystore``` is specified the system tries to utilize all known private keys
to decrypt the payload if possible. In case no key is found there is no decrypted payload.

## Accessing payload

```
jwe.get_payload()
```


