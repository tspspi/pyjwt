# Keystore interface

The keystore is a class that contains either JWK (JSON Web Keys)
or JWKSets (i.e. lists of JSON Web Keys). It acts as the trust and
key repository of the ```pyjwt``` library.

## Initializing an empty keystore

One can simply initialize an empty keystore by instantiating the
class:

```
ks = Keystore()
```

## Adding keys

To add a newly generated or loaded JWK one simply can use ```add```:

```
newkey1 = JWK_RSA.create(2048, key_ops = [ "sign", "verify", "encrypt", "decrypt" ], key_id="RSA test key")
newkey2 = JWK_Shared.create(key_ops = [ "sign", "verify", "encrypt", "decrypt" ], key_id = "Shared test key")

ks.add(newkey1)
ks.add(newkey2)
```

## Iterating over keys

### Iterating over all keys

Sometimes one needs to iterate over all keys. The library also does this
in case encryption or signature keys had been used that have no key id
attached. One can filter by usage or operation.

```
for key in ks.iterate("enc", "encrypt"):
    # Do whatever you want
```

### Iterating over all keys with a given ID

Sometimes one only wants to iterate over all keys with a given key ID. This
can be done using ```iterate_by_id```:

```
for key in ks.iterate_by_id("TestKey", "enc", "encrypt"):
    # Do whatever you want
```

## Currently not implemented

### Serializing into JSON form

```
ks.to_json(indent = None, include_private = False)
```

This method has two parameters.

* ```indent``` can specify a number of spaces to use for JSON pretty
  printing indention. If set to None pretty printing is not used.
* ```include_private``` controls if private keys are included 
  in the JSON dump. By default they are not.

### Store and load

```
ks.store(filename, include_private = False)
```

### Loading from a File
```
Keystore.load(filename)
```

```
Keystore.load(filename)
```
