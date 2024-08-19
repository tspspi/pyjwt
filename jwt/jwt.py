import json
import base64

# Generic wrapper around JWS and JWE to allow parsing both
# automatically determining their typ. This is used internally
# when deserializing ...

def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def base64url_decode(data):
    padding = '=' * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode(data + padding)

def parse_jwt(data, keystore = None):
    # We do imports here to prevent circular import loops
    from jws import JWS
    from jwe import JWE

    if isinstance(data, str):
        # Check if we are one of the compact serializations
        parts = data.split(".")
        if len(parts) == 3:
            # This is most likely a JWS
            return JWS.parse(data, keystore)
        if len(parts) == 5:
            # This is most likely a JWE
            return JWE.parse(data, keystore)

    if not isinstance(data, dict):
        # We either have a compact serialization or 
        # a JSON string. First try to split at dots
        jdata = json.loads(data)
    else:
        jdata = data

    if "protected" not in jdata:
        # This is not a supported datatype
        raise ValueError("Not a supported JWT")
    phdr = json.loads(base64url_decode(jdata["protected"]))
    if "enc" in phdr:
        return JWE.parse(data, keystore)
    elif ("typ" in phdr) and (phdr["typ"] == "JWT"):
        return JWS.parse(data, keystore)

    # ToDo: Can it also be a JWK?

    raise ValueError("Not a supported JWT")
        
