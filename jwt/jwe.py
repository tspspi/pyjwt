class JWE:
    def __init__(
        self
    ):
        pass

    @staticmethod
    def create(
        payload,
        recipient_keys,
        cty = None,
        alg = None,
        enc = None,
        compact = False,
        add_kids = True
    ):
        # Validate parameters
        if not isinstance(recipient_keys, list):
            recipient_keys = [ recipient_keys, ]

        for k in recipient_keys:
            if not isinstance(k, JWK):
                raise ValueError("Recipient keys have to be JWK instances")

        if alg is not None:
            if not isinstance(alg, list):
                alg = [ alg, ]
        else:
            alg = [ ]
            for i in range(len(recipient_keys)):
                alg.append(None)
        if len(alg) != len(recipient_keys):
            raise ValueError("alg is specified but length differs from number of recipient keys")

        if compact and (len(recipient_keys) > 1):
            raise ValueError("Compact serialization is only possible for a single recipient key")
        if len(recipient_keys) == 0:
            raise ValueError("At least one recipient has to be specified")

        if cty is None:
            if isinstance(payload, dict):
                cty = "application/json"
            elif isinstance(payload, JWS) or isinstance(payload, JWE):
                cty = "JWT"
            elif isinstance(payload, str):
                cty = "text/plain"
            elif isinstance(payload, bytes):
                cty = "application/octet-stream"
            elif isinstance(payload, JWK):
                cty = "jwk+json"
            else:
                raise ValueError("Content type not specified and not auto-detectable")

        if isinstance(payload, dict):
            payload = base64url_encode(json.dumps(payload).encode("utf-8"))
        elif isinstance(payload, JWS) or isinstance(payload, JWE):
            payload = payload.to_json().encode("utf-8")
        elif isinstance(payload, str):
            payload = payload.encode("utf-8")
        elif isinstance(payload, bytes):
            pass
        elif isinstance(payload, JWK):
            payload = payload.to_json().encode("utf-8")
        else:
            raise ValueError("Payload data type not supported")
 

        # enc can be:
        #   A128CBC-HS256 
        #   A192CBC-HS384
        #   A256CBC-HS512
        #   A128GCM
        #   A192GCM
        #   A256GCM
        #
        # alg can be one of the encryption algorithms supported by they JWK itself.
        # This is also processed by the JWK

        if enc is None:
            # Set our default encryption algorithm
            enc = "A256GCM"
        if enc not in [ "A128GCM", "A192GCM", "A256GCM" ]:
            raise ValueError(f"Content encryption algorithm {enc} not supported")

        encbits = None
        if enc in [ "A128GCM", "A128CBC-HS256" ]:
            encbits = 128
        elif enc in [ "A192GCM", "A192CBC-HS384" ]:
            encbits = 192
        elif enc in [ "A256GCM", "A256CBC-HS512" ]:
            encbits = 256

        for ialg, a in enumerate(alg):
            if a is None:
                alg[ialg] = recipient_keys[ialg].get_enc_alg()


        # Header parameters:
        #   alg
        #   enc
        #   typ = "JWT"
        #   cty: Content type (see above)

        # There is a generic and a per recipient header (in compact serialization
        # they are merged for a single recipient). The generic header includes
        # the "enc" header, "typ" and "cty".
        #
        # The per recipient header includes "alg" and optionally the "kid"
        #
        # For compact serialization we have to include alg in the generic header
        # (since this is added as AAD we cannot change from compact to JSON later on!)


        genheader = {
            "enc" : enc
        }

        if compact:
            genheader.update({
                "alg" : alg[0]
            })
            if add_kids and (recipient_keys[0]._kid is not None):
                genheader.update({
                    "kid" : recipient_keys[0]._kid
                })
        encoded_header = base64url_encode(json.dumps(genheader).encode("utf-8"))

        # Generate random CEK matching bit length of our AES algorithm
        cek = get_random_bytes(encbits // 8)

        # For each recipient encrypt the CEK and add to our recipients array
        recipients = []
        for ik, k in recipient_keys:
            newenccek = k._encrypt(cek, alg = alg[ik])
            recipients.append({
                "header" : { "alg" : alg[ik] }
                "encrypted_key" : base64url_encode(newenccek)
            })
            if add_kids and (k._kid is not None):
                recipients[-1]["header"].update({
                    "kid" : k._kid
                })

        # Encrypt AES payload. Include the generic header as AAD; Store IV too ...
        iv = get_random_bytes(12)
        cipher = AES.new(cek, AES.MODE_GCM, nonce=iv)
        cipher.udpate(encoded_header.encode("utf-8"))
        ciphertext, tag = cipher.encrypt_and_digest(payload)

        # Either build compact serialization or initialize our local structures for JSON
        encoded_iv = base64url_encode(iv)
        encoded_ciphertext = base64url_encode(ciphertext)
        encoded_tag = base64url_encode(tag)


        # ToDo: Dont use self here ...
        if compact:
            # Store data for compact serialization
            compact_serialization = f"{encoded_header}.{recipients[0]['encrypted_key']}.{encoded_iv}.{encoded_ciphertext}.{encoded_tag}"
        else:
            # Store data for JSON serialization
            #encoded_ciphertext
            #encoded_tag
            #encoded_iv
            #encoded_header
            pass
