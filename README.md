scripts provides an EdDSA object that can sign and verify messages and signatures

supports phEdDSA, ctxEdDSA, pureEdDSA
supports both curve25519 and curve448 signatures. 

Usage:
Object: EdDSA(mode, ph, ctx, private_key)
    - mode: 1 or 2. 1 will use curve 25519, 2 will use curve448
    - ph: default False. True: message will be hashed before being signedn
    - ctx: default empty, Context to be added to a signature. may not be longer than 255 bytes.
    - private_key: default None, if no private key is specified, one will be emitted during the signing process.

Example Ed448:

object = EdDSA(2)
signature, public_key, priv_key = object.sign(message)
assert(object.verify(signature, public_key, message))

further improvements can be made towards the curve arithmetic.