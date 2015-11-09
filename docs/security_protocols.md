# Security Protocols

This page describes the current security protocols for SecureSessoins.jl.

As the author is not a security professional, suggestions from security professionals are very welcome.

**Note: The security of this implementation has not been verified by a security professional. Use at your own risk.**


## Secure Cookies
Each session cookie is created as follows:

- const_key, const_iv     = global constants, output from a cryptographically secure random number generator (used to encrypt session-specific secret keys)
- timestamp               = milliseconds since epoch, represented as a string
- session_key, session_iv = output from a cryptographic random number generator, unique for each session
- encrypted_session_key   = AES CBC encrypt(const_key, const_iv, session_key)
- data blob               = AES CBC encrypt(session_key, session_iv, arbitrary data)
- hmac signature          = HMAC(session_key, timestamp * data_blob)
- unencoded cookie_value  = session_iv * encrypted_secret_key * hmac signature * timestamp * data blob
- cookie_value            = base64encode(unencoded cookie value)...the encoding is for transport in an http header.

##### TODO:

- Ensure that cookie attributes are being used correctly
- Compress data before encrypting?
