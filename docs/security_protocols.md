# Security Protocols

This page describes the current security protocols for SecureSessoins.jl.

As the author is not a security professional, suggestions from security professionals are very welcome.

**Warning: The security of this package has not been reviewed by a security professional. Use at your own risk.**


## Secure Cookies
Each session cookie is created as follows:

- const_key, const_iv     = global constants, output from a cryptographically secure random number generator (used to encrypt session-specific secret keys)
- timestamp               = milliseconds since epoch, represented as a string
- session_key, session_iv = output from a cryptographic random number generator, unique for each session
- encrypted_session_key   = AES CBC encrypt(const_key, const_iv, session_key)
- data blob               = AES CBC encrypt(session_key, session_iv, arbitrary data)
- hmac signature          = HMAC(session_key, timestamp * data_blob)
- unencoded cookie_value  = session_iv * encrypted_session_key * hmac signature * timestamp * data blob
- cookie_value            = base64encode(unencoded cookie value)...the encoding is for transport in an http header.

##### TODO:

- Ensure that cookie attributes are being used correctly
- Compress data before encrypting?


## Password Hashing

A given password is hashed using the following algorithm:

1. Generate a 16 byte (128 bit) salt using a cryptographically secure RNG.
2. Hash the salted password using PBKDF2 with:
	- SHA-512 as the pseudorandom function
	- 5000 iterations
	- A 512-bit derived key length
