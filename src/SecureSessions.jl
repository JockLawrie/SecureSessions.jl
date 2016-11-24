module SecureSessions


using HttpServer
using MbedTLS


export
# Secure cookies
    create_secure_session_cookie,
    get_session_cookie_data,
    invalidate_cookie!,
# Password hashing
    StoredPassword,
    password_is_valid,
    password_is_valid,
# utils
    username_is_permissible,
    password_is_permissible


include("utils.jl")
include("secure_cookies.jl")
include("password_hash.jl")
include("pbkdf2.jl")


# Globals
session_timeout = 5 * 60 * 1000        # Duration of a session's validity in milliseconds
key_length      = 32                   # Key length for AES 256-bit cipher in CBC mode
block_size      = 16                   # IV  length for AES 256-bit cipher in CBC mode
const_key       = csrng(key_length)    # Symmetric key for encrypting secret_keys (with 256-bit encryption)
const_iv        = csrng(block_size)    # IV for encrypting secret_keys
http_only       = true
encrypted_sessions_only = true
timeout_str     = string(convert(Int64, 0.001 * session_timeout))    # Session timeout in seconds, represented as a string


end # module
