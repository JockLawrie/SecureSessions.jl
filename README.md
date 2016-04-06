# SecureSessions

[![Build Status](https://travis-ci.org/JockLawrie/SecureSessions.jl.svg?branch=master)](https://travis-ci.org/JockLawrie/SecureSessions.jl)
[![SecureSessions](http://pkg.julialang.org/badges/SecureSessions_0.4.svg)](http://pkg.julialang.org/?pkg=SecureSessions&ver=0.4)
[![Coverage Status](http://codecov.io/github/JockLawrie/SecureSessions.jl/coverage.svg?branch=master)](http://codecov.io/github/JockLawrie/SecureSessions.jl?branch=master)


## WARNING
**The security of this implementation has not been reviewed by a security professional. Use at your own risk.**


## Functionality
- Encrypted, tamper-proof cookies; used primarily for stateless secure sessions.
- Password hashing; used for login.


## Security Protocols
For the current status of the security protocols used see [this doc](https://github.com/JockLawrie/SecureSessions.jl/blob/master/docs/security_protocols.md).


## Usage
The API is detailed below.

Basic examples are in test/runtests.jl.

[This repo](https://bitbucket.org/jocklawrie/skeleton-webapp.jl) contains example web applications:
- Example 5 demonstrates secure cookies.
- Example 6 uses password hashing for login as well as secure cookies.

See ``docs/outline`` for a description of these examples.

## API
```julia
Pkg.add("SecureSessions")
using SecureSessions

##########################
### Secure cookies
##########################
username_is_permissible(username)    # Returns true if username adheres to a set of rules defined in the package.

# Create a secure cookie called "sessionid" and include it in the response.
# data is user-supplied, encrypted and included as part of the cookie value.
# For example, data may be a username.
create_secure_session_cookie(data, res::Response, "sessionid")

# Extract and decrypt data from the "sessionid" cookie in the request.
# This is the same user-supplied data included during the cookie's construction.
get_session_cookie_data(req::Request, "sessionid")

##########################
### Password storage
##########################
password_is_permissible(password)     # Returns true if password adheres to a set of rules defined in the package

# Store password...add salt, then hash, then store in type StoredPassword.
immutable StoredPassword
    salt::Array{UInt8, 1}
    hashed_password::Array{UInt8, 1}
end

# The constructor argument is an AbstractString
# A salt is randomly generated using a cryptographically secure RNG
sp = StoredPassword(password)
password_is_valid(password::AbstractString, sp::StoredPassword)    # Returns true if hash(sp.salt, password) == sp.hashed_password
```
