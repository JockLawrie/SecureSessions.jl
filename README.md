# SecureSessions

[![Build Status](https://travis-ci.org/JockLawrie/SecureSessions.jl.svg?branch=master)](https://travis-ci.org/JockLawrie/SecureSessions.jl)
[![codecov.io](http://codecov.io/github/JockLawrie/SecureSessions.jl/coverage.svg?branch=master)](http://codecov.io/github/JockLawrie/SecureSessions.jl?branch=master)


## WARNING
**The security of this implementation has not been reviewd by a security professional. Use at your own risk.**


## Functionality
- Encrypted, tamper-proof cookies; used primarily for stateless secure sessions.
- Password hashing; used for login.


## Usage
Basic examples are in test/runtests.jl.

[This repo](https://bitbucket.org/jocklawrie/skeleton-webapp.jl) contains example web applications:
- Example 5 demonstrates secure cookies.
- Example 6 uses password hashing for login and secure cookies for encrypted tamper-proof sessions.

See ``docs/outline`` for a description of these examples.


## Security Protocols
For the current status of the security protocols used see [this doc](https://github.com/JockLawrie/SecureSessions.jl/blob/master/docs/security_protocols.md).
