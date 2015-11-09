# Contents: Utility functions for SecureSessions.jl


"Cryptographically secure RNG"
function csrng(numbytes::Integer)
    entropy = MbedTLS.Entropy()
    rng     = MbedTLS.CtrDrbg()
    MbedTLS.seed!(rng, entropy)
    rand(rng, numbytes)
end


"""
Returns: Milliseconds since the epoch.

Takes 13 characters (valid until some time around the year 2287).
"""
function get_timestamp()
    1000 * convert(Int, Dates.datetime2unix(now()))
end
