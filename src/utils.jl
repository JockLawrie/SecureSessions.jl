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


"""
Returns true if username adheres to the following formatting rules:
1) length(username) <= 20
2) username contains none of the following tags:
       "<script>", "<link>", "<img>", "<iframe>", "<object>"
"""
function username_is_permissible(username)
    result = length(username) <= 20
    if result
        bad_tags = ["<script>", "<link>", "<img>", "<iframe>", "<object>"]
        for tag in bad_tags
            if contains(username, tag)
                 result = false
                 break
            end
        end
    end
    result
end


"""
Returns true is password adheres to the following formatting rules:
1) TODO: To be specified.
"""
function password_is_permissible(password)
    true  # TODO: implement this function
end
