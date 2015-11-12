# Contents: Functions for hashing passwords using PBKDF2.

"""
Returns the hashed password as Array{UInt8, 1}.
"""
function pbkdf2(salt::Array{UInt8, 1}, password::AbstractString, niter::Int64, dklen::Int64)
    hlen = 64                    # Length of output of hash function in bytes (SHA512 >> length = 512 bits = 64 bytes)
    assert(dklen % hlen == 0)    # Assert dklen is divisible by hlen
    assert(niter >= 1000)
    derived_key = zeros(UInt8, dklen)
    nblocks     = convert(Int, round(dklen / hlen))
    for i = 1:nblocks
        dk_block_i = pbkdf2_block(salt, password, niter, i)    # dk_block_i has length hlen

	# Copy i^th block to result
	offset = (i - 1) * hlen
	for j = 1:hlen
	    derived_key[offset + j] = dk_block_i[j]
	end
    end
    derived_key
end


"""
Compute the i^th block of the derived key.
Uses SHA512 as the pseudorandom function.
"""
function pbkdf2_block(salt, password, niter, i)
    key    = password
    U0     = vcat(salt, num_to_bytearray(hton(Int32(i))))    # Length = 20 bytes = vcat(16 byte salt, 4 byte bigendian integer) 
    U1     = digest(MD_SHA, U0, key)                         # MD_SHA == SHA512
    U2     = digest(MD_SHA, U1, key)
    result = U1 $ U2
    Ujm1   = U2    # U_(j-1)
    for j = 3:niter
	Uj      = digest(MD_SHA, Ujm1, key)
	result $= Uj
	Ujm1    = Uj
    end
    result
end


### EOF
