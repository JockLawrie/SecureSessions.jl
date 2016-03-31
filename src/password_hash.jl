# Contents: Functions for hashing passwords.


"""
Type for storing user-specific salt and hashed password.

The password is hashed by the constructor using the following algorithm:
1) Generate a 16 byte (128 bit) salt using a cryptographically secure RNG.
2) Hash the salted password using PBKDF2 with:
    - SHA-512 as the pseudorandom function
    - 5000 iterations
    - A 512-bit derived key length
"""
immutable StoredPassword
    salt::Array{UInt8, 1}
    hashed_password::Array{UInt8, 1}

    function StoredPassword(password::AbstractString)
	salt            = csrng(16)
	hashed_password = compute_hashed_password(salt, password)
	new(salt, hashed_password)
    end
end


"""
Returns true if hash(salt * password) == stored hashed password.

The algorithm:
1) Compute hash(salt, password), where the salt is supplied in a StoredPassword.
2) Return true if hash(password) == stored hashed password
"""
function password_is_valid(password::AbstractString, salt::Vector{UInt8}, hashed_pwd::Vector{UInt8})
    result = false
    hp     = compute_hashed_password(salt, password)
    if hp == hashed_pwd
	result = true
    end
    result
end
password_is_valid(password::AbstractString, sp::StoredPassword) = password_is_valid(password, sp.salt, sp.hashed_password)


"Selects and applies the password hashing algorithm."
function compute_hashed_password(salt::Array{UInt8, 1}, password::AbstractString)
    pbkdf2(salt, password, 5000, 64)    # 5000 iterations; dklen = 64 bytes = 512 bits
end


### EOF
