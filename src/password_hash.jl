# Contents: Functions for hashing passwords.


immutable StoredPassword
    salt::Array{UInt8, 1}
    hashed_password::Array{UInt8, 1}
end


"""
Stores user-specific salt and hashed password in password_store.

password_store: username => StoredPassword

The algorithm:
1) Generate a 16 byte (128 bit) salt using a cryptographically secure RNG.
2) Hash the salted password using PBKDF2.
3) Store the salt and the hashed password in password_store.
"""
function set_password(username::AbstractString, password::AbstractString, password_store::Dict{AbstractString, StoredPassword})
    salt                     = csrng(16)
    hashed_password          = compute_hashed_password(salt, password)
    password_store[username] = PasswordStore(salt, hashed_password)
end


"""
Returns true if hash(password) == username's stored hashed password.

The algorithm:
1) Retrieve username's salt and hashed password from io.
2) Compute hash(salt, password)
3) Return true if hash(password) == username's stored hashed password
"""
function username_password_are_valid(username::AbstractString, password::AbstractString, password_store::Dict{AbstractString, StoredPassword})
    result = false
    sp     = password_store[username]
    hp     = compute_hashed_password(sp.salt, password)
    if hp == sp.hashed_password
	result = true
    end
    result
end


"Selects and applies password hashing algorithm."
function compute_hashed_password(salt, password)
    pbkdf2(salt, password)
end


### EOF
