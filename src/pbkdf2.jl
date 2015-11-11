# Contents: Functions for hashing passwords using PBKDF2.

function pbkdf2(salt, password)
    c = 1000                  # Number of iterations
    dklen = TODO              # Length of derived key
    hlen = TODO    # Length of output of hash function

    derived_key = zeros(UInt8, dklen)
    nblocks = convert(Int, round(dklen / hlen))
    for i = 1:nblocks
        result_i = pbkdf2_block(password, salt, c, i)
	offset = (i - 1) * blocksize
	for j = 1:blocksize    # Copy result_i to result
	    result[offset + j] = result_i[j]
	end
    end
    derived_key
end


function pbkdf2_block(password, salt, c, i)
    # Compute the i^th block of the derived key
    data = salt * string(hton(convert(Int32, i)))
    U1 = digest("sha256", password, data)
    U2 = digest("sha256", password, U1)
    result = U1 $ U2
    U = U2
    for j = 3:c
        U = digest("sha256", password, U)
	result = U $ result
    end
    result
end


### EOF
