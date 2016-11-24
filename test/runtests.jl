using SecureSessions
using Base.Test
using HttpServer
using URIParser
using Requests


##################################################
### Test username and password permissibility
username1 = "John Smith"
username2 = "<script>do_something_terrible();</script>"
@test  username_is_permissible(username1)
@test !username_is_permissible(username2)

password1 = "v@l1d_pasSw0rd"
password2 = "bad_password"
@test  password_is_permissible(password1)
@test !password_is_permissible(password2)


##################################################
### Test secure cookies

# Override default globals
encrypted_sessions_only = false    # Avoids requiring https for this test

# Define app
function app(req::Request)
    res = Response()
    uri = URI(req.resource)
    if uri.path == "/set_secure_cookie"
	data = String(copy(req.data))
	create_secure_session_cookie(data, res, "sessionid")
    elseif uri.path == "/read_cookie"
        res.data = get_session_cookie_data(req, "sessionid")
    else
	res.status = 404
    end
    res
end

# Define and run server
server = Server((req, res) -> app(req))
@async run(server, port = 8000)
sleep(1.0)

# Post data "John Smith", which will be encrypted and included in the "sessionid" cookie.
username = "John Smith"
res1     = Requests.post("http://localhost:8000/set_secure_cookie"; data = username)

# Extract the cookie from the response and post it back to the server to be decrypted.
# Compare the returned data to the data originally encrypted.
cookie = res1.cookies["sessionid"]
res2   = Requests.post("http://localhost:8000/read_cookie"; cookies = [cookie])
@test String(copy(res2.data)) == username


##################################################
### Test password hashing
sp = StoredPassword("pwd_alice")
@test  password_is_valid("pwd_alice", sp)
@test !password_is_valid("pwd_bob",   sp)


# EOF
