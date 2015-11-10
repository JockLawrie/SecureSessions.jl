using SecureSessions
using Base.Test
using HttpServer
using Requests

##################################################
### Set up

# Override default globals
encrypted_sessions_only = false    # Avoids requiring https for this test

# Define app
function app(req::Request)
    res = Response()
    if req.resource == "/set_secure_cookie"
	data = bytestring(req.data)
	create_secure_session_cookie(data, res, "sessionid")
    elseif req.resource == "/read_cookie"
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

##################################################
### The test

# Post data "John Smith", which will be encrypted and included in the "sessionid" cookie.
username = "John Smith"
res1     = Requests.post("http://localhost:8000/set_secure_cookie"; data = username)

# Extract the cookie from the response and post it back to the server to be decrypted.
# Compare the returned data to the data originally encrypted.
cookie = res1.cookies["sessionid"]
res2   = Requests.post("http://localhost:8000/read_cookie"; cookies = [cookie])
@test bytestring(res2.data) == username
