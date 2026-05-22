-- Strips Config.Env from Docker /containers/<id>/json responses so secrets
-- in container env vars don't leak through the proxy.
--
-- HAProxy ≥2.5 forbids channel manipulation in HTTP mode, so we can't
-- rewrite the response body via http-response. Instead this opens its own
-- connection to the docker socket, fetches the inspect JSON, scrubs Env,
-- and returns the modified body via the Reply API.
core.register_action("inspect_handler", {"http-req"}, function(txn)
    local socket_path = os.getenv("SOCKET_PATH") or "/var/run/docker.sock"
    local sock = core.tcp()
    if not sock:connect(socket_path) then return end

    sock:send("GET " .. txn.f:path() .. " HTTP/1.1\r\n"
        .. "Host: docker\r\nConnection: close\r\n\r\n")

    local response = ""
    while true do
        local chunk = sock:receive("*a")
        if not chunk or #chunk == 0 then break end
        response = response .. chunk
    end
    sock:close()

    local hdr_end = response:find("\r\n\r\n", 1, true)
    if not hdr_end then return end
    local headers_raw = response:sub(1, hdr_end - 1)
    local body = response:sub(hdr_end + 4)

    if headers_raw:lower():find("transfer%-encoding:%s*chunked") then
        local decoded, p = {}, 1
        while p <= #body do
            local nl = body:find("\r\n", p, true)
            if not nl then break end
            local sz_hex = body:sub(p, nl - 1):match("^[0-9a-fA-F]+")
            if not sz_hex then break end
            local sz = tonumber(sz_hex, 16)
            if sz == 0 then break end
            table.insert(decoded, body:sub(nl + 2, nl + 1 + sz))
            p = nl + 2 + sz + 2
        end
        body = table.concat(decoded)
    end

    local new_body = body:gsub('"Env"%s*:%s*%b[]', '"Env":[]')
    local status = tonumber(response:match("HTTP/1%.%d (%d+)")) or 200

    local reply = txn:reply{
        status = status,
        headers = {
            ["content-type"]   = {"application/json"},
            ["content-length"] = {tostring(#new_body)},
        },
        body = new_body,
    }
    txn:done(reply)
end)
