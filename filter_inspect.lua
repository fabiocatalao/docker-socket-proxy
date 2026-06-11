-- Strips Config.Env from Docker /containers/<id>/json responses so secrets
-- in container env vars don't leak through the proxy.
--
-- HAProxy ≥2.5 forbids channel manipulation in HTTP mode, so we can't
-- rewrite the response body via http-response. Instead this opens its own
-- connection to the docker socket, fetches the inspect JSON, scrubs Env,
-- and returns the modified body via the Reply API.

-- Replace every "Env":[...] in body with "Env":[].
--
-- We can't use body:gsub('"Env"%s*:%s*%b[]', '"Env":[]') because Lua's
-- %b[] doesn't understand JSON string escaping: an env value containing
-- an un-paired ] (e.g. FOO=]bar) would close the balance counter early
-- and leave the rest of the array un-stripped (plus break the JSON).
-- This scanner tracks JSON string state so brackets inside strings are
-- ignored, and only matches the array's true closing ].
local function strip_env(body)
    local out, pos = {}, 1
    while true do
        local s, e = body:find('"Env"%s*:%s*%[', pos)
        if not s then
            out[#out + 1] = body:sub(pos)
            break
        end
        out[#out + 1] = body:sub(pos, s - 1)
        out[#out + 1] = '"Env":[]'
        local depth, in_str, i = 1, false, e + 1
        while i <= #body and depth > 0 do
            local c = body:sub(i, i)
            if in_str then
                if c == "\\" then i = i + 1
                elseif c == '"' then in_str = false end
            elseif c == '"' then in_str = true
            elseif c == "[" then depth = depth + 1
            elseif c == "]" then depth = depth - 1
            end
            i = i + 1
        end
        if depth ~= 0 then return body end
        pos = i
    end
    return table.concat(out)
end

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

    local new_body = strip_env(body)
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
