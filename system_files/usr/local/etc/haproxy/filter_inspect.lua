-- Strips Config.Env from Docker container inspect responses
-- (GET /containers/<id>/json) so secrets passed to containers as environment
-- variables don't leak through the proxy. Enabled with HIDE_CONTAINER_ENV=1.
--
-- HAProxy >=2.5 forbids channel manipulation in HTTP mode, so the response body
-- can't be rewritten on its way back from the backend. Instead this service
-- opens its own connection to the Docker socket, fetches the inspect JSON,
-- scrubs Env, and answers the client itself.
--
-- It is registered as a service (not an action) on purpose: `use-service` is a
-- final rule, so a request that reaches it can never fall through to the
-- `allow` rules and get the unfiltered response. Every failure below answers
-- with an error instead of the original body.

local TIMEOUT = 30

-- Replace every "Env":[...] in body with "Env":[]. Returns nil if the JSON is
-- truncated or malformed, so the caller can refuse to answer.
--
-- We can't use body:gsub('"Env"%s*:%s*%b[]', '"Env":[]') because Lua's %b[]
-- doesn't understand JSON string escaping: an env value containing an unpaired
-- ] (e.g. FOO=]bar) would close the balance counter early and leave the rest
-- of the array unstripped. This scanner tracks JSON string state so brackets
-- inside strings are ignored, and only matches the array's true closing ].
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
        if depth ~= 0 then return nil end
        pos = i
    end
    return table.concat(out)
end

local function decode_chunked(body)
    local decoded, p = {}, 1
    while true do
        local nl = body:find("\r\n", p, true)
        if not nl then return nil end
        local sz_hex = body:sub(p, nl - 1):match("^[0-9a-fA-F]+")
        if not sz_hex then return nil end
        local sz = tonumber(sz_hex, 16)
        if sz == 0 then return table.concat(decoded) end
        if nl + 1 + sz > #body then return nil end
        decoded[#decoded + 1] = body:sub(nl + 2, nl + 1 + sz)
        p = nl + 2 + sz + 2
    end
end

-- Fetch the inspect response straight from the Docker socket.
-- Returns status, body on success, or nil, error message.
local function fetch(path)
    local sock = core.tcp()
    sock:settimeout(TIMEOUT)
    local socket_path = os.getenv("SOCKET_PATH") or "/var/run/docker.sock"
    if not sock:connect(socket_path) then
        return nil, "cannot connect to " .. socket_path
    end
    sock:send("GET " .. path .. " HTTP/1.1\r\n"
        .. "Host: docker\r\nConnection: close\r\n\r\n")
    local response = sock:receive("*a")
    sock:close()
    if not response then return nil, "no response from Docker" end

    local hdr_end = response:find("\r\n\r\n", 1, true)
    if not hdr_end then return nil, "malformed response from Docker" end
    local headers = response:sub(1, hdr_end - 1)
    local body = response:sub(hdr_end + 4)
    local status = tonumber(headers:match("^HTTP/1%.%d (%d%d%d)"))
    if not status then return nil, "malformed status line from Docker" end
    if headers:lower():find("\r\ntransfer%-encoding:%s*chunked") then
        body = decode_chunked(body)
        if not body then return nil, "malformed chunked body from Docker" end
    end
    return status, body
end

local function reply(applet, status, content_type, body)
    applet:set_status(status)
    applet:add_header("content-type", content_type)
    applet:add_header("content-length", tostring(#body))
    applet:start_response()
    applet:send(body)
end

core.register_service("inspect_hide_env", "http", function(applet)
    local path = applet.path
    if applet.qs and applet.qs ~= "" then path = path .. "?" .. applet.qs end

    local ok, status, body = pcall(fetch, path)
    local new_body, err
    if not ok then
        err = status
    elseif not status then
        err = body
    else
        new_body = strip_env(body)
        if not new_body then err = "cannot parse inspect JSON" end
    end
    if not new_body then
        core.Warning("inspect_hide_env: " .. tostring(err) .. "\n")
        reply(applet, 502, "application/json",
            '{"message":"docker-socket-proxy: cannot filter inspect response"}')
        return
    end
    reply(applet, status, "application/json", new_body)
end)
