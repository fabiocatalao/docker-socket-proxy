-- Strips secret-bearing fields from Docker /containers/<id>/json responses so
-- secrets passed via env vars (Config.Env) or the container command line
-- (Config.Cmd / top-level Args) don't leak through the proxy.
--
-- Config.Labels is deliberately NOT stripped: Homepage's Docker label
-- discovery reads homepage.* labels (including widget API keys) through this
-- proxy, so blanking Labels would break the dashboard. Keep label-borne
-- secrets off untrusted networks by scoping the proxy itself (e.g. bind it to
-- a Tailscale interface) rather than by redacting Labels here.
--
-- HAProxy ≥2.5 forbids channel manipulation in HTTP mode, so we can't
-- rewrite the response body via http-response. Instead this opens its own
-- connection to the docker socket, fetches the inspect JSON, scrubs the
-- fields, and returns the modified body via the Reply API.

-- Replace every '"key":<open>...<close>' in body with '"key":<open><close>'
-- (e.g. "Env":[...] -> "Env":[]).
--
-- We can't use body:gsub('"key"%s*:%s*%b[]', ...) because Lua's %b[] doesn't
-- understand JSON string escaping: a value containing an un-paired bracket
-- (e.g. FOO=]bar) would close the balance counter early and leave the rest of
-- the value un-stripped (plus break the JSON). This scanner tracks JSON string
-- state so brackets inside strings are ignored, and only matches the value's
-- true closing bracket. On malformed/truncated input it returns the body
-- unchanged for that field, so we never emit broken JSON.
local function strip_field(body, key, openc, closec)
    -- '[' is a Lua-pattern magic char; '{' is not. Escape only what's needed.
    local open_pat = openc:gsub("([%[%]%%])", "%%%1")
    local find_pat = '"' .. key .. '"%s*:%s*' .. open_pat
    local empty = openc .. closec
    local out, pos = {}, 1
    while true do
        local s, e = body:find(find_pat, pos)
        if not s then
            out[#out + 1] = body:sub(pos)
            break
        end
        out[#out + 1] = body:sub(pos, s - 1)
        out[#out + 1] = '"' .. key .. '":' .. empty
        local depth, in_str, i = 1, false, e + 1
        while i <= #body and depth > 0 do
            local c = body:sub(i, i)
            if in_str then
                if c == "\\" then i = i + 1
                elseif c == '"' then in_str = false end
            elseif c == '"' then in_str = true
            elseif c == openc then depth = depth + 1
            elseif c == closec then depth = depth - 1
            end
            i = i + 1
        end
        if depth ~= 0 then return body end
        pos = i
    end
    return table.concat(out)
end

-- Scrub every field that can carry a secret. Each pass is independent, so a
-- malformed value in one field can't prevent the others from being stripped.
local function scrub(body)
    body = strip_field(body, "Env", "[", "]")   -- Config.Env
    body = strip_field(body, "Cmd", "[", "]")   -- Config.Cmd (secrets in the command line)
    body = strip_field(body, "Args", "[", "]")  -- top-level Args (the same command line)
    return body
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

    local new_body = scrub(body)
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
