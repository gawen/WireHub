-- WireHub authentication
--
-- An alias is a secret key given to a peer to authenticate itself. It is used
-- to add a peer to a network when its public key is not known yet.
--
-- Peer A wants to add peer B, but does not know B's key. Peer A generates a
-- secret key and stores it as an alias of peer B. Peer B is given this alias
-- through a secure channel (e.g. GPG, Keybase, ...), and sends a packet `AUTH`
-- to peer A to prove it knows the alias secret key. Peer A will then discover
-- peer A's key and register it as a new trusted peer.

local packet = require('packet')

local M = {}

local function explain(n, fmt, ...)
    return n:explain("auth", fmt, ...)
end

function M.authenticate(n, k, alias_sk, cb)
    local a = {
        alias_sk = alias_sk,
        alias_k = wh.publickey(alias_sk),
        k = k,
        retry=0,
        req_ts=0,
    }

    a.cb = function(ok, ...)
        if not n.auths[a] then
            return
        end

        n.auths[a] = nil

        if a.alias_sk then
            wh.burnsk(a.alias_sk)
            a.alias_sk = nil
        end

        if a.s then
            n:stop_search(a.s)
            a.s = nil
        end

        if a.p then
            a.p:release(a)
            a.p = nil
        end

        if cb then
            cpcall(cb, ok, ...)
        end
    end

    a.s = n:search(a.k, 'lookup', function(s, p, via)
        if not a.s then
            return
        end
        a.s = nil

        n:stop_search(s)

        if not p then
            return a:cb(false, "not found")
        end

        a.p = p:acquire(a)
    end)

    n.auths[a] = true

    return a
end

function M.stop_authenticate(n, a)
    a:cb(false, 'interrupted')
end


function M.update(n, a, deadlines)
    -- still searching?
    if not a.p then
        return
    end

    local deadline = a.req_ts+a.retry+1

    if now >= deadline then
        if a.retry > wh.AUTH_RETRY then
            return a:cb(false, "could not auth")
        end

        explain(n, "auth as %s ? (retry: %d)", n:key(a.alias_k), a.retry)
        n:_sendto{
            dst=a.p,
            m=packet.auth(n, a.p),
            sk=a.alias_sk,
        }

        a.retry = a.retry + 1
        a.req_ts = now
        a.last_seen = now

        deadline = a.req_ts+a.retry+1
    end

    deadlines[#deadlines+1] = deadline
end

function M.resolve_alias(n, alias, src)
    -- alias may be nil

    if alias then
        explain(n, "alias %s is %s", n:key(alias), n:key(src))

        -- copy all attributes from alias to p
        src.relay = nil
        for k, v in pairs(alias) do
            if k ~= 'k' and k ~= 'alias' then
                src[k] = alias[k]
            end
        end

        -- remove alias
        n.kad:unlink(alias)


    end
end

function M.on_authed(n, alias_k, src)
    for a in pairs(n.auths) do
        if a.alias_k == alias_k then
            local alias = n.kad:get(alias_k)

            M.resolve_alias(n, alias, n.p)

            -- wg might need to be enabled
            if n.lo then
                n.lo:refresh()
            end

            if n.wgsync then
                n.wgsync:refresh()
            end

            return a:cb(true)
        end
    end
end

return M

