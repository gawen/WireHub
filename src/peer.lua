-- Peer's methods

local M = {}
local MT = {
    __index = {},
}

function MT.__index.pack(p)
    local r = { p.k, p.addr:pack() }

    --if p.relay ~= nil then
    --    r[#r+1] = p.relay.k
    --    r[#r+1] = p.relay.addr:pack()
    --end

    return table.concat(r)
end

if DEBUG then
    function MT.__newindex(r, attr, val)
        local t = ""
        if false then
            t = debug.traceback()
            t = string.match(t, "[^\n]*\n[^\n]*\n\t.*src/([^\n]*) *\n.*")
            t = "$(reset)\t(" .. t .. ")"
        end

        if rawget(r, attr) ~= val then
            printf("$(darkgray)--$(reset) $(bold)%s$(reset).$(blue)%s$(reset) = $(blue)%s"..t,
                wh.key(r), attr, dump(val)
            )
        end

        rawset(r, attr, val)
    end
end

function MT.__tostring(p)
    local r = {}

    local s = string.format("%s@%s", wh.key(p), p.addr)

    if p.is_nated then
        s = s .. ' (NAT)'
    end

    if p.relay then
        s = s .. string.format(" (relayed)")
    end

    return s
end

-- Returns two values:
-- 1. the type of the peer
-- 2. if it is considered as active
function MT.__index.state(p)
    -- peer is an alias: a public-key of a private key given to the peer to
    -- authenticate in the future
    if p.alias then
        return 'alias', false

    -- peer may be contacted through a relay
    elseif p.relay then
        return 'relay', now-(p.last_seen or 0) <= wh.KEEPALIVE_NAT_TIMEOUT

    -- peer is connected in P2P, but behind a NAT
    elseif p.is_nated and p.addr then
        return 'nat', now-(p.last_seen or 0) <= wh.KEEPALIVE_NAT_TIMEOUT

    -- peer is direct
    elseif p.addr then
        return 'direct', now-(p.last_seen or 0) <= wh.KEEPALIVE_DIRECT_TIMEOUT

    -- no connection information
    else
        return nil, false
    end
end

function MT.__index.acquire(p, obj)
    if p.ref == nil then
        p.ref = {}
    end

    p.ref[obj] = true

    --dbg('acquire %s', dump(p))
    return p
end

function MT.__index.release(p, obj)
    if p.ref == nil then
        return
    end

    p.ref[obj] = nil

    local empty = true
    for _ in ipairs(p.ref) do
        empty = false
        break
    end

    if empty then
        p.ref = nil
    end
end

function MT.__index.owned(p)
    return not not p.ref
end

return function(p)
    return setmetatable(p, MT)
end

