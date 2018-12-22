-- WireHub protocol packets

local M = {}

local cmds = {
    -- PING. Requests a peer to PONG.
    'ping',

    -- PONG. Response of the request PING.
    'pong',

    -- SEARCH. Search for closest peers for a given key.
    'search',

    -- RESULT. Response of a SEARCH.
    'result',

    -- RELAY. Request recipient to relay WireHub packet to a given peer.
    'relay',

    -- RELAYED. Sends a relayed packet to and for a recipient. Is sent after a
    -- RELAY.
    'relayed',

    -- AUTH. Prove recipient that current peer has an alias.
    'auth',

    -- AUTHED. Response after a AUTH, as authentication succeeded.
    'authed',

    -- FRAGMENT. Send fragments of raw data. Used to relay WireGuard packets.
    'fragment',
}
for i, str in ipairs(cmds) do cmds[str] = string.pack("B", i-1) end

M.cmds = cmds

function M.ping(arg, body)
    body = body or ''
    assert(#body <= 8)

    if arg == nil or arg == 'normal' then
        arg = "\x00"
    elseif arg == 'swapsrc' then
        arg = "\x01"
    elseif arg == 'direct' then
        arg = "\x02"
    end

    return table.concat{cmds.ping, arg, body or ''}
end
function M.pong(port_echo, src, body)
    return table.concat{
        cmds.pong,
        src:pack(),
        string.pack("!H", port_echo),
        body,
    }
end
function M.search(k)
    return table.concat{cmds.search, k}
end

function M.result(k, closest)
    local m = {cmds.result, k}

    for i, c in ipairs(closest) do
        local p = c[2]

        if i > wh.KADEMILIA_K then
            break
        end

        if p.relay then
            m[#m+1] = "\x01"
        elseif p.is_nated then
            m[#m+1] = "\x02"
        else
            m[#m+1] = "\x00"
        end

        do
            m[#m+1] = p.k
            m[#m+1] = p.addr:pack()
        end

        if p.relay then
            m[#m+1] = p.relay.k
            m[#m+1] = p.relay.addr:pack()
        end
    end

    return table.concat(m)
end

function M.relay(dst, body)
    assert(#dst == 32)
    assert(type(body) == "string")
    return table.concat{
        cmds.relay,
        dst,
        body,
    }
end

function M.relayed(src, body)
    return table.concat{
        cmds.relayed,
        src.addr:pack(),
        body,
    }
end

function M.auth(n, dst)
    local m = n.k

    return table.concat{
        cmds.auth,
        wh.packet(n.sk, dst.k, false, m),
    }
end

function M.authed(alias_k)
    return table.concat{
        cmds.authed,
        alias_k,
    }
end

function M.fragment(id, num, mf, m)
    -- mf: More Fragment

    assert(id&0xffff==id)
    assert(num&0x7f==num)

    assert(#m <= wh.FRAGMENT_MTU)

    local b = num
    if mf then
        b = 0x80 | b
    end

    return table.concat{
        cmds.fragment,
        string.pack(">HB", id, b),
        m
    }
end

return M

