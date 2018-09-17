local packet = require('packet')
local peer = require('peer')

local auth = require('auth')
local kad = require('kad')
local nat = require('nat')
local search = require('search')

local H = {}

local function log_cmd(n, m, src, fmt, ...)
    --printf("%s - %s - %d - %s", src, wh.todate(now), #m, string.format(fmt, ...))
    if n.log >= 2 then
        printf("%s -> :%d: %s (%dB)", src, n.port, string.format(fmt, ...), #m)
    end
end

H[packet.cmds.ping] = function(n, m, src, via)
    local arg = string.sub(m, 2, 2)
    if arg == '\x00' then
        arg = 'normal'
    elseif arg == '\x01' then
        arg = 'swapsrc'
    elseif arg == '\x02' then
        arg = 'direct'
    end

    local body = string.sub(m, 3)

    --if src.lazy and (arg ~= "normal" or #body ~= 0) then return end

    -- ignore ping with body bigger than 8
    if #body > 8 then
        printf("$(red)drop too big ping")
        return
    end

    -- by default, respond via same port, except if argument is 'swapsrc'
    local echo

    if via == 'relay' then
        echo = false
    else
        echo = via == 'echo'
        if arg == 'swapsrc' then echo = not echo end
    end

    if arg == 'direct' then
        -- remove relay
        src = {addr=src.addr, k=src.k}
    end

    log_cmd(n, m, src, "$(yellow)ping$(reset)(%s, %s)", arg, wh.tob64(body))
    n:_sendto{
        dst=src,
        m=packet.pong(n.port_echo, src.addr, body),
        from_echo=echo
    }
end

H[packet.cmds.pong] = function(n, m, src)
    --if src.lazy then return end

    local i = 2
    local l

    local src_port_echo, src_addr_echo, public_addr

    public_addr, l = wh.unpack_address(string.sub(m, i))
    i = i + l

    src_port_echo = string.unpack("!H", string.sub(m, i, i+1))
    src_addr_echo = wh.set_address_port(src.addr, src_port_echo)
    i = i + 2

    src.addr_echo = src_addr_echo

    local body = string.sub(m, i)

    log_cmd(n, m, src, "$(yellow)pong$(reset)(%s, port_echo=%s, self=%s)", wh.tob64(body), src_addr_echo, public_addr)

    kad.on_pong(n, src)
    nat.on_pong(n, body, src)
    search.on_pong(n, body, src)
end

H[packet.cmds.search] = function(n, m, src)
    local k = string.sub(m, 2)
    log_cmd(n, m, src, "$(yellow)search$(reset)(%s)", n:key(k))

    local closest = n.kad:kclosest(k, wh.KADEMILIA_K)

    n:_sendto{dst=src, m=packet.result(k, closest)}
end

H[packet.cmds.result] = function(n, m, src)
    if src.lazy then return end

    local pks = string.sub(m, 2, 33)
    local closest = {}
    local i = 34
    local l

    while i < #m do
        local p = {}

        local flag = string.sub(m, i, i)
        i = i + 1

        do
            p.k = string.sub(m, i, i+31);
            i = i + 32

            p.addr, l = wh.unpack_address(string.sub(m, i))
            i = i + l
        end

        if flag == '\x01' then
            local relay = {}
            relay.k = string.sub(m, i, i+31)
            i = i + 32
            relay.addr = wh.unpack_address(string.sub(m, i))
            i = i + l

            -- prefer own source
            p.relay = n.kad:get(relay.k) or peer(relay)

        elseif flag == '\x02' then
            p.relay = src
        end

        closest[#closest+1] = peer(p)
    end

    log_cmd(n, m, src, "$(yellow)result$(reset)(#%d)", #closest)

    search.on_result(n, pks, closest, src)
end

H[packet.cmds.relay] = function(n, m, src)
    local i = 2
    local l

    local dst_k = string.sub(m, i, i+32-1)
    i = i + 32
    if #dst_k ~= 32 then
        return
    end

    local relayed_m = string.sub(m, i)

    local dst = n.kad:get(dst_k)
    if not dst then
        return
    end

    -- XXX bandwidth limit
    -- XXX whitelist management
    -- XXX keep source in kademilia for some time as it is currently relaying
    -- with dst
    -- XXX SECURITY ISSUE!
    -- Do not let anyone send a 'relayed' packet with any type of body. Just
    -- sign the digest, not the entire body! (AEAD?)
    -- OK for the POC
    -- XXX make sure to keep dst in the kademilia table

    log_cmd(n, m, src, "$(blue)relay$(reset)(%s, %d)", n:key(dst_k), #relayed_m)

    if dst.relay then
        printf("$(red)cannot forward relayed packet to relayed peer %s$(reset)", n:key(dst))
        return
    end

    if not dst.addr then
        printf("$(red)unknown route for relayed packet to %s$(reset)", n:key(dst))
        return
    end

    n:_sendto{dst=dst, m=packet.relayed(src, relayed_m)}
end

H[packet.cmds.relayed] = function(n, m, relay)
    local i = 2
    local l

    local src_addr
    src_addr, l = wh.unpack_address(string.sub(m, i))
    i = i + l
    assert(src_addr)    -- XXX

    local me = string.sub(m, i)

    log_cmd(n, m, relay, "$(blue)relayed$(reset)(%s, %d)", src_addr, #me)

    local src_k, time, src_is_nated
    src_k, src_is_nated, time, m = wh.open_packet(n.sk, me)

    if m == nil then
        printf("$(red)relayed packet dropped!$(reset)")
        return
    end

    -- XXX SECURITY ISSUE!
    -- a node received a relayed must check that the source indeed sent the
    -- relayed packet through the relay!

    local src_relay
    if src_is_nated then
        src_relay = relay
    end

    return n:read(
        m,
        src_addr,
        src_k,
        src_is_nated,
        time,
        'relay',
        src_relay
    )
end

H[packet.cmds.auth] = function(n, m, alias)
    if not alias.alias then
        -- not set as alias
        return
    end

    local me = string.sub(m, 2)
    local src_k, src_is_nated, src_time, src_m = wh.open_packet(n.sk, me)

    if src_m == nil then
        log_cmd(n, m, alias, "$(yellow)auth$(reset)($(red)bad$(reset))")
        return
    end

    if src_k ~= src_m then
        log_cmd(n, m, alias, "$(yellow)auth$(reset)($(red)invalid$(reset))")
        return
    end

    log_cmd(n, m, alias, "$(yellow)auth$(reset)(%s)", n:key(src_k))

    local src = n.kad:touch(src_k)

    auth.resolve_alias(n, alias, src)

    n:_sendto{
        dst=src,
        m=packet.authed(alias.k),
    }
end

H[packet.cmds.authed] = function(n, m, src)
    local alias_k = string.sub(m, 2)

    log_cmd(n, m, alias, "$(yellow)authed$(reset)(%s)", n:key(alias_k))

    auth.on_authed(n, alias_k, src)
end

H[packet.cmds.fragment] = function(n, m, src)
    if not n.lo then
        return
    end

    local id, b = string.unpack(">HB", string.sub(m, 2, 4))
    local num = b&0x7f
    local mf = b&0x80==0x80
    m = string.sub(m, 5)

    log_cmd(n, m, alias, "$(yellow)fragment$(reset)(id:%.4x, num:%d, mf:%s, m:%d)", id, num, mf, #m)

    if not src.fragments then
        src.fragments = {}
    end
    local id = src.k .. string.pack("H", id)
    local sess = src.fragments[id]
    if not sess then
        sess = {
            deadline=now+wh.FRAGMENT_TIMEOUT,
            id=id,
        }
        src.fragments[#src.fragments+1] = sess
        table.sort(src.fragments, function(a, b)
            return a.deadline < b.deadline
        end)
        src.fragments[sess.id] = sess
    end

    sess[num+1] = m

    -- if last fragment was received
    if not mf then
        sess.last = num+1
    end

    if not sess.last or #sess ~= sess.last then
        return
    end

    local m = table.concat(sess)

    n.lo:recv_datagram(src, m)

    -- clean
    src.fragments[id] = nil
    for i, v in ipairs(src.fragments) do
        if v == sess then
            table.remove(src.fragments, i)
            break
        end
    end

    --if #src.fragments == 0 then
    --    src.fragments = nil
    --end
end

return H

