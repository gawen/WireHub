local TRY_AUTOCONNECT_EVERY_S = 60

local MT = {
    __index = {}
}

local function _alloc(lo)
    -- XXX manages lo.cidr
    -- XXX slow
    for i = 1024, 65535 do
        local a = wh.set_address_port(lo.addr, i)
        if not lo.addr_ks[a:pack()] then
            return a
        end
    end

    error("no more free space for ports")
    return nil
end

function MT.__index.touch(lo, k)
    local a = lo.k_addrs[k]
    if not a then
        a = _alloc(lo, k)
        lo.k_addrs[k] = a
        lo.addr_ks[a:pack()] = k
    end
    assert(a)

    return a
end

function MT.__index.free(lo, k)
    local a = lo.k_addrs[k]
    if a then
        lo.addr_ks[a:pack()] = nil
        lo.k_addrs[k] = nil
    end
end

function MT.__index.update(lo, socks)
    local deadlines = {}
    local timeout
    lo.sniff_fd, timeout = wh.get_pcap(lo.sniff)

    socks[#socks+1] = lo.sniff_fd
    if timeout then
        deadlines[#deadlines+1] = now+timeout
    end

    for _, c in pairs(lo.connects) do
        if not c.ac_deadline then
            -- do nothing
        elseif c.ac_deadline > now then
            deadlines[#deadlines+1] = c.ac_deadline
        else
            lo.connects[c.k] = nil
        end
    end

    return min(deadlines)
end

function MT.__index.touch_tunnel(lo, p)
    if not p.tunnel then
        p.tunnel = {
            lo_addr = lo:touch(p.k)
        }
    end
    return p.tunnel
end

function MT.__index.free_tunnel(lo, p)
    if p.tunnel then
        lo:free(p.k)
        p.tunnel = nil
    end
end

local function on_connect(lo, c, dst, p2p)
    --dbg(dump(dst))
    if dst then
        if p2p then
            printf("$(green)auto-connect to %s succeed$(reset)", lo.n:key(dst))
        else
            printf("$(orange)cannot establish P2P connection with %s$(reset)", lo.n:key(dst))

            assert(dst.tunnel)
            dst.tunnel.last_tx = now
        end

        for _, m in ipairs(c.pkt_buf or {}) do
            -- XXX
            lo.n:send_datagram(dst, m)
        end

    else
        printf("$(red)could not find %s$(reset)", lo.n:key(c.k))
    end

    c.ac_deadline = now + TRY_AUTOCONNECT_EVERY_S
end

function MT.__index.on_readable(lo, r)
    while r[lo.sniff_fd] do
        local src_addr, dst_lo_addr, m = wh.pcap_next_udp(lo.sniff)

        if not m then
            break
        end

        local dst_k = lo.addr_ks[dst_lo_addr:pack()]

        if not dst_k then
            printf("$(red)error: unknown lo addr: %s$(reset)", dst_lo_addr)
            return
        end

        local dst = lo.n.kad:get(dst_k)
        if not dst then
            return
        end

        -- is peer set with a tunnel? if so, redirect the wireguard packet.
        -- else, try to connect while buffering the packets

        if lo.auto_connect then
            local c = lo.connects[dst.k]
            if not c then
                printf("$(green)auto-connecting to %s$(reset)", lo.n:key(dst))
                c = lo.n:connect(dst.k, nil, function(...)
                    return on_connect(lo, ...)
                end)
                lo.connects[dst.k] = c
            end

            if not c.pkt_buf then
                c.pkt_buf = {}
            end

            c.pkt_buf[#c.pkt_buf+1] = m
            if #c.pkt_buf > lo.buffer_max then
                table.remove(c.pkt_buf, 1)
            end
        end

        if dst.tunnel then
            dst.tunnel.last_tx = now
            local through_tunnel = lo.n:send_datagram(dst, m)

            if not through_tunnel then
                lo:free_tunnel(dst)
            end
        end
    end
end

function MT.__index.forget(lo, k)
    lo.connects[k] = nil
end

function MT.__index.recv_datagram(lo, src, m)
    lo:touch_tunnel(src)
    src.tunnel.last_rx = now

    printf("$(orange)receive datagram %dB$(reset)", #m)

    local ret, errmsg = wh.sendto_raw_wg(lo.sock, m, src.tunnel.lo_addr, lo.n.port)

    if not ret then
        printf('$(red)error: could not send packet: %s', errmsg)
    end
end

function MT.__index.close(lo)
    if lo.sniff then
        wh.close_pcap(lo.sniff)
        lo.sniff = nil
    end

    if lo.sniff_fd then
        wh.close(lo.sniff_fd)
        lo.sniff_fd = nil
    end

    if lo.sock then
        wh.close(lo.sock)
        lo.sock = nil
    end
end

return function(lo)
    assert(lo.n)

    if lo.auto_connect == nil then
        lo.auto_connect = true
    end

    if not lo.cidr then
        lo.cidr = 32
    end

    if not lo.addr then
        -- XXX
        lo.addr = wh.address(string.format("127.%d.%d.%d",
            randomrange(1, 254),
            randomrange(1, 254),
            randomrange(1, 254)
        ), 0)
    end
    lo.subnet = lo.addr:addr() .. '/' .. tostring(lo.cidr)

    lo.k_addrs = {}
    lo.addr_ks = {}
    lo.tunnels = {}
    lo.connects = {}

    if lo.auto_connect then
        if not lo.buffer_max then
            lo.buffer_max = 1
        end
    end

    -- XXX lazy?
    lo.sniff = wh.sniff('any', 'in', 'wg', " and dst net " .. lo.subnet)
    lo.sock = wh.socket_raw_udp('ip4_hdrincl')

    return setmetatable(lo, MT)
end

