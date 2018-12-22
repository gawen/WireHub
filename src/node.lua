-- WireHub node manager

local handlers = require('handlers')
local packet = require('packet')
local peer = require('peer')
local time = require('time')

local auth = require('auth')
local kad = require('kad')
local nat = require('nat')
local search = require('search')
local connectivity = require('connectivity')

local M = {}
local MT = {
    __index = {},
}

function MT.__index._extend(n, s, closest, src)
    s.states[src.k] = {retry=0, rep=true}

    local set = {}
    for _, c in ipairs(s.closest) do
        local p = c[2]
        set[p:pack()] = true
    end

    for _, c in ipairs(closest) do
        local dist = c[1]
        local p = c[2]

        local st = s.states[p.k]

        if (
            -- if peer has address
            p.addr and

            -- if peer already answered, skip,
            (st == nil or not st.rep) and

            -- ignore doublons
            not set[p:pack()]
        ) then
            --printf('extend $(cyan)%s', p)
            s.closest[#s.closest+1] = {dist, n:add(p)}
            set[p:pack()] = true

            if s.cb and p.k == s.k then
                cpcall(s.cb, s, p, src)
            end
        end
    end

    -- XXX maybe give a preference to trusted peers, or peers which are public
    -- or geographically close
    table.sort(s.closest, function(a, b) return a[1] < b[1] end)
end

function MT.__index._sendto(n, opts)
    assert(opts.dst)

    opts.sk = opts.sk or n.sk

    if opts.dst.k == n.k then
        error("cannot send to self")
    end

    --if math.random() < .3 then return end

    local me = opts.me
    if not me then
        me = wh.packet(opts.sk, opts.dst.k, n.is_nated, opts.m)

        if opts.dst.relay then
            me = wh.packet(opts.sk, opts.dst.relay.k, n.is_nated, packet.relay(
                opts.dst.k, me
            ))
        end
    end

    local udp_dst = opts.dst.relay and opts.dst.relay or opts.dst

    local udp_dst_addr
    if opts.to_echo then
        if not udp_dst.addr_echo then
            errorf("unknown echo address for %s", udp_dst)
        end

        udp_dst_addr = udp_dst.addr_echo
    else
        if not udp_dst.addr then
            errorf("unknown address for %s", udp_dst)
        end
        udp_dst_addr = udp_dst.addr
    end

    local port = opts.from_echo and n.port_echo or n.port

    -- DEBUG
    if n.log >= 2 then
        local msg = {}
        msg[#msg+1] = string.format('%s <- :%d: $(yellow)', udp_dst, port)

        if opts.dst.relay then
            msg[#msg+1] = string.format("relay$(reset)(%s, $(yellow)", opts.dst.addr)
        end

        if opts.m then
            msg[#msg+1] = packet.cmds[string.byte(string.sub(opts.m, 1, 1))+1] or "???"
        else
            msg[#msg+1] = string.format("<raw %dB>", #me)
        end
        msg[#msg+1] = "$(reset)"

        if opts.dst.relay then
            msg[#msg+1] = ')'
        end

        msg[#msg+1] = string.format(" (%dB)", #me)
        printf(table.concat(msg))
    end

    if n.bw then
        n.bw:add_tx(udp_dst.k, #me)
    end

    local ret, errmsg = wh.sendto_raw_udp(n.sock4_raw, n.sock6_raw, me, port, udp_dst_addr)

    if not ret then
        printf('$(red)error: could not send packet: %s', errmsg)
    end
end

function MT.__index.update(n, socks)
    local timeout
    local deadlines = {}

    socks[#socks+1] = n.sock_echo
    socks[#socks+1] = wh.pipe_event_fd(n.pe)

    n.in_udp_fd, timeout = wh.get_pcap(n.in_udp)
    socks[#socks+1] = n.in_udp_fd
    if timeout then
        deadlines[#deadlines+1] = now+timeout
    end

    if n.upnp then
        n.upnp.worker:update(socks)
    end

    connectivity.update(n, deadlines)

    if n.ns then
        n.ns.worker:update(socks)
    end

    for d in pairs(n.nat_detectors) do
        nat.update(n, d, deadlines)
    end

    for s in pairs(n.searches) do
        search.update(n, s, deadlines)
    end

    for a in pairs(n.auths) do
        auth.update(n, a, deadlines)
    end

    kad.update(n, deadlines)

    if n.lo then
        deadlines[#deadlines+1] = n.lo:update(socks)
    end

    if (n.bw and
        n.bw:length() ~= 0 and
        time.every(deadlines, n.bw, 'last_collect_ts', n.bw.scale)) then

        n.bw:collect()
    end

    return min(deadlines)
end

function MT.__index.add(n, other)
    assert(other.k)
    local self = n.kad:touch(other.k)

    assert(self.k == other.k)

    local changed = (
        -- do not change bootstrap
        not self.bootstrap and

        -- ignore older others
        (not other.last_seen or other.last_seen >= (self.last_seen or 0)) and

        (
            -- replace if we don't know the address (worst situation)
            not self.addr or

            -- replace if other peer is not relayed
            not other.relay or

            -- replace if our route is through a relay
            self.relay

            -- XXX if the relay is of good quality, avoid to change it by a bad
            -- one
        )
    )

    if changed then
        self.addr = other.addr
        self.is_nated = other.is_nated
        self.last_ping = nil
        self.last_seen = other.last_seen or self.last_seen
        self.ping_retry = 0
        self.relay = other.relay
    end

    return self, changed
end

function MT.__index.getent(n, hostname, result_cb)
    if hostname == nil then
        return nil
    end

    local cbs = {}

    if n.ns then
        for _, ns in ipairs(n.ns) do
            cbs[#cbs+1] = ns
        end
    end

    -- might be a shorther version of Base64 WireHub Base64
    cbs[#cbs+1] = function(n, k, cb)
        local test = function(p)
            local e = string.find(wh.tob64(p.k), k)
            return e
        end

        local match

        if test(n.kad.root) then
            match = n.kad.root
        end

        for _, bucket in ipairs(n.kad.buckets) do
            for _, p in ipairs(bucket) do
                if test(p) then
                    if match then
                        -- there's an possible ambiguity. fails
                        return cb(nil)
                    else
                        match = p
                    end
                end
            end
        end

        if match then
            return cb(match.k)
        else
            return cb(nil)
        end
    end

    -- might be Base64 from WireHub
    cbs[#cbs+1] = function(n, k, cb)
        local ok, k = pcall(wh.fromb64, k, 'wh')

        if ok then
            if #k ~= 32 then k = nil end
        else
            k = nil
        end

        return cb(k)
    end

    -- might be Base64 from WireGuard
    cbs[#cbs+1] = function(n, k, cb)
        local k = pcall(wh.fromb64, k, 'wg')
        if k then
            if #k ~= 32 then k = nil end
        else
            k = nil
        end
        return cb(k)
    end

    -- might be a hostname
    cbs[#cbs+1] = function(n, h, cb)
        -- XXX manages index for hostnames

        if n.kad.root.hostname == h then
            return cb(n.kad.root.k)
        end

        for _, bucket in ipairs(n.kad.buckets) do
            for _, p in ipairs(bucket) do
                if p.hostname == h and p.k then
                    return cb(p.k)
                end
            end
        end

        return cb()
    end

    local key = nil
    local cont_cb

    function cont_cb()
        local cb
        key, cb = next(cbs, key)

        if key and cb then
            return cb(n, hostname, function(k)
                if k then
                    return result_cb(k)
                else
                    return cont_cb()
                end
            end)
        else
            return result_cb(nil)
        end
    end

    return cont_cb()
end

function MT.__index.search(n, k, mode, count, timeout, cb)
    assert(k)

    if mode == nil then mode = 'ping' end
    if mode ~= 'lookup' and
       mode ~= 'p2p' and
       mode ~= 'ping' then
        error("arg #3 must be 'p2p', 'lookup' or 'ping'")
    end
    if count == nil then count = wh.KADEMILIA_K end
    if timeout == nil then timeout = wh.SEARCH_TIMEOUT end

    local s = setmetatable({
        cb=cb,
        closest={},
        count=count,
        deadline=now+timeout,
        k=k,
        mode=mode,
        running=true,
        uid1=wh.randombytes(8),
        uid2=wh.randombytes(8),
        may_offline=true,
        states={},
    }, {
        __index = S
    })

    n.searches[s] = true

    -- bootstrap
    n:_extend(s, n.kad:kclosest(s.k, wh.KADEMILIA_K), n.kad.root)

    return s
end

function MT.__index.stop_search(n, s)
    if s.running then
        s.running = false

        --printf('stop search $(cyan)%s', n:key(s))

        n.searches[s] = nil

        if s.cb then
            cpcall(s.cb, s, nil)
        end
    end
end

function MT.__index.detect_nat(n, k, cb)
    local p
    if k == nil then
        -- XXX get the closest node which is public!
        local closest = n.kad:kclosest(n.k, 1, function(p)
            return p.bootstrap
        end)
        if #closest == 0 then
            return cb("offline")
        end

        p = closest[1][2]
        k = p.k
    else
        p = n.kad:get(k)

        if not p then
            error(string.format("no route to %s", n:key(k)))
        end
    end

    local d = {
        may_cone=true,
        may_offline=true,
        may_direct=true,
        k=k,
        req_ts=0,
        retry=0,
        uid=wh.randombytes(8),
        uid_echo=wh.randombytes(8),
        p=p,
        p_echo=nil,          -- explicit
    }

    d.cb = function(...)
        n.nat_detectors[d] = nil
        return cb(...)
    end


    n.nat_detectors[d] = true
end

function MT.__index.authenticate(n, k, alias_sk, cb)
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

        if cb then
            cpcall(cb, ok, ...)
        end
    end

    a.s = n:search(a.k, 'lookup', nil, nil, function(s, p, via)
        if not a.s then
            return
        end
        a.s = nil

        n:stop_search(s)

        if not p then
            return a:cb(false, "not found")
        end

        a.p = p
    end)

    n.auths[a] = true

    return a
end

function MT.__index.stop_authenticate(n, a)
    a:cb(false, 'interrupted')
end

function MT.__index.connect(n, dst_k, timeout, cb)
    local count = 1
    local p_relay
    local cbed = false

    return n:search(dst_k, 'p2p', count, timeout, function(s, p, via)
        if cbed then return end

        if p and not p.relay and p.addr then
            cbed = true
            return cb(s, p, true, p.addr)
        elseif p and p.relay then
            p_relay = p
        elseif n.lo and p_relay then
            local tunnel = n.lo:touch_tunnel(p_relay)
            cbed = true
            return cb(s, p_relay, false, tunnel.lo_addr)
        else
            cbed = true
            return cb(s)
        end
    end)
end

function MT.__index.forget(n, dst_k)
    local p = n.kad:get(dst_k)
    if not p then
        return
    end

    -- do not forget bootstrap nodes
    if p.bootstrap then
        return
    end

    n.kad:touch(dst_k)
    p.addr = nil
    p.addr_echo = nil
    p.first_seen = nil
    p.is_nated = nil
    p.last_ping = nil
    p.last_seen = nil
    p.ping_retry = nil
    p.relay = nil
    p.tunnel = nil

    if n.lo then
        n.lo:forget(dst_k)
    end
end


function MT.__index.send_datagram(n, dst, m)
    if type(dst) == 'string' then
        dst = n.kad:get(dst)

        -- unknown destination. close tunnel
        if not dst then
            return false
        end
    end

    if dst.relay then
        local num = 0
        while true do
            local fragment = string.sub(m, num*wh.FRAGMENT_MTU+1, (num+1)*wh.FRAGMENT_MTU)
            local mf = #m > ((num+1)*wh.FRAGMENT_MTU)

            if #fragment == 0 then
                break
            end

            n:_sendto{
                dst=dst,
                m=packet.fragment(
                    n.frag_counter,
                    num,
                    mf,
                    fragment
                )
            }

            num = num + 1
            assert(num < 64)
        end

        n.frag_counter = (n.frag_counter + 1) % 0x10000

        return true
    elseif dst.addr then
        n:_sendto{dst=dst, me=m}

        return false
    else
        printf("$(red)no route to %s. drop datagram$(reset)", n:key(p))

        return true
    end
end

function MT.__index.read(n, m, src_addr, src_k, src_is_nated, time, via, relay)
    -- peer's key needs enough workbit
    if n.workbit == 0 or wh.workbit(src_k, n.namespace) < n.workbit then
        return
    end

    local cmd = string.sub(m, 1, 1)
    if #cmd == 0 then return end

    -- a relayed message must not be of type 'relayed'
    if via == 'relay' and cmd == packet.cmds.relayed then
        printf("$(red)drop a double relayed packet$(reset)")
        return
    end

    local src, better_route = n:add{
        addr = src_addr,
        is_nated = src_is_nated,
        k = src_k,
        last_seen = now,
        relay = relay,
    }

    src.first_seen = src.first_seen or now
    src.last_seen = now

    if src.bootstrap and src_is_nated then
        printf("$(yellow)INVALID: bootstrap cannot be behind a NAT$(reset)")
        return
    end

    local real_relay
    -- better connection. However the new route will be used only to respond to this
    -- it is ok to answer relayed requests through relay, even we already know a
    -- request.
    if not better_route and not src.relay and relay then
        real_relay = src.relay
        src.relay = relay
    else
        real_relay = src.relay
    end

    local h = handlers[cmd]
    if h then
        h(n, m, src, via)
    else
        printf("$(red)unknown cmd: {%d} (%dB)\t%s", string.byte(cmd), #m, src)
    end

    src.relay = real_relay
end

function MT.__index.on_readable(n, r)
    if r[wh.pipe_event_fd(n.pe)] then
        wh.clear_pipe_event(n.pe)
    end

    if n.upnp then
        n.upnp.worker:on_readable(r)
    end

    if n.ns then
        n.ns.worker:on_readable(r)
    end

    while r[n.in_udp_fd] or r[n.sock_echo] do
        local me, src_addr
        local via

        if r[n.in_udp_fd] then
            src_addr, _, me = wh.pcap_next_udp(n.in_udp)
            via = "normal"

            if not me then
                r[n.in_udp_fd] = nil
            end
        end

        if r[n.sock_echo] then
            me, src_addr = wh.recvfrom(n.sock_echo, 1500) -- XXX MTU?
            via = "echo"
        end

        -- if no more packet, break
        if me == nil then
            break
        else
            local src_k, src_is_nated, time, m = wh.open_packet(n.sk, me)

            -- XXX do something with time

            -- if message is valid,
            if m ~= nil then
                if n.bw then
                    n.bw:add_rx(src_k, #me)
                end

                n:read(m, src_addr, src_k, src_is_nated, time, via)
            end
        end
    end

    if n.lo then
        n.lo:on_readable(r)
    end
end

function MT.__index.close(n)
    if n.upnp then
        n.upnp.worker:free()
    end

    if n.ns then
        n.ns.worker:free()
    end

    if n.lo then
        n.lo:close()
    end

    wh.close(n.sock4_raw)
    n.sock4_raw = nil

    wh.close(n.sock6_raw)
    n.sock6_raw = nil

    wh.close(n.sock_echo)
    n.sock_echo = nil

    wh.close_pcap(n.in_udp)
    n.in_udp = nil

    wh.close_pipe_event(n.pe)
    n.pe = nil

    if n.in_udp_fd then
        wh.close(n.in_udp_fd)
        n.in_udp_fd = nil
    end
end

function MT.__index.describe(n, mode)
    if mode == nil then mode = 'all' end

    assert(mode == 'all' or mode == 'light')

    local r = {}

    if n.name then
        r[#r+1] = string.format("network $(bold)%s$(reset), ", n.name)
    end

    r[#r+1] = "node "

    if n.p.hostname then
        r[#r+1] = string.format("$(bold)%s$(reset) ", n.p.hostname)
    end

    do
        local mode = {}
        if n.is_nated then mode[#mode+1] = "NAT" end
        if n.p.is_router then mode[#mode+1] = "ROUTER" end
        if n.p.is_gateway then mode[#mode+1] = "GATEWAY" end

        r[#r+1] = string.format("<%s>\n", string.join(',', mode))
    end

    r[#r+1] = string.format("  public key: %s\n", wh.tob64(n.p.k))

    --r[#r+1] = string.format("  port: %d, port echo: %d\n", n.port, n.port_echo)
    --if n.workbit then
    --    r[#r+1] = string.format("  namespace: %s, workbit: %d\n", n.namespace, n.workbit)
    --end

    if mode == 'all' then
        local any_nat = false
        for d in pairs(n.nat_detectors) do
            if not any_nat then
                any_nat = true
                r[#r+1] = "  $(bold)nat detecting$(reset)\n"
            end

            local mode
            if d.may_offline then
                mode = "OFFLINE?"
            elseif d.may_direct then
                mode = "DIRECT?"
            elseif d.may_cone then
                mode = "CONE?"
            else
                mode = "BLOCKED"
            end

            r[#r+1] = string.format("    %s (%s)\n", n:key(d), wh.tob64(d.uid))
            r[#r+1] = string.format("      mode: %s (retry: %d)\n", mode, d.retry)
        end
    end

    if mode == 'all' then
        local any_search = false
        for s in pairs(n.searches) do
            if not any_search then
                any_search = true
                r[#r+1] = "  $(bold)searches$(reset)\n"
            end

            r[#r+1] = string.format("    %s (%d queued, closest %d)\n",
                n:key(s), #s.closest,
                s.closest[1] and wh.bid(s.k, s.closest[1][1]) or 0
            )

            if s.deadline-now<5 then
                r[#r+1] = string.format("    timeout in %.1fs\n", s.deadline-now)
            end
        end
    end

    local peers = {}
    for bid, bucket in pairs(n.kad.buckets) do
        for _, p in ipairs(bucket) do
            peers[#peers+1] = {
                bid=bid,
                p=p,
            }
        end
    end

    local filter_cb, comp_cb
    if mode == 'light' then
        filter_cb = function(p)
            return p.p.trust
        end
    end
    comp_cb = function(a, b)
        local a_w_hostname = a.p.hostname and not a.p.alias
        local b_w_hostname = b.p.hostname and not b.p.alias

        if a_w_hostname and b_w_hostname then
            return a.p.hostname < b.p.hostname
        elseif a_w_hostname and not b_w_hostname then
            return true
        elseif not a_w_hostname and b_w_hostname then
            return false
        else
            return a.p.k < b.p.k
        end
    end

    do
        if filter_cb then
            for i = #peers, 1, -1 do
                local p = peers[i]
                if not filter_cb(p) then
                    table.remove(peers, i)
                end
            end
        end

        if comp_cb then
            table.sort(peers, comp_cb)
        end
    end

    local bw = n.bw and n.bw:avg()

    if #peers > 0 then
        r[#r+1] = "\n  $(bold)peers$(reset)\n"
        for _, x in ipairs(peers) do
            local bid = x.bid
            local p = x.p

            r[#r+1] = "  "

            local active = p.last_seen and now-p.last_seen <= wh.KEEPALIVE_TIMEOUT and not p.alias

            if active then
                r[#r+1] = "$(green)"
            end

            if p.alias then
                r[#r+1] = '◌ '
            elseif p.relay then
                r[#r+1] = '○ '
            elseif p.is_nated and p.addr then
                r[#r+1] = '◒ '
            elseif p.addr then
                r[#r+1] = '● '
            else
                r[#r+1] = '  '
            end

            r[#r+1] = string.format("$(reset) %s", n:key(p))

            if p.alias then
                if type(p.alias) == 'string' then
                    r[#r+1] = string.format(" is %s", p.hostname or n:key(p.alias))
                end
            elseif p.relay then
            elseif p.addr then
                r[#r+1] = string.format(': %s', p.addr)
            end

            if p.is_router then r[#r+1] = ' (master)' end
            if p.is_gateway then r[#r+1] = ' (gw)' end

            if mode == 'all' then
                r[#r+1] = string.format(" (bucket:%d)", bid)
            end

            if bw and bw[p.k] then
                local b = bw[p.k]

                r[#r+1] = " ("

                if b.tx > 0 then
                    r[#r+1] = string.format("↑ %s/s", memunit(bw[p.k].tx))
                end

                if b.tx > 0 and b.rx > 0 then
                    r[#r+1] = ", "
                end

                if b.rx > 0 then
                    r[#r+1] = string.format("↓ %s/s", memunit(bw[p.k].rx))
                end

                r[#r+1] = ")"
            end

            r[#r+1] = "\n"
        end
    end


    return table.concat(r)
end

function MT.__index.stop(n)
    n.running = false
    wh.set_pipe_event(n.pe)
end

function MT.__index.key(n, p_or_k)
    return wh.key(p_or_k, n)
end

function MT.__index.explain(n, ...)
    if n.log >= 1 then
        local fmt = select(1, ...)
        printf("$(green)" .. fmt .. "$(reset)", select(2, ...))
    end
end

function MT.__index.resolve(n, opts, cb)
    local peers = {}

    local function cont()
        if opts.k then
            local p = n.kad:get(opts.k)

            if p then
                peers[#peers+1] = p
            end
        end

        if opts.ip then
            if n.kad.root.ip == opts.ip then
                peers[#peers+1] = n.kad.root
            end

            for bid, bucket in pairs(n.kad.buckets) do
                for _, p in ipairs(bucket) do
                    if p.ip == opts.ip then
                        peers[#peers+1] = p
                    end
                end
            end
        end

        -- check every peer are identical, else drop
        for i = 2, #peers do
            if peers[1] ~= peers[i] then
                return cb()
            end
        end

        local peer = peers[1]
        if peer then
            return cb(peer.k, peer.hostname, peer.ip)
        end

        return cb()
    end

    if opts.name then
        return n:getent(opts.name, function(k)
            opts.k = k
            cont()
        end)
    else
        return cont()
    end
end

function M.new(n)
    assert(n.sk and n.port and n.port_echo)

    if n.mode == nil then n.mode = 'unknown' end
    if n.bw == nil then n.bw = true end

    if n.workbit == nil then
        n.workbit = 0
    else
        assert(n.namespace)
    end

    n.log = n.log or 0
    n.running = true
    n.k = wh.publickey(n.sk)
    n.in_udp = wh.sniff('any', 'in', 'wh', " and dst port " .. tostring(n.port))
    n.sock_echo = wh.socket_udp(wh.address('0.0.0.0', n.port_echo))
    n.sock4_raw = wh.socket_raw_udp("ip4")
    n.sock6_raw = wh.socket_raw_udp("ip6")
    n.kad = require('kadstore')(n.k, wh.KADEMILIA_K)
    n.p = n.kad.root
    n.searches = {}
    n.connects = {}
    n.auths = {}
    n.nat_detectors = {}
    n.jitter_rand = math.random() * 1
    n.pe = wh.pipe_event()
    n.frag_counter = math.floor(math.random() * 0xffff)

    if n.bw then
        n.bw = require('bwlog'){scale=1.0}
    end

    n.is_nated = n.mode ~= 'direct'

    if wh.upnp then
        n.upnp = {
            worker = wh.worker('upnp'),
            enabled = false,
            last_check = 0,
            checking = false,
        }

        n.upnp.worker:pcall(function() end, function()
            require('wh')
            require('helpers')
        end)
    end

    if n.ns then
        n.ns.worker = wh.worker('ns')

        n.ns.worker:pcall(function() end, function()
            require('wh')
            require('helpers')
        end)
    end

    return setmetatable(n, MT)
end

return M
