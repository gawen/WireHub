local NODEID_NULL = 0
local DEFAULT_LAN_SUBNET = subnet("192.168.0.1", 24)
local WAN_SUBNET = subnet("0.0.0.0", 0)

local node_mt = {}
local nodes = {}

function node_mt.__bor(n, down)
    assert(down.up == nil)
    down.up = n

    n.down = n.down or {}
    n.down[#n.down+1] = down

    return down
end

function node(n)
    assert(n and n.type)
    nodes[#nodes+1] = n
    return setmetatable(n, node_mt)
end

function peer(n)
    n = n or {}

    n.type = 'peer'
    n._init = function(n)
        return _peer(
            n.id,
            'peer',
            n.up and n.up.id,
            n.up_ip,
            n.up_gw
        )
    end

    return node(n)
end

function link(n)
    n.type = 'link'
    n._init = function(n)
        return _link(
            n.id,
            'link',
            n.up and n.up.id,
            n.down and n.down.id
        )
    end
    return node(n)
end

-- NAT ------------------------------------------------------------------------

local NAT_TIMEOUT = 60
NAT_SYMMETRIC = "symmetric"
NAT_FULL_CONE = "full cone"
NAT_RESTRICTED_CONE = "restricted cone"
NAT_RESTRICTED_PORT = "restricted port"

local function mapping_rawget(t, up_id)
    local e = t[up_id]

    if e then
        assert(e.id ~= NODEID_NULL)

        if e.id ~= NODEID_NULL and now() > e.opened_ts + NAT_TIMEOUT then
            t[up_id] = nil
            e = nil
        end
    end

    return e
end

local function mapping_up_key(mode, addr, port)
    if mode == NAT_FULL_CONE then
        return ''
    elseif mode == NAT_RESTRICTED_CONE then
        return string.pack('I', addr)
    elseif mode == NAT_RESTRICTED_PORT or mode == NAT_SYMMETRIC then
        return string.pack('IH', addr, port or 0)
    end
end

local function mapping_get(n, p)
    local up_id
    local t
    local mode

    if p.p == IPPROTO_ICMP and (p.icmp_type == ICMP_ECHO or p.icmp_type == ICMP_ECHOREPLY) then
        t = n.icmp_mapping
        up_id = p.icmp_echo_id
        mode = NAT_SYMMETRIC

    elseif p.p == IPPROTO_TCP or p.p == IPPROTO_UDP then
        t = n.tcpudp_mapping
        up_id = p.dport
        mode = n.mode

    else
        error("unknown protocol")
    end

    local e = mapping_rawget(t, up_id)

    if not e then
        return nil, "not opened"
    end

    if e and not e.up_addr[mapping_up_key(mode, p.saddr, p.sport)] then
        return nil, string.format("port opened but bad mapping (NAT is %s)", n.mode)
    end

    return e
end

local function mapping_translate(n, p)
    local down_id
    local min
    local t
    local mode

    if p.p == IPPROTO_ICMP and p.icmp_type == ICMP_ECHO then
        down_id = p.icmp_echo_id
        min = 1
        mode = NAT_SYMMETRIC
        t = n.icmp_mapping

    elseif p.p == IPPROTO_TCP or p.p == IPPROTO_UDP then
        down_id = p.sport
        min = 1024
        mode = n.mode
        t = n.tcpudp_mapping

    else
        error("unknown protocol")
    end

    local function check(up_id)
        local e = mapping_rawget(t, up_id)
        if e and (e.down_addr ~= p.saddr or e.down_id ~= down_id) then
            return nil
        end

        if not e then
            e = {
                id = p.from_id,
                down_addr = p.saddr,
                down_id = down_id,
                up_addr = {},
            }

            t[up_id] = e
        end

        e.opened_ts = now()
        e.up_addr[mapping_up_key(mode, p.daddr, p.dport)] = true

        return e
    end

    local up_id = down_id
    if mode == NAT_SYMMETRIC then
        up_id = (up_id * p.saddr) % 65534 + 1
        up_id = (up_id * p.daddr) % 65534 + 1

        if p.p == IPPROTO_TCP or p.p == IPPROTO_UDP then
            up_id = (up_id * p.dport) % 65534 + 1
        end
    end

    assert(up_id ~= nil)

    local v
    v = check(up_id)
    if v ~= nil then return up_id, v end

    for i = min, 65535 do
        v = check(i)
        if v ~= nil then return i, v end
    end

    return nil
end


local function _nat_kernel(n, p)
    -- XXX IP fragmentation

    if p.p == IPPROTO_ICMP then
        if p.dir == UP then
            if p.icmp_type == ICMP_ECHO then
                -- allocate opened entry
                local up_echo_id, e = mapping_translate(n, p)

                if not up_echo_id then
                    return "NAT ICMP full"
                end

                assert(e.id ~= NODEID_NULL)

                -- modify IP packet
                p.saddr = n.up_ip:ip().s_addr
                p.icmp_echo_id = up_echo_id

                -- redirect to up
                return n.up.id
            else
                return "unknown ICMP packet"
            end
        else
            if p.icmp_type == ICMP_ECHO then
                p.dir = p.dir == UP and DOWN or UP
                p.daddr = p.saddr
                p.saddr = n.up_ip:ip().s_addr
                p.icmp_type = ICMP_ECHOREPLY

                return p.from_id
            elseif p.icmp_type == ICMP_ECHOREPLY then
                local e, err = mapping_get(n, p)

                if not e then
                    return err
                end

                -- modify IP
                p.daddr = e.down_addr
                p.icmp_echo_id = e.down_id

                -- redirect to down
                return e.id
            else
                return "unknown ICMP packet"
            end
        end
    elseif p.p == IPPROTO_TCP or p.p == IPPROTO_UDP then
        if p.dir == UP then
            local nat_sport, e = mapping_translate(n, p)

            if not nat_sport then
                return "NAT full"
            end

            assert(e.id ~= NODEID_NULL)

            -- modify IP header
            p.saddr = n.up_ip:ip().s_addr
            p.sport = nat_sport

            -- redirect to up
            return n.up.id
        else
            local e, err = mapping_get(n, p)

            if not e then
                return err
            end

            -- XXX

            -- modify IP
            p.daddr = e.down_addr
            p.dport = e.down_id

            -- redirect to down
            return e.id
        end
    else
        return "unknown protocol"
    end
end

function nat(n)
    n.type = 'nat'
    n.mode = n.mode or NAT_RESTRICTED_PORT

    n._init = function(n)
        return _nat(
            n.id,
            'nat',
            n.up and n.up.id,
            n.up_ip,
            n.up_gw,
            function(...) return _nat_kernel(n, ...) end
        )
    end
    n.lan_subnet = n.lan_subnet or DEFAULT_LAN_SUBNET
    n.down_ip = n.lan_subnet
    n.lan_ip = n.lan_subnet:next()
    n.tcpudp_mapping = {}
    n.icmp_mapping = {}

    return node(n)
end

function _init_wan(n)
    -- create WAN simulation

    local routes = {}

    local browse_down
    function browse_down(n)
        if n.up_ip then
            routes[#routes+1] = {n.up_ip, n.id}
        else
            for _, n_down in ipairs(n.down) do
                browse_down(n_down)
            end
        end
    end
    browse_down(n)


    return _wan(
        n.id,
        'wan',
        NODEID_NULL,
        routes
    )
end

function wan()
    return node{
        type='wan',
        _init = _init_wan
    }
end

function _build()
    local cur_peer_id = 0

    -- get maximum peer id
    for _, node in ipairs(nodes) do
        if node.type == 'peer' then
            if not node.id then
                cur_peer_id = cur_peer_id + 1
                node.id = cur_peer_id
            end

            if node.id > cur_peer_id then
                cur_peer_id = node.id
            end
        end
    end

    -- allocate IDs
    for _, node in ipairs(nodes) do
        if not node.id then
            cur_peer_id = cur_peer_id + 1
            node.id = cur_peer_id
        end
    end

    local function browse_and_alloc(n, parent, gw)
        assert(node and parent and gw)

        n.up_gw = gw

        if n.up and n.type ~= 'link' then
            if n.up_ip then
                -- do nothing
            elseif parent.lan_ip then
                n.up_ip = parent.lan_ip
                n.up_gw = gw

                parent.lan_ip = parent.lan_ip:next()
            else
                n.up_ip = randomwan()
            end
        end

        if n.type == 'nat' then
            parent = n
            gw = n.down_ip
        end

        for _, n_down in ipairs(n.down or {}) do
            browse_and_alloc(n_down, parent, gw)
        end
    end

    -- allocate IPs
    for _, node in ipairs(nodes) do
        if not node.up then
            node.ip = node.ip or randomwan()
            browse_and_alloc(node, node, WAN_SUBNET)
        end
    end

    -- init every node
    _alloc_nodes(cur_peer_id)
    for _, node in ipairs(nodes) do
        node:_init()
    end
end

function M() end

