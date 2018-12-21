function help()
    print('Usage: wh set <network name> ' ..
        '[namespace <namespace>] ' ..
        '[subnet <IP subnetwork>] ' ..
        '[workbit <work bits>] ' ..
        '[{ peer <base64 public key> | ' ..
           '[name <hostname>] } ' ..
            '[alias <base64 public key>] ' ..
            '[bootstrap {yes|no}] ' ..
            '[allowed-ips <ip1>/<cidr1>[,<ip2>/<cidr2>]...] ' ..
            '[endpoint <ip>:<port>] ' ..
            '[gateway {yes|no}] ' ..
            '[ip <ip>] ' ..
            '[router {yes|no}] ' ..
            '[untrusted] ' ..
            '[remove] ' ..
        ']'
    )
end

if arg[2] == 'help' then
    return help()
end

local name = arg[2]

if not name then
    return help()
end

local function tohost(n)
    local m = string.match(n, '([%a%d%.%-%_]+)')
    if m ~= n then
        n = nil
    end
    return n
end

local function tosubnet(x)  -- XXX TODO
    return tostring(x)
end

local function split_comma(x, cb)
    local r = {}
    for subnet in string.gmatch(x, "([^,]+)") do
        if not subnet then
            return nil
        end
        r[#r+1] = subnet
    end

    return r
end

local function fromb64_or_false(x)
    if x == 'none' or x == 'remove' then
        return false
    end

    return wh.fromb64(x)
end

local opts = parsearg(3, {
    alias=fromb64_or_false,
    ['allowed-ips']=function(x) return split_comma(x, tosubnet) end,
    bootstrap=parsebool,
    endpoint=function(s) return wh.address(s, wh.DEFAULT_PORT) end,
    gateway=parsebool,
    name=tohost,
    ip=function(s)
        -- XXX
        if not wh.address(s, 0) then
            return nil
        end

        return s
    end,
    namespace=tostring,
    peer=wh.fromb64,
    remove=true,
    router=parsebool,
    subnet=tosubnet,
    untrusted=true,
    workbit=tonumber,
})

if not opts then
    return help()
end

if not opts.peer and not opts.name then
    for _, o in ipairs{
        'allowed-ips',
        'bootstrap',
        'endpoint',
        'gateway',
        'ip',
        'remove',
        'router',
        'untrusted',
    } do
        if opts[o] then
            printf('Invalid argument: %s', o)
            return help()
        end
    end
end

local conf = wh.fromconf(wh.readconf(name))

conf = conf or {peers={}}

local k_map = {}
local host_map = {}
for i, p in ipairs(conf.peers) do
    if p.k then k_map[p.k] = i end
    if p.hostname then host_map[p.hostname] = i end
end

conf.name = name
conf.namespace = opts.namespace or conf.namespace or 'public'
conf.workbit = opts.workbit or conf.workbit
conf.subnet = opts.subnet or conf.subnet

local k_idx = opts.peer and k_map[opts.peer]
local host_idx = opts.name and host_map[opts.name]

if opts.peer or opts.name then
    if opts.peer and opts.name and k_idx ~= host_idx and host_idx then
        printf('Host already exists: %s', opts.name)
        return help()
    end

    local idx = k_idx or host_idx

    if opts.remove then
        if idx then
            table.remove(conf.peers, idx)
        end
    else
        if not idx then
            idx = #conf.peers+1
            conf.peers[idx] = {}
        end
        local p = conf.peers[idx]

        if opts.peer then
            -- check workbit is respected
            local wb = wh.workbit(opts.peer, conf.namespace)

            if wb < (conf.workbit or 0) then
                printf("Insufficient workbit: %d (minimum is %d)", wb, conf.workbit or 0)
                return
            end

            p.k = opts.peer
        end

        p.addr = opts.endpoint or p.addr

        if opts.alias then
            p.alias = opts.alias
        elseif opts.alias == false then
            p.alias = nil
        end

        p['allowed-ips'] = opts['allowed-ips'] or p['allowed-ips']
        if opts.gateway then p.is_gateway = opts.gateway end
        p.hostname = opts.name or p.hostname
        p.ip = opts.ip and wh.address(opts.ip) or p.ip
        if opts.router then p.is_router = opts.router end
        if p.trust == nil then p.trust = true end
        if opts.untrusted then p.trust = false end
        if opts.bootstrap then p.bootstrap = opts.bootstrap end
    end
end

local conf = wh.toconf(conf)
wh.fromconf(conf) -- check conf

wh.writeconf(name, conf)
