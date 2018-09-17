function help()
    printf('Usage: wh connect <interface> <base64 public key>')
end

if arg[2] == 'help' then
    return help()
end

local interface = arg[2]
local k = arg[3]

if not interface or not k then
    return help()
end

local ipc_cmd = string.format('connect %s', k)
local ok, value = pcall(require('ipc').call, interface, ipc_cmd)
if not ok then
    printf("%s\nError when connecting to WireHub daemon.", value)
    return
end

local sock = value
if not sock then
    print("Interface not attached to WireHub")
    return
end

local b64k, via_b64k, addr, mode, is_nated, relay

now = wh.now()
while true do
    local r = wh.select({sock}, {}, {}, now+30)
    now = wh.now()

    if not r[sock] then
        wh.close(sock)
        printf("timeout")
        return -1       -- timeout
    end

    local buf = wh.recv(sock, 65535)

    if not buf or #buf == 0 then
        break
    end

    b64k, mode, addr, via_b64k = string.match(buf, '([^ ]+) ([^ ]+) ([^ ]+) ([^ ]+)\n')

    if not via_b64k or not addr or not mode then
        printf("$(red)bad format: %s$(reset)", buf)
        wh.close(sock)
        return -1
    end

    addr = wh.address(addr, 0)

    if mode == '(direct)' then
        mode = 'direct'
    elseif mode == '(nat)' then
        mode = 'nat'
        is_nated = true
    else
        relay = wh.fromb64(mode)
        mode = 'relay'
    end
end
wh.close(sock)

local found
local m = {}
if mode == 'relay' then
    found = true
    m[#m+1] = string.format('relay %s', wh.key(relay))
elseif mode == 'nat' then
    found = true
    m[#m+1] = string.format('nat %s', addr)
elseif mode == 'direct' then
    found = true
    m[#m+1] = string.format('direct %s', addr)
else
    found = false
    m[#m+1] = "not found"
end

m = table.concat(m)

if cmd == 'lookup' then
    print(m)
    return found and 0 or -1

elseif cmd == 'ping' then
    if found then
        printf('ping %s: time=%.2fms', m, (now-time_before_ping)*1000.0)
    else
        print('offline')
    end

elseif cmd == 'p2p' then
    local k = wh.fromb64(b64k)
    if mode == 'relay' then
        printf('unable to open a p2p connection')
        return -1
    end

    local peer = {
        public_key=k,
        endpoint=addr,
    }

    if mode == 'nat' then
        peer.persistent_keepalive_interval = wh.NAT_TIMEOUT
    end


    local ok, err = pcall(wh.wg.set, {name=interface, peers={peer}})

    if not ok then
        printf('error when setting up wireguard interface %s: %s', interface, err)
        return -1
    end

    printf('connected to %s', m)
end

return found and 0 or -1

