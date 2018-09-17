function help()
    printf('Usage: wh forget <interface> <base64 public key>')
end

if arg[2] == 'help' then
    return help()
end

local interface = arg[2]
local k = arg[3]

if not interface or not k then
    return help()
end

local ipc_cmd = string.format('forget %s', k)
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

    printf("$(red)bad format: %s$(reset)", buf)
    break
end
wh.close(sock)

