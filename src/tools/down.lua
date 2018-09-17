function help()
    print('Usage: wh down <interface>')
end

local interface = arg[2]
if not interface then
    return help()
end

local ipc=require'ipc'

local ok, value = pcall(ipc.call, interface, 'down')

if not ok then
    printf("%s\nError when connecting to WireHub daemon.", value)
    return
end

local sock = value
if not sock then
    print("Interface not attached to WireHub")
    return -1
end

local ret = -1

now = wh.now()
while true do
    local r = wh.select({sock}, {}, {}, now+30)
    now = wh.now()

    if not r[sock] then
        printf("timeout")
        break
    end

    local buf = wh.recv(sock, 65535)

    if not buf or #buf == 0 then
        break
    end

    if buf == "OK\n" then
        ret = 0
        break
    end
end
wh.close(sock)

return ret

