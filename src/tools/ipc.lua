function help()
    print('Usage: wh ipc <interface> <cmd>')
end

local interface = arg[2]

if not interface then
    return help()
end

local s = {}
local idx = 3
while arg[idx] do
    if arg[idx] == '-' then
        s[#s+1] = io.stdin:read()
        s[#s+1] = ' '
        break
    else
        s[#s+1] = arg[idx]
        s[#s+1] = ' '
        idx = idx + 1
    end
end

if #s == 0 then
    return help()
end

s[#s] = nil
s = table.concat(s)

local ipc=require'ipc'

local ok, value = pcall(ipc.call, interface, s)

if not ok then
    printf("%s\nError when connecting to WireHub daemon.", value)
    return
end

local sock = value
if not sock then
    print("Interface not attached to WireHub")
    return
end

while true do
    wh.select({sock}, {}, {}, nil)

    local buf = wh.recv(sock, 65535)

    if not buf or #buf == 0 then
        break
    end

    io.stdout:write(buf)
    io.stdout:flush()
end

wh.close(sock)
