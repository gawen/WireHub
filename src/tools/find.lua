function help()
    print('Usage: wh find <interface> <base64 public key>')
end

local interface = arg[2]
local b64k = arg[3]

if not interface or not b64k then
    return help()
end

local wg = wh.wg.get(interface)

if not wg then
    print("Unable to access interface: No such device")
    return
end

local ok, k = pcall(wh.fromb64, b64k)

if not ok then
    print("Invalid key")
    return
end

local ipc=require'ipc'

local ok, value = pcall(ipc.call, interface, 'search ' .. b64k)

if not ok then
    printf("%s\nError when connecting to WireHub daemon.", value)
    return
end

local sock = value
if not sock then
    print("Interface not attached to WireHub")
    return
end

local buf = ''
while true do
    local r = wh.select({sock}, {}, {}, 60)

    if #r == 0 then
        break
    end

    local chunk = wh.recv(sock, 65535)
    buf = buf .. chunk

    local newline_idx = string.find(buf, '\n')
    if newline_idx then
        local line = string.sub(buf, 1, newline_idx-1)
        buf = string.sub(buf, newline_idx+1)

        on_new_endpoint(line)
    end
end
