function help()
    print("Usage: wh reload {<interface> | all}")
end

local ipc = require'ipc'

local all = {}
local interface = arg[2]

if interface == 'all' then interface = nil end

local function call(interface, cmd)
    local ok, value = pcall(ipc.call, interface, cmd)

    if not ok then
        printf("Error when connecting to WireHub daemon: %s\n", value)
        return
    end

    local sock = value
    if not sock then
        return
    end

    local buf = {}
    while true do
        local r = wh.select({sock}, {}, {}, 1)

        if not r[sock] then
            r[#r+1] = '\n(daemon timeout)'
            break
        end

        local chunk = wh.recv(sock, 65535)
        if not chunk or #chunk == 0 then
            break
        end

        buf[#buf+1] = chunk
    end

    wh.close(sock)

    return table.concat(buf)
end

local names
local whs = wh.ipc_list()
for _, v in ipairs(whs) do whs[v] = true end
if interface then
    if not whs[interface] then
        printf('invalid interface: %s', interface)
        return help()
    end

    names = {interface}
else
    names = whs
end

table.sort(names)

for _, name in ipairs(names) do
    local status = call(name, 'reload')

    if status ~= 'OK\n' then
        printf("interface $(bold)%s$(reset): %s", name,status)
    end
end

