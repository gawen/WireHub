function help()
    print("Usage: wh show {<interface> | all | interfaces } [light | all]")
end

local ipc = require'ipc'

local all = {}
local interface = arg[2]

local mode = 'light'
if interface == 'interfaces' then
    local interfaces = wh.ipc_list()
    table.sort(interfaces)
    for _, i in ipairs(interfaces) do
        print(i)
    end

    return 0

elseif interface then
    mode = arg[3]
    if mode == nil then mode = 'light' end
    local mode_ok = ({
        light=true,
        all=true,
    })[mode]

    if not mode_ok then
        printf('invalid mode: %s', mode)
        return help()
    end
end

if interface == 'all' then interface = nil end

local function call(interface, cmd)
    local ok, value = pcall(ipc.call, interface, cmd)

    if not ok then
        printf("%s\nError when connecting to WireHub daemon.", value)
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
    local cmd = string.format('describe %s', mode)
    local info = call(name, cmd)

    if info then
        printf("interface $(bold)%s$(reset), %s", name, info)
    end
end

