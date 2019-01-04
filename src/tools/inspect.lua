function help()
    print('Usage: wh inspect {all | <interface>}')
end

local interface = arg[2]
if not interface or interface == 'help' then
    return help()
end

local ipc=require'ipc'

local function inspect(interface)
    local ok, value = pcall(ipc.call, interface, 'inspect')

    if not ok then
        printf("%s\nError when connecting to WireHub daemon.", value)
        return -1
    end

    local sock = value
    if not sock then
        return -1
    end

    local ret = {}
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

        ret[#ret+1] = buf
    end

    wh.close(sock)

    return table.concat(ret)
end

if interface == 'all' then
    print('[')

    local interfaces = wh.ipc_list()
    table.sort(interfaces)
    for i, k in ipairs(interfaces) do
        if i > 1 then
            io.stdout:write(', ')
        end
        local v = inspect(k)
        if v == -1 then return -1 end
        io.stdout:write(v)
    end

    print(']')
else
    local v = inspect(k)
    if v == -1 then return -1 end
    print(v)
end

