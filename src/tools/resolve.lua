function help()
    printf('Usage: wh resolve <hostname>')
end

if not arg[2] or arg[2] == 'help' then
    return help()
end

local name = arg[2]

local function resolve(cmd, name)
    local resolv = {}

    for _, interface in ipairs(wh.ipc_list()) do
        local ipc_cmd = string.format('%s %s', cmd, name)
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

        now = wh.now()
        while true do
            local r = wh.select({sock}, {}, {}, now+1)
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

            local b64k, hostname, ip = string.match(buf, '([^%s]+)\t([^%s]*)\t([^%s]*)\n')

            if not b64k then
                break
            end

            if hostname and #hostname == 0 then
                hostname = nil
            end

            if ip and #ip == 0 then
                ip = nil
            end

            if hostname or ip then
                resolv[#resolv+1] = {interface, b64k, hostname, ip}
            end
            break
        end
        wh.close(sock)
    end

    return resolv
end

local is_host = true
local resolv = resolve('gethostbyname', name)

if #resolv == 0 then
    is_host = false
    resolv = resolve('gethostbyaddr', name)
end

if #resolv == 1 then
    local r = resolv[1][is_host and 4 or 3]
    if r then
        print(r)
    end
elseif #resolv >= 2 then
    print("multiple results")
    for _, v in ipairs(resolv) do
        printf("  %s: %s", resolv[1], resolv[2])
    end
    return -1
end
