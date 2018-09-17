function help()
    print('Usage: wh orchid <network name> <base64 public key>')
end

if arg[2] == 'help' then
    return help()
end

local name = arg[2]

if not name then
    return help()
end

local conf = wh.fromconf(wh.readconf(name))

if not conf then
    printf("Unknown network `%s'", name)
    return help()
end

local b64k = arg[3]

if b64k == '-' then
    b64k = io.stdin:read()
end

if b64k == nil then
    return help()
end

local ok, value = pcall(wh.fromb64, b64k)

if not ok then
    printf("Invalid key: %s", value)
    return
end

local k = value

local addr = wh.orchid(conf.namespace or 'public', k, 0)

addr = tostring(addr)
addr = string.sub(addr, 2, string.find(addr, ']')-1)

print(addr)
