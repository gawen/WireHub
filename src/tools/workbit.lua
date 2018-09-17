function help()
    print('Usage: wh workbit <network name>')
end

if arg[2] == 'help' then
    return help()
end

local name = arg[2]

if not name then
    return help()
end

local conf_s = wh.readconf(name)

if not conf_s then
    return
end

local conf = wh.fromconf(conf_s)

if not conf then
    print('Invalid configuration')
    return
end

local k = io.stdin:read()
local ok, value = pcall(wh.fromb64, k)

if not ok then
    printf("Invalid name: %s", value)
    return
end

k = value

local wb = wh.workbit(k, conf.namespace)

print(wb)
