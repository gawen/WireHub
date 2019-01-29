function help()
    print('Usage: wh orchid {<network file path> | namespace <namespace>}')
end

if arg[2] == 'help' then
    return help()
end

local conf
local idx
if arg[2] and arg[2] ~= "namespace" then
    local err
    conf, err = openconf(arg[2])
    if not conf then
        printf("error: %s", err)
        return -1
    end

    idx = 3

else
    idx = 2
end

if not conf then
    conf = parsearg(idx, {
        namespace=tostring,
    })

    if not conf.namespace then
        conf.namespace = wh.DEFAULT_NAMESPACE
    end
end

local b64k = io.stdin:read()
local ok, value = pcall(wh.fromb64, b64k)

if not ok then
    printf("invalid key")
    return -1
end

local k = value

local addr = wh.orchid(conf.namespace, k, 0)

addr = tostring(addr)
addr = string.sub(addr, 2, string.find(addr, ']')-1)

print(addr)
