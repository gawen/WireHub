function help()
    print('Usage: wh workbit {<network file path> | namespace <namespace>}')
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

local k = io.stdin:read()
local ok, value = pcall(wh.fromb64, k)

if not ok then
    printf("Invalid name: %s", value)
    return
end

k = value

local wb = wh.workbit(k, conf.namespace or 'public')

print(wb)
