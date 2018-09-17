function help()
    print('Usage: wh showconf <network name>')
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

print(wh.toconf(conf))

