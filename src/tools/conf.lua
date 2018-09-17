local cmd = arg[1]

function help()
    if cmd == 'clearconf' then
        printf("Usage: wh %s <network name>", cmd)
    else
        printf("Usage: wh %s <network name> {<configuration filename>|'-'}", cmd)
    end
end

if arg[2] == 'help' then
    return help()
end

local name = arg[2]

if not name then
    return help()
end

if cmd == 'clearconf' then
    wh.writeconf(name, nil)
    return
end

local conf_s = wh.readconf(name)
local conf
if conf_s then
    conf = wh.fromconf(conf_s)
end

if not arg[3] then
    return help()
end

local conf_filepath = arg[3]
local conf_fh
if conf_filepath == '-' then
    conf_fh = io.stdin
else
    conf_fh = io.open(conf_filepath, 'r')
end

local conf_s = {}
while true do
    local c = conf_fh:read()
    if c == nil then
        break
    end

    conf_s[#conf_s+1] = c .. '\n'
end
conf_s = table.concat(conf_s)

if conf_fh ~= io.stdin then
    conf_fh:close()
end

local updated_conf = wh.fromconf(conf_s)

if not updated_conf then
    printf('Invalid configuration')
    return -1
end

if cmd == 'setconf' or conf == nil then
    conf = updated_conf
    conf.name = name
else
    assert(cmd == 'addconf')

    conf.workbit = updated_conf.workbit or conf.workbit

    local to_add = {}
    for _, up in ipairs(updated_conf.peers) do
        local found = false
        for _, p in ipairs(conf.peers) do
            if p.k == up.k then
                p.hostname = up.hostname or p.hostname
                if up.is_router ~= nil then p.is_router = up.is_router end
                if up.is_gateway ~= nil then p.is_gateway = up.is_gateway end
                if up.trust ~= nil then p.trust = up.trust end
                p.ip = up.ip or p.ip
                if up.bootstrap ~= nil then p.bootstrap = up.bootstrap end
                p['allowed-ips'] = up['allowed-ips'] or p['allowed-ips']
                found = true
                break
            end
        end

        if not found then
            to_add[#to_add+1] = up
        end
    end

    for _, p in ipairs(to_add) do
        conf.peers[#conf.peers+1] = p
    end
end

local conf = wh.toconf(conf)
wh.fromconf(conf)   -- check conf

wh.writeconf(name, conf)

