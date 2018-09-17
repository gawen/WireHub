function help()
    print('Usage: wh authenticate <interface> {<hostname>|<base64 public key>} <alias private key>')
end

if arg[2] == 'help' then
    return help()
end

local interface = arg[2]
local k = arg[3]
local alias_sk_path = arg[4]

if not interface or not k or not alias_sk_path then
    return help()
end

-- XXX
local alias_sk = wh.readsk(alias_sk_path)
if not alias_sk then
    printf('cannot load alias private key: %s', alias_sk_path)
    return help()
end

local cmd = string.format('authenticate %s %s', k, alias_sk_path)
local ok, value = pcall(require('ipc').call, interface, cmd)

if not ok then
    printf("error when connecting to WireHub daemon: %s", value)
end

local sock = value
if not sock then
    print("Interface not attached to WireHub")
    return
end

local via_k, addr, mode, is_nated, relay

local resp = {}
now = wh.now()
while true do
    local r = wh.select({sock}, {}, {}, now+30)
    --now = wh.now()

    if not r[sock] then
        wh.close(sock)
        r={'timeout'}
        return -1       -- timeout
    end

    local buf = wh.recv(sock, 65535)
    if not buf or #buf == 0 then
        break
    end

    resp[#resp+1] = buf
end
wh.close(sock)

resp = table.concat(resp)
if string.match(resp, 'authenticated!') then
    return 0
else
    resp = string.match(resp, 'failed: (.*)\n')
    if resp then
        printf('%s', resp)
    end
    return -1
end

