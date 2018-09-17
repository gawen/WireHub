#!/usr/bin/env lua

function execf(...)
    local cmd = string.format(...)
    print(cmd)
    return os.execute(cmd)
end

seed = io.popen("dd if=/dev/urandom bs=1 count=4"):read()
seed = string.unpack("I", seed)
math.randomseed(seed)

port = math.floor(math.random()*(65535-1024)+1024)

execf("make")
os.execute("wh clear jgl")
os.execute("wh set jgl workbit 8 subnet 10.0.42.1/24")

os.execute("wh set jgl peer P17zMwXJFbBdJEn05RFIMADw9TX5_m2xgf31OgNKX3w endpoint bootstrap.wirehub.io")
--os.execute("wh set jgl peer P17zMwXJFbBdJEn05RFIMADw9TX5_m2xgf31OgNKX3w endpoint 172.17.0.1")
os.execute("wh set jgl name root.jgl peer ZvuWjYZPQL7NGBZKXsB7zJgqVpY3zG_h-8ALBE3QHTM ip 10.0.42.1 router yes")
os.execute("wh set jgl name test1.jgl alias ahfGTIiek0znHEnNTk-G1yjNEoDlhQ_g-OLliAMii3g")

local id = tonumber(arg[1])
assert(id)

local key = arg[2] or 'rand'
local mode = arg[3] or 'nat'

if key == 'rand' then
    execf("wh genkey jgl > sk")
else
    execf("echo " .. os.getenv('EXAMPLE' .. key .. '_KEY') .. " > sk")
end

execf("cat sk | wg pubkey > k")
execf("cat k | wh orchid jgl - | tee orchid")

local orchid = io.popen("cat orchid"):read()


execf("ip link del wg%d", id)
execf("ip link add dev wg%d type wireguard", id)
execf("wg set wg%d private-key ./sk listen-port %d", id, port)
execf("ip addr add 10.0.42.%d/24 dev wg%d", id, id)
execf("ip addr add %s/128 dev wg%d", orchid, id)
execf("ip link set wg%d up", id)

do
    local wh=require'wh'

    local i = 1
    while true do
        local i_sk = os.getenv('EXAMPLE' .. tostring(i) .. '_KEY')

        if i_sk == nil then
            break
        end

        local i_k = io.popen(string.format("echo %s | wg pubkey", i_sk)):read()

        if i ~= tonumber(key) then
            execf("wg set wg%d peer %s allowed-ips 10.0.42.%d/32", id, i_k, i)
        end

        i = i + 1
    end
end

if os.getenv('FOREGROUND') then
    cmd = 'attach'
else
    cmd = 'up'
end

execf("wh %s jgl interface wg%d mode %s", cmd, id, mode)
