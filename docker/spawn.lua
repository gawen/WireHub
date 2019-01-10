#!/usr/bin/env lua

-- Spawn X nodes
--
-- Usage: spawn.lua 100     # start 100 nodes

require('wh')

io.popen('mkdir -p /tmp/spawn')

if arg[1] == nil then
    print(string.format("usage: %s <count of peers to spawn>", arg[0]))
    print()
    print( "Spawn N WireHub peers (without WireGuard interface). This is useful to populate\n" ..
        "a network with ephemeron peers."
    )
    return
end

local n = tonumber(arg[1])

for i = 1, n do
    local b64k = io.popen(string.format("wh genkey public | tee /tmp/spawn/%s.sk | wh pubkey", i)):read()
    print(b64k)
    local k = wh.fromb64(b64k)

    print("spawn", i, b64k)
    os.execute(string.format("WH_LOGPATH=/tmp/spawn/%s.log wh up public private-key /tmp/spawn/%s.sk listen-port 0 &", b64k, i))
end
