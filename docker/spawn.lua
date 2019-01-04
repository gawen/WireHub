#!/usr/bin/env lua

-- Spawn X nodes
--
-- Usage: spawn.lua 100     # start 100 nodes

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
    print("spawn", i)
    os.execute("wh up public listen-port 0")
end
