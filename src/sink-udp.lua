require'wh'

local s = wh.socket_udp(wh.address('0.0.0.0', wh.DEFAULT_PORT))

while true do
    wh.select({s}, {}, {})
    wh.recvfrom(s, 1500)
end

