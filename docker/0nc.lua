#!/usr/bin/env lua

require('wh')

function execf(...)
    local cmd = string.format(...)
    --print(cmd)
    return os.execute(cmd)
end

function readb64(fp, mode)
    local fh = io.open(fp)
    if not fh then error(string.format('file not found: %s', fp)) end
    local buf = wh.fromb64(fh:read(), mode)
    fh:close()
    return buf
end

function writeb64(fp, buf, mode)
    local fh = io.open(fp, 'w')
    fh:write(wh.tob64(buf, mode) .. '\n')
    fh:close()
end

execf("make > /dev/null 2> /dev/null")
execf("wh clearconf znc")
execf("wh set znc workbit 8 subnet 10.0.42.1/24")
execf("wh set znc endpoint bootstrap.wirehub.io bootstrap yes untrusted peer P17zMwXJFbBdJEn05RFIMADw9TX5_m2xgf31OgNKX3w")

execf("wh genkey znc | tee /tmp/znc.sk | wh pubkey > /tmp/znc.k")

local k = readb64('/tmp/znc.k')

execf("ip link add dev wg1 type wireguard")
execf("wg set wg1 private-key /tmp/znc.sk listen-port 0")
execf("ip link set wg1 up")

local is_server = arg[1] == nil

if is_server then
    execf("wh genkey znc | tee /tmp/alias.znc.sk | wh pubkey > /tmp/alias.znc.k")
    local alias_sk = readb64('/tmp/alias.znc.sk', 'wg')
    local alias_k = readb64('/tmp/alias.znc.k')

    execf("wh set znc ip 10.0.42.1 name server.znc router yes peer %s", wh.tob64(k))
    execf("wh set znc ip 10.0.42.2 name client.znc alias %s", wh.tob64(alias_k))
    execf("wh up znc interface wg1 mode nat")

    local invit = wh.tob64(k .. alias_sk)

    print("znc invitation: " .. invit)

    execf("nc -l -p 1234")
else
    local keys = wh.fromb64(arg[1])
    local server_k = string.sub(keys, 1, 32)
    local alias_sk = string.sub(keys, 33, 64)
    local alias_k = wh.publickey(alias_sk)

    writeb64('/tmp/alias.znc.sk', alias_sk, 'wg')

    execf("wh set znc ip 10.0.42.1 name server.znc router yes peer %s", wh.tob64(server_k))
    execf("wh set znc ip 10.0.42.2 name client.znc alias %s", wh.tob64(alias_k))
    execf("wh up znc interface wg1 mode nat")

    execf("sleep 1")
    execf("wh auth wg1 %s /tmp/alias.znc.sk", wh.tob64(server_k))

    execf("sleep 1")
    execf("nc 10.0.42.1 1234")
end
