-- WireGuard <-> WireHub synchronization
--
-- Configure WireGuard with latest WireHub metadata about peers. Set keys,
-- endpoints, persistent keep-alive, ...
--
-- Update the last time each peer was seen by WireGuard, to have a unified view
-- for WireHub and WireGuard.

-- XXX handles sync from wg to wh

local REFRESH_EVERY = wh.NAT_TIMEOUT / 2

local M = {}

local MT = {
    __index = {}
}

function MT.__index.update(sy, socks)
    local deadlines = {}

    local deadline = (sy.last_sync or 0) + REFRESH_EVERY
    if deadline <= now then
        local wg = wh.wg.get(sy.interface)
        for _, wg_p in pairs(wg.peers) do
            local k = wg_p.public_key
            local p = sy.n.kad:get(k)

            if p then
                p.wg_connected = wg_p.last_handshake_time > 0

                if (p.last_seen or 0) < wg_p.last_handshake_time then
                    p.last_seen = wg_p.last_handshake_time
                end

                if wg_p.rx_bytes ~= (sy.p_rx[k] or 0) then
                    p.last_seen = now
                    sy.p_rx[k] = wg_p.rx_bytes
                end
            end
        end

        sy.last_sync = now
        deadline = (sy.last_sync or 0) + REFRESH_EVERY
    end
    deadlines[#deadlines+1] = deadline

    for k, p in pairs(sy.n.kad.touched) do
        local comment = nil
        if k ~= sy.n.p.k and (not p or p.trust) then
            local peer

            -- destroy tunnel
            if sy.n.lo and p and p.tunnel and p.addr and not p.relay then
                sy.n.lo:free_tunnel(p)
                assert(not p.tunnel)
            end

            if p and p.trust and not p.alias and p.ip then
                peer = {
                    public_key = p.k,
                    replace_allowedips=true,
                    allowedips={},
                }

                if p.ip then
                    -- XXX check subnet

                    local slash_idx = string.find(sy.subnet, '/')
                    local cidr = string.sub(sy.subnet, slash_idx+1)

                    -- XXX IPv6 Orchid

                    peer.allowedips[#peer.allowedips+1] = {p.ip, 32}
                end

                p.endpoint = nil
                if sy.n.p.ip then
                    if p.tunnel then
                        p.endpoint = 'lo'
                    elseif p.addr and not p.relay then
                        p.endpoint = p.addr
                    elseif sy.n.lo then
                        sy.n.lo:touch_tunnel(p)
                        p.endpoint = 'lo'
                    else
                        p.endpoint = nil
                    end
                end

                if p.endpoint ~= p._old_endpoint then
                    if p.endpoint == 'lo' then
                        peer.endpoint = p.tunnel.lo_addr
                    elseif p.endpoint then
                        peer.endpoint = p.endpoint
                    else
                        comment = "replace"
                        wh.wg.set{name=sy.interface, peers={public_key=p.k, remove_me=true}}
                    end

                    p._old_endpoint = p.endpoint
                end

                if p.endpoint ~= nil and p.endpoint ~= 'lo' and p.is_nated then
                    peer.persistent_keepalive_interval = wh.NAT_TIMEOUT
                else
                    peer.persistent_keepalive_interval = 0
                end

            elseif not p then
                comment = "remove"
                peer = {
                    public_key = p.k,
                    remove_me = true,
                }
            end

            if peer then
                comment = comment or "upsert"
                --printf("$(orange)%s %s$(reset)", comment, dump(peer))

                wh.wg.set{name=sy.interface, peers={peer}}
            end
        end
    end


    return min(deadlines)
end

function MT.__index.close(sy)
end

function M.new(sy)
    assert(sy.n and sy.interface)
    sy.p_rx = {}
    return setmetatable(sy, MT)
end

return M

