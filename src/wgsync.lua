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

local function explain(sy, fmt, ...)
    return sy.n:explain("(wgsync) " .. fmt, ...)
end

local function set_peers(sy, wg_peers)
    local wg_peers_remove = {}
    for _, wg_p in ipairs(wg_peers) do
        local action
        if wg_p.replace_me then
            action = "replace"
            wg_p.replace_me = nil
            wg_peers_remove[#wg_peers_remove+1] = {public_key=wg_p.public_key, remove_me=true}

        elseif wg_p.remove_me then
            action = "remove"
        else
            action = "upsert"
        end
        explain(sy, "%s peer %s", action, wh.tob64(wg_p.public_key, 'wg'))
    end

    wh.wg.set{name=sy.interface, peers=wg_peers_remove}
    wh.wg.set{name=sy.interface, peers=wg_peers}
end

-- Remove all WireGuard peers
local function remove_all_peers(sy)
    local peers = {}

    local wg = wh.wg.get(sy.interface)
    for _, wg_p in ipairs(wg.peers) do
        peers[#peers+1] = {
            public_key = wg_p.public_key,
            remove_me = true,
        }
    end

    set_peers(sy, peers)
end

local function update_peer(sy, k, p, wg_peers)
    local n = sy.n

    -- ignore self
    if k == n.p.k then
        return
    end

    -- ignore alias
    if p.alias then
        return
    end

    if p and not p.trust then
        return
    end

    local wg_peer

    -- if peer is connected, remove loopback tunnel
    if p and p.addr and not p.relay and n.lo and p.tunnel then
        n.lo:free_tunnel(p)
        assert(not p.tunnel)
    end

    if p and p.trust and p.ip then
        wg_peer = {
            public_key = p.k,
            replace_allowedips=true,
            allowedips={},
        }

        if p.ip then
            -- XXX check subnet

            local slash_idx = string.find(sy.subnet, '/')
            local cidr = string.sub(sy.subnet, slash_idx+1)

            -- XXX IPv6 Orchid

            wg_peer.allowedips[#wg_peer.allowedips+1] = {p.ip, 32}
        end

        p.endpoint = nil
        if n.p.ip then
            if p.tunnel then
                p.endpoint = 'lo'
            elseif p.addr and not p.relay then
                p.endpoint = p.addr
            elseif n.lo then
                n.lo:touch_tunnel(p)
                p.endpoint = 'lo'
            else
                p.endpoint = nil
            end
        end

        if p.endpoint ~= p._old_endpoint then
            if p.endpoint == 'lo' then
                wg_peer.endpoint = p.tunnel.lo_addr
            elseif p.endpoint then
                wg_peer.endpoint = p.endpoint
            else
                wg_peer.replace_me = true
            end

            p._old_endpoint = p.endpoint
        end

        if p.endpoint ~= nil and p.endpoint ~= 'lo' and p.is_nated then
            wg_peer.persistent_keepalive_interval = wh.NAT_TIMEOUT
        else
            wg_peer.persistent_keepalive_interval = 0
        end

    elseif not p then
        wg_peer = {
            public_key = p.k,
            remove_me = true,
        }
    end

    if wg_peer then
        wg_peers[#wg_peers+1] = wg_peer
    end
end

local function update_touched_peers(sy)
    local wg_peers_update = {}
    for k, p in pairs(sy.n.kad.touched) do
        update_peer(sy, k, p, wg_peers_update)
    end
    set_peers(sy, wg_peers_update)
end

function MT.__index.update(sy, socks)
    local deadlines = {}

    -- read WireGuard tunnel peer's activity and update p.last_seen
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

    -- if current peer has a private IP, update WireGuard conf
    if sy.wg_enabled then
        assert(sy.n.p.ip)
        update_touched_peers(sy)
    end

    return min(deadlines)
end

function MT.__index.reload(sy)
    -- if node has no IP but wireguard was enabled, remove all wireguard peers
    -- and disable
    if not sy.n.p.ip and sy.wg_enabled then
        remove_all_peers(sy)
    end

    sy.wg_enabled = not not sy.n.p.ip

    -- if enabled, remove all non trusted peers
    if sy.wg_enabled then
        local wg = wh.wg.get(sy.interface)
        local wg_peers = {}
        for _, wg_p in ipairs(wg.peers) do
            wg_peers[wg_p.public_key] = wg_p
        end

        -- if a peer has a WireGuard tunnel but is not trusted (anymore), remove
        do
            local wg_peers_remove = {}
            for bid, bucket in pairs(sy.n.kad.buckets) do
                for i, p in ipairs(bucket) do
                    if wg_peers[p.k] and not p.trust then
                        wg_peers_remove[#wg_peers_remove+1] = {
                            public_key = p.k,
                            remove_me = true,
                        }
                    end
                end
            end
            set_peers(sy, wg_peers_remove)
        end

        update_touched_peers(sy)
    end
end

function MT.__index.close(sy)
end

function M.new(sy)
    assert(sy.n and sy.interface)
    sy.p_rx = {}
    sy.wg_enabled = false
    return setmetatable(sy, MT)
end

return M

