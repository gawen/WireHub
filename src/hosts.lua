-- XXX race condition!

local M = {}

local HOSTS_PATH = "/etc/hosts"
--local COMMENT_BEGIN = "# WireHub hosts (automatically generated, DO NOT EDIT)"
--local COMMENT_END = "# End of WireHub hosts"

-- Returns a sorted table with all peers which should appear in /etc/hosts
local function list_peers(n)

    local peers = {}

    for bid, bucket in pairs(n.kad.buckets) do
        for i, p in ipairs(bucket) do
            if p.trust and p.hostname and p.ip then
                peers[#peers+1] = p
            end
        end
    end

    table.sort(peers, function(a, b)
        return tostring(a.ip) < tostring(b.ip)
    end)

    return peers
end

local function match(l)
    local ip, hostname, b64interface, network, b64k = string.match(l, "([^%s]+)%s+([^%s]+)%s+# inserted by WireHub, interface: ([^%s]+) network: ([^%s]+) key: ([^%s]+)")

    local interface, k
    if b64interface then
        local ok
        ok, interface = pcall(wh.fromb64, b64interface)
        if not ok then return end
    end

    if b64k then
        local ok
        ok, k = pcall(wh.fromb64, b64k)
        if not ok then return end
    end

    return interface, network, k, ip, hostname
end

local function generate_host(n, map_cb)
    -- if n is not nil, add peers from n inside newly generated host file
    -- if map_cb is not nil, called for each wirehub peer entry. If map_cb
    -- returns false, the peer will be removed

    local r = {}
    local begin_idx
    local any_entry

    for line in io.lines(HOSTS_PATH) do
        local copy_line = true

        local interface, network, k, ip, hostname = match(line)

        if ip and hostname and interface and network and k then
            if map_cb and not map_cb(ip, hostname, interface, network, k) then
                copy_line = false
            end
        end

        if copy_line then
            r[#r+1] = line .. "\n"
        end
    end

    if n then
        for _, p in ipairs(list_peers(n)) do
            r[#r+1] = string.format("%s\t%s\t# inserted by WireHub, interface: %s network: %s key: %s\n", p.ip:addr(), p.hostname, wh.tob64(n.p.k), n.name, wh.tob64(p.k))
            assert(match(r[#r]) ~= nil)
        end
    end

    return table.concat(r)
end

local function update_host(n, append)
    if not wh.EXPERIMENTAL_MODIFY_HOSTS then
        return
    end

    local append_n
    if append then
        append_n = n
    end

    local new_host = generate_host(append_n, function(interface, network)
        return interface == n.p.k and network == n.name
    end)

    local fh = io.open(HOSTS_PATH, "w")
    fh:write(new_host)
    fh:close()
end

-- Register trusted nodes of n
function M.register(n)
    return update_host(n, true)
end

-- Unregister nodes from n
function M.unregister(n)
    return update_host(n, false)
end

return M

