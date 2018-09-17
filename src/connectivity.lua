local M = {}

local function _work_upnp(n)
    local u = {
        enabled=false,
        peers={},
    }

    local d, url
    d, u.iaddr, url = wh.upnp.discover_igd(1)

    if d then
        printf('UPnP device found: %s', url)
        local ok, val = wh.upnp.external_ip(d)

        if ok then
            u.external_ip = val
        else
            u.external_ip = nil
        end

        local function _add(port)
            local ok, err = wh.upnp.add_redirect(d, {
                desc = string.format('WireHub %s', wh.tob64(n.k)),
                eport=port,
                iaddr=u.iaddr,
                iport=port,
                lease=wh.UPNP_REFRESH_EVERY,
                protocol='udp',
            })

            if ok then
                printf('upsert UPnP redirection %s:%d -> %s:%d',
                    u.external_ip or '???', n.port, u.iaddr, n.port
                )
            else
                printf('UPnP error: %s. ignore', err)
            end

            return ok
        end

        if _add(n.port) and _add(n.port_echo) then
            u.enabled = true
        end

        for _, r in ipairs(wh.upnp.list_redirects(d)) do
            local k = string.match(r.desc, "WireHub ([^ ]+)")

            if k then
                local ok
                ok, k = pcall(wh.fromb64, k)
                if not ok then k = nil end
            end

            if k and #k == 32 and n.k ~= k then
                -- check version if necessary
                u.peers[k] = {r.iaddr, r.iport}
            end
        end
    end

    return u
end

local function update_upnp(n, deadlines)
    assert(n.upnp)

    if n.mode ~= 'unknown' then
        return
    end

    local u = n.upnp

    local deadline = u.last_check + wh.UPNP_REFRESH_EVERY - 30

    if deadline <= now and not u.checking then
        u.checking = true

        n:explain("checking UPnP...")
        u.worker:pcall(
            function(ok, ...)
                u.checking = false

                if not ok then
                    error(...)
                end
                local nu = ...

                local peers = nu.peers
                nu.peers = nil

                for k, v in pairs(nu) do
                    u[k] = v
                end

                for k, addr in pairs(peers) do
                    local addr = wh.address(addr[1], addr[2])
                    printf("found UPnP device $(yellow)%s$(reset) (%s)", wh.tob64(k), addr)

                    local upnp_p = n.kad:touch(k)
                    upnp_p.addr = addr
                end

                u.last_check = now
                n.last_connectivity_check = nil
            end,
            _work_upnp,
            {
                k=n.k,
                port=n.port,
                port_echo=n.port_echo,
            }
        )

    elseif u.checking then
        deadline = nil
    else
        deadline = u.last_check + wh.UPNP_REFRESH_EVERY - 30
    end

    deadlines[#deadlines+1] = deadline
end

function M.update(n, deadlines)
    if n.upnp then
        update_upnp(n, deadlines)

        if n.upnp.checking then
            return
        end
    end

    if n.checking_connectivity then
        return
    end

    local deadline = (n.last_connectivity_check or 0) + wh.CONNECTIVITY_CHECK_EVERY
    if now > deadline then
        if n.mode == 'unknown' then
            n:explain("checking connectivity...")
            n.checking_connectivity = true
            n:detect_nat(nil, function(mode)
                n.checking_connectivity = false

                n:explain("NAT is $(magenta)%s", mode)

                n.is_nated = mode ~= 'direct'

                n:explain("find self")
                n:search(n.k, 'lookup')     -- center
                n.last_connectivity_check = now
            end)

            deadline = nil
        else
            n:explain("find self")
            n:search(n.k, 'lookup')     -- center

            n.last_connectivity_check = now
            deadline = n.last_connectivity_check + wh.CONNECTIVITY_CHECK_EVERY
        end
    end

    deadlines[#deadlines+1] = deadline
end

return M

