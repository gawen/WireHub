-- WireHub configuration reader/writer


function wh.fromconf(conf)
    if not conf then return end

    local r = {
        peers = {}
    }

    local lineno = 0
    local function err(reason, ...)
        return false, string.format("line %s: %s", lineno, string.format(reason, ...))
    end

    local ip_lineno = {}
    local hostname_lineno = {}

    for l in string.gmatch(conf, "[^\n]*") do
        lineno = lineno + 1

        -- remove contents
        local comment_idx = string.find(l, "#")
        if comment_idx then
            l = string.sub(l, 1, comment_idx-1)
        end

        -- extract cmd
        local ws = {}
        for w in string.gmatch(l, "([^%s]+)") do ws[#ws+1] = w end
        local cmd = ws[1]

        if cmd == 'name' then
            r.name = ws[2]
        elseif cmd == 'subnet' then
            if r.subnet then
                return err("subnetwork already set")
            end

            local e
            r.subnet, e = tosubnet(ws[2])
            if r.subnet == false then
                return err(e)
            end

        elseif cmd == 'workbit' then
            if r.workbit then
                return err("workbit already set")
            end

            r.workbit = tonumber(ws[2])
            if not r.workbit then
                return err("workbit is not a number")
            end

        elseif cmd == 'namespace' then
            if r.namespace then
                return err("namespace already set")
            end

            r.namespace = ws[2]

        elseif (cmd == 'alias' or cmd == 'boot' or cmd == 'router' or
            cmd == 'peer' or cmd == 'trust') then

            if cmd == 'alias' or cmd == 'router' or cmd == 'trust' then
                if r.subnet == nil then
                    return err("no subnet set")
                end
            end

            local p = {}
            if cmd == 'alias' then
                p.trust = true

            elseif cmd == 'boot' then
                p.bootstrap = true

            elseif cmd == 'peer' then
                -- do nothing

            elseif cmd == 'router' then
                p.trust = true
                p.is_router = true

            elseif cmd == 'trust' then
                p.trust = true
            end

            local k = nil
            for i = 2, #ws do
                local w = ws[i]
                local ok, wb = pcall(wh.fromb64, w)
                if not ok or #wb ~= 32 then
                    wb = nil
                end

                -- a base64 has to be the peer's key
                if wb then
                    if k then
                        return err("public key already set")
                    end

                    k = wb

                -- if key was set, next has to be an endpoint
                elseif k and not p.addr then
                    p.addr = wh.address(w, wh.DEFAULT_PORT)

                -- if key and endpoint was set, nothing is supposed to come
                -- next
                elseif k and p.addr then
                    return err("invalid %s", w)

                -- else it has to be the hostname or the ip
                else
                    local ok, w_as_ip = pcall(wh.address, w, nil, "numeric")
                    if not ok then w_as_ip = nil end

                    if w_as_ip then
                        if not p.trust then
                            return err("non-trusted peer cannot have a static ip")
                        end

                        if p.ip then
                            return err("private ip is already set")
                        end

                        if not w_as_ip:same_subnet(r.subnet.ip, r.subnet.cidr) then
                            return err("IP %s is not inside subnet %s/%d",
                                w_as_ip:addr(), r.subnet.ip:addr(), r.subnet.cidr)
                        end

                        local l = ip_lineno[w_as_ip:pack()]
                        if l then
                            return err("private ip was already set at line %d", l)
                        end

                        p.ip = w_as_ip
                        p.staticip = w_as_ip
                        ip_lineno[w_as_ip:pack()] = lineno
                    else
                        if p.hostname then
                            return err("bad IP or hostname is already set")
                        end

                        local l = hostname_lineno[w]
                        if l then
                            return err("hostname was already set at line %d", l)
                        end

                        p.hostname = w
                        hostname_lineno[w] = lineno
                    end
                end
            end

            if not k then
                return err("public key is not set")
            end

            p[cmd == 'alias' and 'alias' or 'k'] = k

            if p.bootstrap and not p.addr then
                return err("bootstrap node must have an endpoint set")
            end

            r.peers[#r.peers+1] = p
        end
    end

    if not r.namespace then
        r.namespace = wh.DEFAULT_NAMESPACE
    end

    if not r.workbit then
        r.workbit = wh.DEFAULT_WORKBIT
    end

    -- create index (private ip, peer)
    local p_by_ip = {}
    for _, p in ipairs(r.peers) do
        if p.ip then
            p_by_ip[p.ip:pack()] = p
        end
    end

    -- assign an IP for trusted peer
    local addr_idx = 2
    for _, p in ipairs(r.peers) do
        if p.trust then
            while not p.ip do
                assert(r.subnet)
                local addr = r.subnet.ip:subnet_id(r.subnet.cidr, addr_idx)

                if not addr then
                    return err("too many trusted nodes")
                end

                -- if not already allocated, assign
                if not p_by_ip[addr:pack()] then
                    p.ip = addr
                end

                addr_idx = addr_idx + 1
            end
        end
    end

    return r
end

function wh.toconf(conf)
    local r = {}

    local function writef(...) r[#r+1] = string.format(...) end

    if conf.name then
        writef("name %s\n", conf.name)
    end

    if conf.workbit then
        writef("workbit %d\n", conf.workbit)
    end

    if conf.namespace then
        writef("namespace %s\n", conf.namespace)
    end

    writef("subnet %s/%s\n\n", conf.subnet.ip:addr(), conf.subnet.cidr)

    -- create index (private ip, peer)
    local p_by_ip = {}
    for _, p in ipairs(conf.peers) do
        if p.staticip then
            p_by_ip[p.staticip:pack()] = p
        end
    end

    table.sort(conf.peers, function(a, b)   -- a < b
        -- have first boot
        if a.bootstrap and not b.bootstrap then
            return true
        elseif not a.bootstrap and b.bootstrap then
            return false
        end

        -- have trusted peers first
        if a.trust and not b.trust then
            return true
        elseif not a.trust and b.trust then
            return false
        end

        if a.staticip and b.staticip then
            return a.staticip < b.staticip
        elseif a.staticip and not b.staticip then
            return true
        elseif not a.staticip and b.staticip then
            return false
        end

        if a.ip and b.ip then
            return a.ip < b.ip
        elseif a.ip and not b.ip then
            return true
        elseif not a.ip and b.ip then
            return false
        end

        return false
    end)

    local addr_idx = 2
    for _, p in ipairs(conf.peers) do
        local w = {}

        local m
        if p.bootstrap then
            m = 'boot'
        elseif p.alias then
            m = 'alias'
        elseif p.is_router then
            m = 'router'
        elseif p.trust then
            m = 'trust'
        else
            m = 'peer'
        end
        w[#w+1] = m .. '\t'

        if p.hostname then
            w[#w+1] = " "
            w[#w+1] = p.hostname
        end

        if p.staticip then
            w[#w+1] = " "
            w[#w+1] = p.staticip:addr()
        end

        w[#w+1] = "\t"
        w[#w+1] = wh.tob64(p.alias or p.k)

        if p.addr then
            w[#w+1] = " "
            w[#w+1] = tostring(p.addr)
        end

        w[#w+1] = "\n"

        r[#r+1] = table.concat(w)
    end

    return table.concat(r)
end

