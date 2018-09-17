local function parseconf(conf)
    if not conf then return end

    local entry = {}
    local cur_section

    for l in string.gmatch(conf, "[^\n]*") do
        if string.sub(l, 1, 1) ~= '#' then
            local section = string.match(l, '%[[%a%d]+%]')

            if section then
                cur_section = string.sub(section, 2, -2)
                cur_section = string.lower(cur_section)
                entry[#entry+1] = {_name=cur_section}

            else
                local k, v = string.match(l, "(%a+)%s+=%s+(%g+)")

                if k and v then
                    if not cur_section then
                        return
                    end

                    k = string.lower(k)
                    entry[#entry][k] = v
                end
            end
        end
    end

    return entry
end

function wh.fromconf(conf)
    if not conf then return end

    local entry = parseconf(conf)

    local r = {
        name=nil,       -- explicit
        workbit=nil,    -- explicit
        peers={},
    }
    local has_section_network = false
    for _, section in ipairs(entry) do
        if section._name == 'interface' then
            r['private-key'] = section.privatekey

        elseif section._name == 'network' then
            if has_section_network then return end
            has_section_network = true

            r.name = section.name
            r.namespace = section.namespace
            r.subnet = section.subnetwork

            if section.workbits then
                r.workbit = tonumber(section.workbits)
                if not r.workbit then return end
            end

        elseif section._name == 'peer' then
            local p = {}

            if not section.publickey and not section.name then
                return
            end

            if section.publickey then
                local ok, k = pcall(wh.fromb64, section.publickey)
                if not ok then return end
                p.k = k
            end

            if section.endpoint then
                p.addr = wh.address(section.endpoint, wh.DEFAULT_PORT)
            end

            if section.alias then
                local ok, k = pcall(wh.fromb64, section.alias)
                if not ok then return end
                p.alias = k
            end

            p.hostname = section.name
            p.is_router = section.router == "yes"
            p.is_gateway = section.gateway == "yes"
            p.trust = section.trust == "yes"
            p.ip = section.ip and wh.address(section.ip)
            p.bootstrap = section.bootstrap == "yes"

            if section['allowedips'] then
                local r = {}
                for subnet in string.gmatch(section['allowedips'], "([^,]+)") do
                    if not subnet then
                        return nil
                    end
                    r[#r+1] = subnet
                end

                p['allowed-ips'] = r
            end

            r.peers[#r.peers+1] = p
        end
    end

    return r
end

function wh.toconf(conf)
    local r = {}

    if conf.namespace or conf.workbit then
        if conf['private-key'] then
            r[#r+1] = "[Interface]\n"
            r[#r+1] = string.format("PrivateKey = %s\n", conf['private-key'])

            r[#r+1] = '\n'
        end

        r[#r+1] = "[Network]\n"

        if conf.name then
            r[#r+1] = string.format("Name = %s\n", conf.name)
        end

        if conf.namespace then
            r[#r+1] = string.format("Namespace = %s\n", conf.namespace)
        end

        if conf.workbit then
            r[#r+1] = string.format("Workbits = %d\n", conf.workbit)
        end

        if conf.subnet then
            r[#r+1] = string.format("SubNetwork = %s\n", conf.subnet)
        end

        for _, p in ipairs(conf.peers) do
            r[#r+1] = "\n[Peer]\n"
            if p.trust then
                r[#r+1] = "Trust = yes\n"
            else
                r[#r+1] = "# Trust = no\n"
            end

            if p.bootstrap then
                r[#r+1] = "Bootstrap = yes\n"
            end

            if p.hostname then
                r[#r+1] = string.format("Name = %s\n", p.hostname)
            end

            if p.alias then
                r[#r+1] = string.format("Alias = %s\n", wh.tob64(p.alias))
            end

            if p.is_router then
                r[#r+1] = "Router = yes\n"
            end

            if p.is_gateway then
                r[#r+1] = "Gateway = yes\n"
            end

            if p.ip then
                r[#r+1] = string.format("IP = %s\n", p.ip:addr())
            end

            if p.k then
                r[#r+1] = string.format("PublicKey = %s\n", wh.tob64(p.k))
            end

            if p.addr then
                r[#r+1] = string.format("Endpoint = %s\n", p.addr)
            end

            if p['allowed-ips'] then
                r[#r+1] = string.format("AllowedIPs = ")
                for i, v in ipairs(p['allowed-ips']) do
                    if i > 1 then r[#r+1] = ',' end
                    r[#r+1] = v
                end
                r[#r+1] = '\n'
            end
        end
    end

    return table.concat(r)
end

