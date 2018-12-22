-- IPC command handlers
-- See ipc.lua

return function(n)
    local H = {}

    function H.down(send, close)
        n:stop()
        send('OK\n')
        return close()
    end

    H['getent ([^%s]+)'] = function(send, close, k)
        return n:getent(k, function(k)
            if k then
                local r = {}
                r[#r+1] = wh.tob64(k)

                local p = n.kad:get(k)
                if p and p.ip then
                    r[#r+1] = ' ' .. tostring(p.ip)
                else
                    r[#r+1] = ' nil'
                end
                r[#r+1] = '\n'
                send(table.concat(r))
            end

            return close()
        end)
    end

    H['dump ([^%s]+)'] = function(send, close, k)
        return n:getent(k, function(k)
            if k then
                local p = n.kad:get(k)

                if p then
                    send(dump(p))
                end
            end

            return close()
        end)
    end

    local function _resolve(send, close, cmd, k)
        local args
        if cmd == 'gethostbyname' then
            args = {name = k}
        else
            assert(cmd == 'gethostbyaddr')
            args = {ip = k}
        end

        return n:resolve(args, function(k, hostname, ip)
            if k then
                send(string.format("%s\t%s\t%s\n",
                    wh.tob64(k),
                    hostname or '',
                    ip or ''
                ))
            end

            return close()
        end)
    end

    H['(gethostbyname) ([^%s]+)'] = _resolve
    H['(gethostbyaddr) ([^%s]+)'] = _resolve

    function H.info(send, close)
        send('WireHub %s\n', wh.version)
        send('Uptime: %.1f\n', now-start_time)
        if opts.interface then
            send('Interface: %s\n', opts.interface)
        end

        send('Key: %s\n', wh.tob64(wh.publickey(n.sk)))
        send('ListenPort: %d\n', n.port)
        return close()
    end

    function H.key(send, close)
        send('%s\n', wh.tob64(wh.publickey(n.sk)))
        return close()
    end

    H['describe ([^%s]+)'] = function(send, close, mode)
        send(n:describe(mode) .. '\n')
        return close()
    end

    function H.list(send, close)
        local append = function(p, s)
            send(tostring(s) .. '\t' .. (p.trust and 'trusted' or 'untrusted') .. '\n')
        end

        for bid, bucket in pairs(n.kad.buckets) do
            for _, p in ipairs(bucket) do
                append(p, wh.tob64(p.k))

                if p.hostname then
                    append(p, p.hostname)
                end
            end
        end

        return close()
    end

    function H.dumpkad(send, close)
        for bid, bucket in pairs(n.kad.buckets) do
            for i, p in ipairs(bucket) do

                local d = {}
                for k, v in pairs(p) do d[k] = v end
                d.bid = bid

                send("%s", dump(d) .. '\n')
            end
        end
        return close()
    end

    local function _nat(send, close, k)
        if k == 4 then k = nil end

        local function detect(k)
            return n:detect_nat(k, function(mode)
                send('%s\n', mode)
                close()
            end)
        end

        if k then
            return n:getent(k, function(k)
                if not k then
                    send('invalid key\n')
                    return close()
                end

                return detect(k)
            end)
        else
            return detect()
        end
    end

    H['nat()'] = _nat
    H['nat ([^%d]+)'] = _nat

    local function _search(send, close, cmd, k)
        local s

        n:getent(k, function(k)
            if not k then
                send('invalid key\n')
                return close()
            end

            s = n:search(k, cmd, nil, nil, function(s, p, via)
                if p then
                    local mode
                    if p.relay then
                        mode = wh.tob64(p.relay.k)
                    elseif p.is_nated then
                        mode = '(nat)'
                    else
                        mode = '(direct)'
                    end

                    send('%s %s %s %s\n',
                        wh.tob64(k),
                        mode,
                        p.addr,
                        wh.tob64(via.k)
                    )
                else
                    close()
                end
            end)
        end)

        return function()
            if s then
                n:stop_search(s)
            end

            -- XXX getent stop
        end
    end

    H['(p2p) ([^%s]+)'] = _search
    H['(lookup) ([^%s]+)'] = _search
    H['(ping) ([^%s]+)'] = _search

    H['connect ([^%s]+)'] = function(send, close, k)
        local s

        n:getent(k, function(k)
            if not k then
                send('invalid hostname or key\n')
                return close()
            end

            s = n:connect(k, nil, function(s, p, p2p, endpoint)
                if p then
                    if p2p then
                        send("p2p ")
                    end
                    send("%s\n", endpoint)
                end
                return close()
            end)
        end)

        return function()
            if s then
                n:stop_search(s)
            end

            -- XXX getent stop
        end
    end

    H['forget ([^%s]+)'] = function(send, close, k)
        return n:getent(k, function(k)
            if not k then
                send('invalid hostname or key\n')
                return close()
            end

            n:forget(k)
            return close()
        end)
    end

    H['authenticate ([^%s]+) (.+)'] = function(send, close, k, path)
        local alias_sk = cpcall(wh.readsk, path)
        if not alias_sk then
            send('!\n')
            return close()
        end

        local a
        n:getent(k, function(k)
            if not k then
                send('invalid key or unknown hostname\n')
                return close()
            end

            a = n:authenticate(k, alias_sk, function(a, success, errmsg)
                if success then
                    send('authenticated!\n')
                else
                    send(string.format('failed: %s\n', errmsg))
                end

                return close()
            end)
        end)

        return function()
            if a then
                n:stop_authenticate(a)
            end
        end
    end

    H.bw = function(send, close)
        if n.bw then
            for k, avg in pairs(n.bw:avg()) do
                send(string.format("%s\t%s\t%s\n",
                    wh.tob64(k),
                    avg.rx,
                    avg.tx
                ))
            end
        end
        return close()
    end

    return H
end

