-- Peer DHT searching logic
--
-- Requests consecutively peers to find the WAN IP address of a searched peer.
--
-- Search have 3 modes:
-- * 'lookup': when a route for the searched peer is found, stop the search. The
--             route might go through a relay. No peer-to-peer communication is
--             initialized.
--
-- * 'ping':   like 'lookup', but send a PING to the searched peer to check if
--             it is reachable/online. No peer-to-peer communication is
--             initialized.
--
-- * 'p2p':    like 'ping', but initialize a peer-to-peer communication with UDP
--             hole punching, if necessary.
--


local peer = require('peer')
local packet = require('packet')

local M = {}

local function explain(n, s, fmt, ...)
    if s.probe_cb then s:probe_cb{
        action='explain',
        what=string.format(fmt, ...),
    } end
    return n:explain("(search %s) " .. fmt, n:key(s.k), ...)
end

function M._extend(n, s, closest, src)
    s.states[src.k] = {retry=0, rep=true}

    local set = {}
    for _, c in ipairs(s.closest) do
        local p = c[2]
        set[p:pack()] = true
    end

    for _, c in ipairs(closest) do
        local dist = c[1]
        local p = c[2]

        local st = s.states[p.k]

        if (
            -- if peer has address
            p.addr and

            -- if peer already answered, skip,
            (st == nil or not st.rep) and

            -- ignore doublons
            not set[p:pack()]
        ) then
            --printf('extend $(cyan)%s', p)
            s.closest[#s.closest+1] = {dist, n:add(p)}
            set[p:pack()] = true

            if s.cb and (s.return_all or p.k == s.k) then
                cpcall(s.cb, s, p, src)
            end

            if s.probe_cb then s:probe_cb{
                action="extend",
                p=p,
                st=st,
            } end
        end
    end

    -- XXX maybe give a preference to trusted peers, or peers which are public
    -- or geographically close
    table.sort(s.closest, function(a, b) return a[1] < b[1] end)

    if s.probe_cb then s:probe_cb{
        action="closest",
        closest=s.closest,
        states=s.states,
    } end
end

function M.search(n, k, opts, cb)
    -- opts might be a string being the search mode
    -- or a table having the following fields:
    -- * mode: 'ping' (default), 'lookup', 'p2p'
    -- * timeout: search timeout. By default, wh.SEARCH_TIMEOUT
    -- * count: search result count. By default, wh.KADEMILIA_K
    -- * return_all: if true, returns all intermediary peers pointing to the
    --               destination. by default, nil.
    -- * probe_cb: function called to follow search steps. For debug purposes.
    --             by default, nil.
    assert(k)

    if type(opts) == 'string' then
        opts = {mode=opts}
    end

    if opts.mode == nil then opts.mode = 'ping' end
    if opts.mode ~= 'lookup' and
       opts.mode ~= 'p2p' and
       opts.mode ~= 'ping' then
        error("arg #3 must be 'p2p', 'lookup' or 'ping'")
    end
    if opts.count == nil then opts.count = wh.SEARCH_COUNT end
    if timeout == nil then opts.timeout = wh.SEARCH_TIMEOUT end

    local s = setmetatable({
        cb=cb,
        closest={},
        count=opts.count,
        deadline=now+opts.timeout,
        k=k,
        may_offline=true,
        mode=opts.mode,
        probe_cb=opts.probe_cb,
        return_all=opts.return_all,
        running=true,
        states={},
        uid1=wh.randombytes(8),
        uid2=wh.randombytes(8),
    }, {
        __index = S
    })

    n.searches[s] = true

    if s.probe_cb then s:probe_cb{
        action="start",
        k=s.k,
        mode=s.mode,
    } end

    -- bootstrap
    n:_extend(s, n.kad:kclosest(s.k, wh.KADEMILIA_K), n.kad.root)

    return s
end

function M.stop_search(n, s)
    if s.running then
        s.running = false

        --printf('stop search $(cyan)%s', n:key(s))

        if s.probe_cb then s:probe_cb{
            action='stop',
        } end

        n.searches[s] = nil

        if s.cb then
            cpcall(s.cb, s, nil)
        end
    end
end

function M.connect(n, dst_k, opts, cb)
    local count = 1
    local p_relay
    local cbed = false

    opts = opts or {}
    opts.mode = 'p2p'
    opts.count = 1

    return n:search(dst_k, opts, function(s, p, via)
        if cbed then return end

        if p and not p.relay and p.addr then
            cbed = true
            return cb(s, p, true, p.addr)
        elseif p and p.relay then
            p_relay = p
        elseif n.lo and p_relay then
            local tunnel = n.lo:touch_tunnel(p_relay)
            cbed = true
            return cb(s, p_relay, false, tunnel.lo_addr)
        else
            cbed = true
            return cb(s)
        end
    end)
end

function M.update(n, s, deadlines)
    local to_remove = {}

    if s.deadline ~= nil then
        -- if search timeout, remove search
        if now >= s.deadline then
            explain(n, s, "stop")
            n:stop_search(s)
            return
        end

        deadlines[#deadlines+1] = s.deadline
    end

    for i, c in ipairs(s.closest) do
        local p = c[2]

        local deadline
        local st = s.states[p.k] or {retry=0, rep=false}

        if p.k == s.k then
            if s.mode == 'ping' then
                deadline = (st.req_ts or 0)+st.retry+1

                if now >= deadline then
                    explain(n, s, "check if peer %s is alive", n:key(p))

                    n:_sendto{dst=p, m=packet.ping('normal', s.uid1)}
                    st.retry = st.retry + 1
                    st.req_ts = now
                    st.last_seen = now
                    deadline = st.req_ts+st.retry+1
                end
            elseif s.mode == 'p2p' then
                if st.is_punched then
                    deadline = st.req_ts + st.retry + 1
                elseif st.is_online then
                    deadline = st.req_ts + wh.MAX_PUNCH_TIMEOUT
                else
                    deadline = (st.req_ts or 0) + st.retry + 1
                end

                if now >= deadline and st.is_punched then
                    if st.retry < wh.PING_RETRY then
                        explain(n, s, "is %s alive?", n:key(p))

                        assert(not p.relay, dump{p=p, st=st})
                        n:_sendto{dst=p, m=packet.ping('normal', s.uid2)}
                        st.req_ts = now
                        st.retry = st.retry + 1

                        deadline = st.req_ts + st.retry + 1
                    end

                elseif now >= deadline then
                    if st.retry > wh.MAX_PUNCH_RETRY then
                        explain(n, s, "maximum tentative of punch with %s. abort!", n:key(p))
                        n:stop_search(s)
                        return
                    end

                    explain(n, s, "try to punch to %s", n:key(p))
                    local p_direct = peer{k=p.k, addr=p.addr}
                    n:_sendto{dst=p_direct,    m=packet.ping('normal', s.uid2)}
                    n:_sendto{dst=p,           m=packet.ping('normal', s.uid1)}
                    n:_sendto{dst=p,           m=packet.ping('direct', s.uid2)}

                    st.retry = st.retry + 1
                    st.req_ts = now

                     if st.is_online then
                        deadline = st.req_ts + wh.MAX_PUNCH_TIMEOUT
                    else
                        deadline = (st.req_ts or 0) + st.retry + 1
                    end
                end
            end

        -- do not send packet to self
        elseif p.k == n.k then
            -- keep deadline to nil

        -- remove if search has too many nodes
        elseif i > s.count then
            -- keep deadline to nil

        -- ignore if node does not have any address
        elseif not p.addr then
            -- keep deadline to nil

        -- no response and not enough retry, send a find and wait retry sec
        elseif not st.rep and st.retry <= wh.PING_RETRY then
            deadline = (st.req_ts or 0)+st.retry+1

            if now >= deadline then
                n:_sendto{dst=p, m=packet.search(s.k)}
                st.retry = st.retry + 1
                st.req_ts = now
                st.rep = false
                deadline = st.req_ts+st.retry+1
            end
        end

        if s.probe_cb then s:probe_cb{
            action='update',
            p=p,
            st=st,
        } end

        -- save state
        s.states[p.k] = st
        if deadline ~= nil then
            deadlines[#deadlines+1] = deadline

        else
            to_remove[#to_remove+1] = i
        end
    end

    for i = #to_remove, 1, -1 do
        table.remove(s.closest, to_remove[i])
    end

    if s.probe_cb then s:probe_cb{
        action="closest",
        closest=s.closest,
    } end

    if #s.closest == 0 then
        n:stop_search(s)
    end
end

function M.on_pong(n, body, src)
    for s in pairs(n.searches) do
        if s.k == src.k then
            local st = s.states[src.k]

            if s.mode == 'ping' then
                if s.uid1 == body then
                    explain(n, s, "%s is alive!", n:key(src))

                    cpcall(s.cb, s, src, src)
                    n:stop_search(s)
                end

            elseif s.mode == 'p2p' then
                if s.uid1 == body then
                    explain(n, s, "%s is alive!", n:key(src))

                    st.is_online = true
                elseif s.uid2 == body and st.is_punched then
                    explain(n, s, "UDP hole punching is stable with %s!", n:key(src))

                    cpcall(s.cb, s, src, src)
                    n:stop_search(s)

                elseif not src.relay and s.uid2 == body then
                    explain(n, s, "punched to %s!", n:key(src))
                    st.is_punched = true
                    st.retry = 0
                    s.uid2 = wh.randombytes(8)
                end
            end

            break
        end
    end
end

function M.on_result(n, pks, closest, src)
    for s in pairs(n.searches) do
        if pks == s.k then
            local s_closest = {}
            for i, p in ipairs(closest) do
                s_closest[i] = {wh.xor(s.k, p.k), p}
            end

            n:_extend(s, s_closest, src)
        end
    end
end

return M

