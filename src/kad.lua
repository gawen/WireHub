local packet = require('packet')
local time = require('time')

local M = {}

local function explain(n, p, fmt, ...)
    return n:explain("(peer %s) " .. fmt, n:key(p), ...)
end

local function update_fragment(p)
    if p.fragments then
        local to_remove = {}
        local count = #p.fragments
        for i, sess in ipairs(p.fragments) do
            if (count > wh.FRAGMENT_MAX or
                sess.deadline <= now) then

                to_remove[#to_remove+1] = i
                count = count - 1
            end
        end

        for i = #to_remove, 1, -1 do
            local sess_i = to_remove[i]
            local sess = p.fragments[sess_i]
            printf("$(red)drop fragment session %s$(reset)", wh.tob64(sess.id))
            p.fragments[sess.id] = nil
            table.remove(p.fragments, sess_i)
        end
    end
end

local function update_peer(n, p, sess)
    -- keeps aliases for ever
    if p.alias then
        return 'inf'
    end

    local test_alive = false
    local reason

    -- if a WireGuard tunnel is enabled with this peer, make sure the peer is
    -- always alive. If the option 'persistent-keepalive' is enabled, WireGuard
    -- sends keep-alive packets which is taken into account by WireHub via the
    -- wg's sync.
    if p.wg_connected and p.addr then
        reason = 'wireguard is enabled'
        test_alive = true

    elseif sess.p_state == 'direct' then
        -- if there are too many direct peers in the bucket, make sure the stored
        -- ones are alive
        if sess.c_direct > wh.KADEMILIA_K then
            -- XXX wh.ALIVE_INTERVAL may depend on the peer's uptime (see
            -- fig. 1 of the Kademilia paper)
            local deadline = (p.last_seen or 0) + wh.ALIVE_INTERVAL

            -- if is peer considered as alive, do not ping, and ...
            if now < deadline then
                -- ... remove if peer is excedent and all previous peers were
                -- checked as alive
                if sess.i_direct > sess.c_direct and sess.all_direct_tested_alive then
                    deadline = nil
                end

                return deadline

            -- else we do not if peer is alive
            -- if peer is in the Kth first, ping
            elseif sess.i_direct <= wh.KADEMILIA_K then
                reason = 'too many directs in bucket. test if peers is alive'
                test_alive = true
                sess.all_directed_tested_alive = false

            -- else, it must be a peer excedent peers.
            -- if all previous direct peers are online, forget
            elseif sess.all_directed_tested_alive then
                return nil

            -- else previous peers are being tested, therefore keep in the
            -- meantime
            else
                return 'inf'
            end

        -- XXX should only ping the closest direct peers, not all!
        -- XXX remove this by a session which searches for the closest direct peers
        elseif n.is_nated then
            reason = 'current peer is NAT-ed'
            test_alive = true

        -- check every now and then direct peers are still online
        else
            local deadline = (p.last_seen or 0) + wh.KEEPALIVE_DIRECT_TIMEOUT

            if now < deadline then
                return deadline
            end

            reason = 'keep-alive'
            test_alive = true
        end
    end

    -- test if peer is alive
    if test_alive then
        local ping_retry
        if not p.bootstrap then
            ping_retry = wh.PING_RETRY
        end

        local do_ping, deadline = time.retry_ping_backoff(
            p,
            wh.NAT_TIMEOUT - n.jitter_rand,
            ping_retry,
            wh.PING_BACKOFF
        )

        if do_ping then
            explain(n, p, "alive? (%s)", reason)
            n:_sendto{dst=p, m=packet.ping()}
        end

        return deadline
    end

    -- if address was forgotten
    if p.addr == nil then
        if p.trust then
            return 'inf'
        else
            return nil
        end
    end

    if sess.p_state == 'direct' then
        return 'inf'
    end

    if p:owned() then
        return 'inf'
    end

    assert(sess.p_state == 'nat' or sess.p_state == 'relay')

    -- p is NAT-ed. Forget if it does not contact current peer after a certain
    -- amount of time
    local deadline = (p.last_seen or 0) + wh.NAT_TIMEOUT * 2
    if deadline <= now then
        return nil
    end

    return deadline
end

function M.update(n, deadlines)
    -- maintain the Kademilia tree

    for bid, bucket in pairs(n.kad.buckets) do
        table.sort(bucket, function(a, b) return (a.first_seen or 0) < (b.first_seen or 0) end)

        local to_remove = {}

        local sess = {
            c_direct = 0,
            c_nat = 0,
            i_direct = 0,
            i_nat = 0,
            all_direct_tested_alive = true,
        }
        for i, p in ipairs(bucket) do
            -- take advantage of iterating over all nodes to remove fragments,
            -- without management of any deadlines
            update_fragment(p)

            -- if relay was forgotten
            if p.relay and p.relay.addr == nil then
                p.relay = nil
            end

            local p_state = p:state()
            if p_state == 'direct' then
                sess.c_direct = sess.c_direct + 1
            elseif p_state == 'nat' or p_state == 'relay' then
                sess.c_nat = sess.c_nat + 1
            end
        end

        for i, p in ipairs(bucket) do
            sess.p_state = p:state()
            if sess.p_state == 'direct' then
                sess.i_direct = sess.i_direct + 1
            elseif sess.p_state == 'nat' or sess.p_state == 'relay' then
                sess.i_nat = sess.i_nat + 1
            end

            local deadline = update_peer(n, p, sess)

            if deadline == nil then
                p.addr = nil
                p.addr_echo = nil
                p.is_nated = nil
                p.relay = nil

                if p.trust then
                    explain(n, p, "forget!")
                    n.kad.touched[p.k] = p
                else
                    n.kad.touched[p.k] = nil

                    if not p:owned() then
                        to_remove[#to_remove+1] = i
                    --else
                    --    dbg("notice: do not remove peer %s", wh.key(p.k))
                    end

                    if sess.p_state == 'direct' then
                        sess.c_direct = sess.c_direct - 1
                        sess.i_direct = sess.i_direct - 1
                    elseif sess.p_state == 'nat' or sess.p_state == 'relay' then
                        sess.c_nat = sess.c_nat - 1
                        sess.i_nat = sess.i_nat - 1
                    end
                end
            elseif deadline ~= 'inf' then
                deadlines[#deadlines+1] = deadline
            end
        end

        for i = #to_remove, 1, -1 do
            local p = bucket[to_remove[i]]
            explain(n, p, "remove!")
            table.remove(bucket, to_remove[i])
            bucket[p.k] = nil
        end
    end
end

function M.on_pong(n, src)
    if (src.ping_retry or 0) > 0 then
        explain(n, src, "alive!")
    end

    src.ping_retry = 0
end

return M

