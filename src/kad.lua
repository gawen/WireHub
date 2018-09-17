local packet = require('packet')
local time = require('time')

local M = {}

local function explain(n, p, fmt, ...)
    return n:explain("(peer %s) " .. fmt, n:key(p), ...)
end

local function update_peer(n, p, excedent)
    -- take advantage of iterating over all nodes to remove fragments,
    -- without management of any deadlines
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

    -- keeps aliases for ever
    if p.alias then
        return 'inf'
    end

    -- if relay was forgotten
    if p.relay and p.relay.addr == nil then
        p.relay = nil
    end

    -- XXX if excedent??? keep trusted peers infinitely?


    local last_seen = p.last_seen or 0
    local ping_retry = p.ping_retry or 0

    -- XXX NOTE XXX
    -- if
    --   current peer is NAT-ed and remote peer is not, OR
    --   current peer has a tunnel opened to remote peer, OR
    --   peer is excedent

    local should_ping
    local reason

    if not p.addr and not p.relay then
        should_ping = false

    elseif p.wg_connected then
        reason = 'wireguard is enabled'
        should_ping = true

    -- XXX should only ping the closest peers, not all!
    elseif n.is_nated then
        reason = 'current peer is NAT-ed'
        should_ping = true

    elseif excedent then
        reason = 'peer is excedent'
        should_ping = true
    end

    if should_ping then
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

    if not p.is_nated then
        return 'inf'
    end

    -- p is NAT-ed. Forget if it does not contact current peer after a certain
    -- amount of time
    local deadline = last_seen + wh.NAT_TIMEOUT * 2
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

        local c = 0
        for i, p in ipairs(bucket) do
            local excedent = c >= n.kad.K

            local deadline = update_peer(n, p, excedent)

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
                    to_remove[#to_remove+1] = i
                end
            elseif deadline ~= 'inf' then
                deadlines[#deadlines+1] = deadline
                c = c + 1
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

