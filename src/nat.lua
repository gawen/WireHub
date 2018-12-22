-- NAT discovery mechanism
--
-- Like STUN, but way ligther and less complete

local time = require('time')
local packet = require('packet')
local peer = require('peer')

local M = {}

local function explain(n, d, fmt, ...)
    return n:explain("(nat %s) " .. fmt, n:key(d.k), ...)
end

function M.update(n, d, deadlines)
    local to_remove = {}

    local do_ping, deadline

    -- check if offline. if node answers, peek its echo node
    if d.may_offline then
        do_ping, deadline = time.retry_backoff(d, 'retry', 'req_ts', wh.PING_RETRY, wh.PING_BACKOFF)

        if do_ping then
            explain(n, d, "offline? (retry: %d)", d.retry)
            n:_sendto{dst=d.p, m=packet.ping(nil, d.uid)}
        end

        if deadline == nil then
            return d.cb('offline')
        end
    end

    -- maybe public? ping node and ask to answer as an echo. if it is not
    -- received after several retry, consider the node as not public.
    if not d.may_offline and d.may_direct then
        assert(d.p_echo, 'a pong with the echo address should have been received')

        do_ping, deadline = time.retry_backoff(d, 'retry', 'req_ts', wh.PING_RETRY, wh.PING_BACKOFF)

        if do_ping then
            explain(n, d, "direct? (retry: %d)", d.retry)
            n:_sendto{dst=d.p, m=packet.ping('swapsrc', d.uid)}
        end

        if deadline == nil then
            explain(n, d, "not direct!")
            d.may_direct = false
            d.req_ts = 0
            d.retry = 0
            d.uid = wh.randombytes(8)
        end
    end

    if not d.may_offline and not d.may_direct and d.may_cone then
        do_ping, deadline = time.retry_backoff(d, 'retry', 'req_ts', wh.PING_RETRY, wh.PING_BACKOFF)

        if do_ping then
            -- UDP hole punch
            explain(n, d, "cone? (retry: %d)", d.retry)
            n:_sendto{dst=d.p_echo, m=packet.ping('normal', d.uid_echo)}
            n:_sendto{dst=d.p, m=packet.ping('swapsrc', d.uid)}
        end

        if deadline == nil then
            explain(n, d, "not cone!")
            d.may_cone = false
            d.req_ts = 0
            d.retry = 0
            d.uid=wh.randombytes(8)
        end
    end

    if not d.may_offline and not d.may_direct and not d.may_cone then
        return d.cb('blocked')
    end

    assert(deadline ~= nil)
    deadlines[#deadlines+1] = deadline
end

function M.on_pong(n, body, src)
    for d in pairs(n.nat_detectors) do
        if d.uid == body then
            if d.may_offline then
                assert(src.addr_echo)
                d.p_echo = peer{k=src.k, addr=src.addr_echo}
                d.may_offline = false
                d.req_ts = 0
                d.retry = 0
                d.uid=wh.randombytes(8)
                explain(n, d, "online!")
            elseif d.may_direct then
                d.cb("direct")
            elseif d.may_cone then
                d.cb("cone")
            end
        end
    end

end

return M

