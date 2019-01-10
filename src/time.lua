local M = {}

function M.every(deadlines, obj, field_ts, value)
    local last_ts = obj[field_ts]

    if now - last_ts >= value then
        obj[field_ts] = now
        deadlines[#deadlines+1] = now + value
        return true
    else
        deadlines[#deadlines+1] = last_ts + value
        return false
    end
end

function M.retry_backoff(obj, retry_field, last_field, retry_max, backoff)
    local deadline

    -- wait for deadline
    deadline = (
        (obj[last_field] or 0) +
        (obj[retry_field] or 0) * backoff
    )

    if now <= deadline then
        return false, deadline
    end

    -- deadline is reached. If retry_max is reached too, timeout
    if retry_max ~= nil and (obj[retry_field] or 0) >= retry_max then
        return false, nil
    end

    -- action has to be performed; calculate next deadline
    obj[last_field] = now
    obj[retry_field] = (obj[retry_field] or 0) + 1
    deadline = (
        obj[last_field] +
        obj[retry_field] * backoff
    )

    return true, deadline

end

local function retry_ping_backoff_deadline(p, retry_every, backoff)
    local deadline

    if p.last_seen then
        deadline = p.last_seen + retry_every
    else
        if p.first_ping_ts == nil then
            p.first_ping_ts = now
        end

        deadline = p.first_ping_ts
    end

    deadline = deadline + (p.ping_retry or 0) * backoff

    return deadline
end

function M.retry_ping_backoff(p, retry_every, retry_max, backoff)
    local deadline
    deadline = retry_ping_backoff_deadline(p, retry_every, backoff)

    if now < deadline then
        return false, deadline
    end

    -- deadline is reached. If retry_max is reached too, timeout
    if retry_max ~= nil and (p.ping_retry or 0) >= retry_max then
        return false, nil
    end

    -- action has to be performed; calculate next deadline
    if p.last_ping == nil and p.first_tx_ts == nil then p.first_tx_ts = now end
    p.last_ping = now
    p.ping_retry = (p.ping_retry or 0) + 1
    deadline = retry_ping_backoff_deadline(p, retry_every, backoff)

    return true, deadline
end

return M

