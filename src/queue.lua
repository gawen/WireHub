-- Generic FIFO queue implementation

local M = {}

function M.push(q, e)
    q = q or {}
    q.tail = (q.tail or 0) + 1
    q[q.tail] = e
    q.heap = q.heap or q.tail
    return q
end

function M.remove(q, c)
    if not q then
        return
    end

    if not q.tail then
        assert(not q.heap)
        return
    end

    local i = q.heap
    while i <= q.tail and i-q.heap < c do
        q[i] = nil
        i = i + 1
    end
    q.heap = i

    if q.tail < q.heap then
        q.heap = nil
        q.tail = nil
        return nil
    end

    return q
end

function M.pop(q)
    if not q.heap then
        return
    end

    local v = q[q.heap]

    M.remove(q, 1)

    return v
end

function M.length(q)
    if not q or not q.heap then
        return 0
    end

    assert(q.tail)

    return q.tail - q.heap
end

local function queue_next(q, k)
    if not q or not q.heap then
        return
    end
    assert(q.tail)

    if k == nil then
        k = q.heap
    else
        k = k + 1
    end

    if k > q.tail then
        return
    end

    return k, q[k]
end

function M.iter(q)
    return queue_next, q, nil
end

return M

