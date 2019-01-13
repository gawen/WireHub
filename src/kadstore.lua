-- kademilia

local peer = require('peer')

local MT = {
    __index = {},
}

-- Touch a peer with key k. If peer does not exist, creates it. Returns two
-- values, the peer table and a boolean if the peer was created.
function MT.__index.touch(t, k)
    if t.root.k == k then
        t.touched[k] = t.root
        return t.root
    end

    local bid = wh.bid(t.root.k, k)
    local b = t.buckets[bid]
    if not b then
        b = {}
        t.buckets[bid] = b
    end

    local p = b[k]
    local new_p = p == nil
    if p == nil then
        p = {
            k=k,
        }

        b[#b+1] = p
        b[k] = p
    end

    t.touched[p.k] = p

    return peer(p), new_p
end

function MT.__index.get(t, k)
    if t.root.k == k then
        return t.root
    end

    local bid = wh.bid(t.root.k, k)
    local b = t.buckets[bid]
    if not b then return end

    return b[k]
end

function MT.__index.clear_touched(t)
    t.touched = {}
end

function MT.__index.kclosest(t, k, count, filter_cb)
    local empty = {}
    if count == nil then count = t.K end
    local bid = wh.bid(t.root.k, k)

    local r = {}

    local function extend(i)
        for _, p in ipairs(t.buckets[i] or empty) do
            if (p.k and
                p.addr and
                not p.alias and (
                    not filter_cb or
                    filter_cb(p)
                )
            ) then
                r[#r+1] = {wh.xor(p.k, k), p}
            end
        end
    end

    extend(bid)

    if #r < count then
        for i = bid+1, #t.root.k*8 do extend(i) end
    end

    for i = bid-1, 1, -1 do
        if #r >= count then
            break
        end

        extend(i)
    end

    table.sort(r, function(a, b) return a[1] < b[1] end)
    return r
end

return function(root_k, kad_k)
    assert(root_k and kad_k)

    return setmetatable({
        buckets={},
        K=kad_k,
        touched={},
        root={k=root_k},
    }, MT)
end

