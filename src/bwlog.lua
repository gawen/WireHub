local queue = require('queue')

local MT = {
    __index = {},
}

function MT.__index.collect(bw)
    for i, v in queue.iter(bw) do
        local ts = v[1]

        if now - ts <= bw.scale then
            break
        end

        assert(i == bw.heap)
        queue.remove(bw, 1)
    end

    bw.last_collect_ts = now
end

function MT.__index.add(bw, class, dir, sz)
    return queue.push(bw, { now, class, dir, sz })
end

function MT.__index.add_rx(bw, class, sz) return bw:add(class, 'rx', sz) end
function MT.__index.add_tx(bw, class, sz) return bw:add(class, 'tx', sz) end

MT.__index.length = queue.length

function MT.__index.avg(bw)
    local acc = {}
    for i, v in queue.iter(bw) do
        local ts, class, dir, sz = table.unpack(v)

        if now - ts <= bw.scale then
            acc[class] = acc[class] or { rx=0, tx=0 }
            acc[class][dir] = acc[class][dir] + sz
        else
            assert(i == bw.heap)
            queue.remove(bw, 1)
        end
    end

    bw.last_collect_ts = now

    for k, v in ipairs(acc) do
        v.rx = v.rx / bw.scale
        v.tx = v.tx / bw.scale
    end

    return acc
end

return function(bw)
    assert(bw and bw.scale)
    bw.last_collect_ts = 0
    return setmetatable(bw, MT)
end

