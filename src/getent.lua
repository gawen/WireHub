-- Resolve entitty name to key

local function find_shorter(n, k, cb)
    local test = function(p)
        return string.find(wh.tob64(p.k), k) == 1
    end

    local match

    if test(n.kad.root) then
        match = n.kad.root
    end

    for _, bucket in ipairs(n.kad.buckets) do
        for _, p in ipairs(bucket) do
            if test(p) then
                if match then
                    -- there's an possible ambiguity. fails
                    return cb(nil)
                else
                    match = p
                end
            end
        end
    end

    if match then
        return cb(match.k)
    else
        return cb(nil)
    end
end

local function find_b64_wh(n, k, cb)
    local ok, k = pcall(wh.fromb64, k, 'wh')
    if ok then
        if #k ~= 32 then k = nil end
    else
        k = nil
    end
    return cb(k)
end

local function find_b64_wg(n, k, cb)
    local ok, k = pcall(wh.fromb64, k, 'wg')
    if ok then
        if #k ~= 32 then k = nil end
    else
        k = nil
    end
    return cb(k)
end

local function find_local_hostname(n, h, cb)
    if n.kad.root.hostname == h then
        return cb(n.kad.root.k)
    end

    for _, bucket in ipairs(n.kad.buckets) do
        for _, p in ipairs(bucket) do
            if not p.alias and p.hostname == h and p.k then
                return cb(p.k)
            end
        end
    end

    return cb()
end

local function find_prefix(n, k, cb)
    if #k >= 43 then
        return cb()
    end

    local k2 = k .. string.rep("A", 43-#k)

    return find_b64_wh(n, k2, cb)
end

return function(n, hostname, result_cb, prefix)
    if hostname == nil then
        return nil
    end

    local cbs = {
        find_shorter,
        find_b64_wh,
        find_b64_wg,
        find_local_hostname,
    }

    if prefix then
        cbs[#cbs+1] = find_prefix
    end

    if n.ns then
        for _, ns in ipairs(n.ns) do
            cbs[#cbs+1] = ns
        end
    end

    local i = nil
    local cont_cb

    function cont_cb()
        local cb
        i, cb = next(cbs, i)

        if i and cb then
            return cb(n, hostname, function(k)
                if k then
                    return result_cb(k)
                else
                    return cont_cb()
                end
            end)
        else
            return result_cb(nil)
        end
    end

    return cont_cb()
end

