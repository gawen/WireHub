local M = {}
local MT = {
    __index = {},
}

function MT.__index.pack(p)
    local r = { p.k, p.addr:pack() }

    --if p.relay ~= nil then
    --    r[#r+1] = p.relay.k
    --    r[#r+1] = p.relay.addr:pack()
    --end

    return table.concat(r)
end

if DEBUG then
    function MT.__newindex(r, attr, val)
        local t = ""
        if false then
            t = debug.traceback()
            t = string.match(t, "[^\n]*\n[^\n]*\n\t.*src/([^\n]*) *\n.*")
            t = "$(reset)\t(" .. t .. ")"
        end

        if rawget(r, attr) ~= val then
            printf("$(darkgray)--$(reset) $(bold)%s$(reset).$(blue)%s$(reset) = $(blue)%s"..t,
                wh.key(r), attr, dump(val)
            )
        end

        rawset(r, attr, val)
    end
end

function MT.__tostring(p)
    local r = {}

    local s = string.format("%s@%s", wh.key(p), p.addr)

    if p.is_nated then
        s = s .. ' (NAT)'
    end

    if p.relay then
        s = s .. string.format(" (relayed)")
    end

    return s
end

return function(p)
    return setmetatable(p, MT)
end

