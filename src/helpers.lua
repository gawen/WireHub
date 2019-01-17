-- random seed
math.randomseed(string.unpack("I", wh.randombytes(4)))

function execf(...)
    return os.execute(string.format(...))
end

function tointeger(s)
    local n = tonumber(s)
    if n == nil then return nil end
    if math.floor(n) ~= n then return nil end
    return n
end


function string.join(val, tbl)
    local r = {}
    for i, v in pairs(tbl) do
        if i > 1 then r[#r+1] = val end
        r[#r+1] = tostring(v)
    end
    return table.concat(r)
end

function dump(x, level)
    level = level or 0

    if type(x) == 'table' then
        local function format_k(k)
            if type(k) == 'number' then
                return string.format('[%d]', k)
            elseif type(k) == 'string' then
                local r = dump(k)
                if string.sub(r, 1, 1) == '"' and string.sub(r, -1, -1) == '"' then
                    return string.sub(r, 2, -2)
                else
                    return string.format('[%s]', r)
                end
            else
                -- XXX check for invalid Lua characters for key
                return tostring(k)
            end
        end

        local r = {'{'}

        level = level + 1

        local keys = {}
        for k in pairs(x) do keys[#keys+1] = k end
        table.sort(keys, function(a,b)
            local a_type = type(a)
            local b_type = type(b)

            if a_type ~= b_type then
                a = a_type
                b = b_type
            end

            return a < b
        end)
        for i, k in ipairs(keys) do
            local v = x[k]

            if i > 1 then r[#r+1] = ',' end
            r[#r+1] = '\n'

            r[#r+1] = string.rep('  ', level) .. string.format('%s = %s', format_k(k), dump(v, level))
        end
        level = level - 1

        r[#r+1] = '\n' .. string.rep('  ', level) .. '}'

        return table.concat(r)
    elseif type(x) == 'string' then
        if #x == 32 then
            return string.format('base64(%s)', wh.tob64(x))
        end

        return string.format('%q', x)
    else
        return tostring(x)
    end
end

local function is_table_list(t)
    for k, v in pairs(t) do
        if type(k) ~= 'number' or 1 > k or k > #t then
            return false
        end
    end

    return true
end

function dump_json(x, level)
    level = level or 0

    if type(x) == 'table' and is_table_list(x) then
        local r = {'['}

        level = level + 1
        for i, v in ipairs(x) do
            if i > 1 then r[#r+1] = ',' end
            r[#r+1] = '\n'
            r[#r+1] = string.rep('  ', level) .. dump_json(v, level)
        end
        level = level - 1

        r[#r+1] = '\n' .. string.rep('  ', level) .. ']'
        return table.concat(r)

    elseif type(x) == 'table' then      -- map
        local function format_k(k)
            if type(k) == 'number' then
                k = tostring(k)
            end

            if type(k) == 'string' then
                return dump_json(k)
            else
                -- XXX check for invalid Lua characters for key
                return tostring(k)
            end
        end

        local r = {'{'}

        level = level + 1

        local keys = {}
        for k in pairs(x) do keys[#keys+1] = k end
        table.sort(keys, function(a,b)
            local a_type = type(a)
            local b_type = type(b)

            if a_type ~= b_type then
                a = a_type
                b = b_type
            end

            return a < b
        end)
        for i, k in ipairs(keys) do
            local v = x[k]

            if i > 1 then r[#r+1] = ',' end
            r[#r+1] = '\n'

            r[#r+1] = string.rep('  ', level) .. string.format('%s: %s', format_k(k), dump_json(v, level))
        end
        level = level - 1

        r[#r+1] = '\n' .. string.rep('  ', level) .. '}'

        return table.concat(r)
    elseif type(x) == 'string' then
        if #x == 32 then
            x = wh.tob64(x)
        end

        local s = {}
        for i = 1, #x do
            local c = string.sub(x, i, i)
            local b = string.byte(c)

            if (
                (32 <= b and b <= 33) or
                (35 <= b and b <= 91) or
                (93 <= b and b <= 126)
            ) then
                s[#s+1] = c
            else
                s[#s+1] = string.format('\\u%.4x', b)
            end
        end
        s = table.concat(s)

        return string.format('%q', s)
    elseif type(x) == 'userdata' then
        return dump_json(tostring(x))
    else
        return tostring(x)
    end
end
function parsearg(idx, fields)
    local state = {}
    while true do
        if arg[idx] == nil then
            break
        end

        local field = arg[idx]
        local field_func = fields[field]

        local value
        if field_func == true then  -- XXX replace true by 'boolean'
            value = true

        elseif not field_func or not arg[idx+1] then
            printf('Invalid argument: %s', field)
            return
        else
            idx = idx + 1
            local errmsg
            value, errmsg = field_func(arg[idx])

            if value == nil then
                printf("Invalid argument: %s. %s", field, errmsg or '')
                return
            end
        end

        state[field] = value
        idx = idx + 1
    end

    return state
end

function parsebool(s)
    if not s then
        return
    end

    s = s:lower()
    if s == 'yes' or s == 'true' or s == '1' then
        return true
    elseif s == 'no' or s == 'false' or s == '0' then
        return false
    end
end

local notif = ""
do
    local C = {
        reset=0,
        bold=1,
        black='0;30',
        red='0;31',
        green='0;32',
        orange='0;33',
        blue='0;34',
        magenta='0;35',
        cyan='0;36',
        gray='0;37',
        darkgray='1;30',
        lightred='1;31',
        lightgreen='1;32',
        yellow='1;33',
        lightblue='1;34',
        lightpurple='1;35',
        lightcyan='1;36',
        white='1;37',
    }

    function format_color(s, color_mode)
        local any_col = false
        s = string.gsub(s, "$%(%a+%)", function(c)
            c = string.sub(c, 3, -2)
            local col = C[c]
            assert(col, "unknown color")

            if color_mode == nil then
                color_mode = wh.color_mode()
            end
            if not color_mode then return '' end

            any_col = true
            return string.format("\x1b[%sm", col)
        end)
        if any_col then
            s = s .. "\x1b[0m"
        end
        return s
    end

    _G['LOG'] = false

    function printf(...)
        local fmt = string.format(...)

        if _G['LOG'] then
            _G['LOG'](format_color(fmt, false))
        end

        io.stdout:write(string.format("\r%s\r", string.rep(' ', #notif)))
        print(format_color(fmt))
        io.stdout:write(notif)
        io.stdout:flush()
    end
end

function hexdump(x)
    if #x == 0 then
        return "<emtpy>\n"
    end
    local r = {}
    for i = 1, #x do
        r[#r+1] = string.format("%.2x ", string.byte(string.sub(x, i, i)))
        if i > 1 and i % 16 == 1 then
            r[#r+1] = "\n"
        elseif i > 1 and i % 8 == 1 then
            r[#r+1] = " "
        end
    end
    return table.concat(r)
end

function status(fmt, ...)
    if true then return end
    if not wh.color_mode() then
        return
    end

    local prev_notif = notif
    if fmt == nil then
        notif = nil
    else
        notif = string.format(fmt, ...)
        notif = string.format('$(lightblue)(%s)$(reset)', notif)
        notif = format_color(notif)
    end

    io.stdout:write("\r" .. string.rep(' ', #(prev_notif or "")) .. "\r")

    if notif then
        io.stdout:write("\r" .. notif)
    end

    io.stdout:flush()
end

function cpcall(cb, ...)
    return (function(ok, ...)
        if ok then
            return ...
        else
            return
        end
    end)(xpcall(cb, function(msg) return print(debug.traceback(msg, 2)) end, ...))
end

local exits_cb = {}
function atexit(cb, ...)
    assert(cb)
    exits_cb[#exits_cb+1] = table.pack(cb, ...)
end

function _do_atexits()
    for _, x in ipairs(exits_cb) do
        cpcall(table.unpack(x))
    end
end

function min(a)
    local m = nil
    for i, v in ipairs(a) do
        if v ~= nil and (m == nil or m > v) then
            m = v
        end
    end
    return m
end

function max(a)
    local m = nil
    for i, v in ipairs(a) do
        if v ~= nil and (m == nil or m < v) then
            m = v
        end
    end
    return m
end

function randomrange(s, e)
    return math.floor(math.random()*(e-s)+s)
end

function dbg(fmt, ...)
    return printf("$(red)" .. fmt .. "$(reset)", ...)
end

function errorf(...)
    return error(string.format(...))
end

function disable_globals()
    setmetatable(_G, {
        __newindex = function(t, n, v)
            if n == '_' then
                return
            end

            if t[n] == nil then
                error(string.format("cannot set any global: %s", n))
            end

            return rawset(t, n, v)
        end,
    })
end

local MEMUNITS = { "B", "KiB", "MiB", "GiB" }
function memunit(v)
    local unit
    for _, u in ipairs(MEMUNITS) do
        if v < 800 then
            unit = u
            break
        end

        v = v / 1024
    end

    return string.format("%.1f%s", v, unit)
end

