local MT = {__index = {}}
local I = MT.__index

local function close(ipc, sock)
    local state = ipc.states[sock]
    ipc.states[sock] = nil

    if state == nil then
        return
    end

    if state.close_cb then
        cpcall(state.close_cb)
    end

    wh.close(sock)
end

function I.close(ipc)
    for sock in pairs(ipc.states) do
        close(ipc, sock)
    end
    ipc.states = {}

    if ipc.listen_sock then
        wh.close(ipc.listen_sock)
        ipc.listen_sock = nil
    end

    if ipc.close_cb then
        ipc.close_cb()
        ipc.close_cb = nil
    end
end

local function on_sock_readable(ipc, sock, cmd)
    local state = ipc.states[sock]

    if not state then
        return
    end

    if not cmd or #cmd == 0 then
        return close(ipc, sock)
    end

    if state.wait_cmd and cmd and #cmd > 0 then
        state.wait_cmd = false

        -- remove trailing \n
        while string.sub(cmd, -1) == '\n' do
            cmd = string.sub(cmd, 1, -2)
        end

        local function send(...)
            if not ipc.states[sock] then
                return
            end

            local s = string.format(...)
            if wh.send(sock, s) ~= #s then
                error("send truncated")
            end
        end

        local function _close()
            close(ipc, sock)
        end

        local done
        for pattern, cb in pairs(ipc.h) do
            done = (function(...)
                if ... == nil then
                    return false
                end

                state.close_cb = cpcall(cb, send, _close, ...)
                return true
            end)(string.match(cmd, pattern))

            if done then
                break
            end
        end

        if not done then
            send('?\n')
            _close()
        end
    end

end

function I.on_readable(ipc, r)
    if ipc.listen_sock and r[ipc.listen_sock] then
        r[ipc.listen_sock] = nil

        local new_sock = wh.ipc_accept(ipc.listen_sock)
        ipc.states[new_sock] = {wait_cmd=true}
    end

    for sock in pairs(ipc.states) do
        if r[sock] then
            local cmd = wh.recv(sock, 65535)
            on_sock_readable(ipc, sock, cmd)
        end
    end
end

function I.update(ipc, socks)
    if ipc.listen_sock then
        socks[#socks+1] = ipc.listen_sock
    end

    for sock, state in pairs(ipc.states) do
        socks[#socks+1] = sock
    end

    return nil
end

local M = {}

function M.bind(interface_name, h)
    assert(interface_name and h)
    local listen_sock, close_cb = wh.ipc_bind(interface_name, false)

    return setmetatable({
        close_cb=close_cb,
        states={},
        listen_sock=listen_sock,
        h=h,
    }, MT)
end

function M.call(interface_name, cmd)
    assert(interface_name)
    local sock = wh.ipc_connect(interface_name)

    if not sock then
        return
    end

    if wh.send(sock, cmd .. '\n') ~= (#cmd+1) then
        error("send truncated")
    end

    return sock
end

return M

