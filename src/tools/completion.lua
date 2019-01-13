if arg[1] == 'completion' then
    function help()
        printf(
            'Usage: wh completion {get-bash}\n' ..
            '\n' ..
            'To enable auto-completion with `bash-completion`, run:\n' ..
            '    wh completion get-bash | sudo tee /usr/share/bash-completion/completions/wh\n'
        )
        return
    end

    if arg[2] == nil or arg[2] == 'help' then
        return help()
    end

    if arg[2] == "get-bash" then
        print(
            '_wh()\n' ..
            '{\n' ..
            '    local opts cur\n' ..
            '    _init_completion || return\n' ..
            '\n' ..
            '    opts=`wh _completion ${COMP_CWORD} ${COMP_WORDS[@]}`\n' ..
            '\n' ..
            '    #if [[ $cur == -* ]] ; then\n' ..
                '    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )\n' ..
                '    return 0\n' ..
            '    #fi\n' ..
            '}\n' ..
            'complete -F _wh wh\n'
        )
    else
        printf("unknown argument: %s", arg[2])
        return -1
    end

    return
end

assert(arg[1] == '_completion')

if #arg < 3 then
    return
end

local opt_count = 0
local function opt(s)
    print(s)
    opt_count = opt_count + 1
end

local function optlist(l)
    table.sort(l)
    for _, v in ipairs(l) do opt(v) end
end

local function listpeers(interface)
    local ok, value = pcall(require('ipc').call, interface, 'list')
    if not ok then
        return
    end

    local sock = value
    if not sock then
        return
    end

    local trusted = {}
    local untrusted = {}
    local buf = ""
    now = wh.now()
    while true do
        local r = wh.select({sock}, {}, {}, now+1)
        now = wh.now()

        if not r[sock] then
            break
        end

        buf = buf .. (wh.recv(sock, 65535) .. "")
        if #buf == 0 then
            break
        end

        while true do
            local name, trust, i = string.match(buf, '([^%s]+)%s+([^%s]+)\n()')

            if not name or not trust then
                break
            end
            buf = string.sub(buf, i)

            if trust == 'trusted' then
                trusted[#trusted+1] = name
            else
                untrusted[#untrusted+1] = name
            end
        end
    end
    wh.close(sock)

    return trusted, untrusted
end

local cur_idx = tonumber(arg[2])
local cmd = {}
for i = 3, #arg do cmd[#cmd+1] = arg[i] end

if cur_idx <= 1 then
    local public_subcmds = {}
    for _, v in ipairs(SUBCMDS) do
        local is_private = string.sub(v, 1, 1) == '_'
        if not is_private then
            public_subcmds[#public_subcmds+1] = v
        end
    end

    optlist(public_subcmds)
    return
end

local subcmd = cmd[2]

if cur_idx == 2 then
    if (
        subcmd == 'authenticate' or
        subcmd == 'down' or
        subcmd == 'forget' or
        subcmd == 'inspect' or
        subcmd == 'ipc' or
        subcmd == 'lookup' or
        subcmd == 'p2p' or
        subcmd == 'ping' or
        subcmd == 'reload' or
        subcmd == 'show'
    ) then
        local interfaces = wh.ipc_list()

        if (
            subcmd == 'show' or
            subcmd == 'inspect'
           ) and #interfaces > 1 then
            opt('all')
        end

        optlist(wh.ipc_list())
        return
    end

    if (
        subcmd == 'addconf' or
        subcmd == 'clearconf' or
        subcmd == 'genkey' or
        subcmd == 'orchid' or
        subcmd == 'set' or
        subcmd == 'show' or
        subcmd == 'showconf' or
        subcmd == 'up' or
        subcmd == 'workbit'
    ) then
        optlist(wh.listconf())
    end
end

if cur_idx == 3 then
    if (
        subcmd == 'forget' or
        subcmd == 'lookup' or
        subcmd == 'p2p' or
        subcmd == 'ping'
    ) then
        local trusted, untrusted = listpeers(cmd[3])

        if trusted and untrusted then
            optlist(trusted)
            if cmd[cur_idx+1] or #trusted == 0 then
                optlist(untrusted)
            end
        end
    end

    if subcmd == 'show' then
        opt('all')
        opt('light')
    end
end

if cur_idx == 2 and opt_count ~= 1 then
    opt('help')
end

