function help()
    print('Usage: wh genkey {<network file path> | workbit <workbit> namespace <namespace>} [threads <worker thread count>]]')
end

if arg[2] == 'help' then
    return help()
end

local args = {
    threads=tonumber,
}

local idx
local conf
if arg[2] and arg[2] ~= 'workbit' and arg[2] ~= 'namespace' and arg[2] ~= 'threads' then
    local err
    conf, err = openconf(arg[2])
    if not conf then
        printf("error: %s", err)
        return -1
    end

    idx = 3
else
    args.namespace = tostring
    args.workbit = tonumber

    idx = 2
end

local opts = parsearg(idx, args)
if not opts then
    return help()
end

if not conf then
    if not opts.namespace then
        opts.namespace = wh.DEFAULT_NAMESPACE
    end

    if not opts.workbit then
        opts.workbit = wh.DEFAULT_WORKBIT
    end

    conf = opts
end

if not conf then
    printf("Unknown network `%s'", name)
    return help()
end

local sign_sk, sign_k, sk, k = wh.genkey(
    conf.namespace,
    conf.workbit,
    opts.threads or 0
)

print(wh.tob64(wh.revealsk(sk), 'wg'))
