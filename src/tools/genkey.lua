function help()
    print('Usage: wh genkey <network name> [threads <worker thread count>]]')
end

if arg[2] == 'help' then
    return help()
end

local name = arg[2]

if not name then
    return help()
end

local opts = parsearg(3, {
    threads=tonumber,
})

if not opts then
    return help()
end

local conf = wh.fromconf(wh.readconf(name))

if not conf then
    printf("Unknown network `%s'", name)
    return help()
end

local sign_sk, sign_k, sk, k = wh.genkey(
    conf.namespace or 'public',
    conf.workbit or 0,
    opts.threads or 0
)

print(wh.tob64(wh.revealsk(sk), 'wg'))
