function help()
    print('Usage: wh pubkey')
end

if arg[2] == 'help' then
    return help()
end

local b64k = io.stdin:read()

local ok, value = pcall(wh.fromb64, b64k, 'wg')

if not ok then
    printf("Invalid key: %s", value)
    return
end

local sk = value

local k = wh.publickey(sk)

print(wh.tob64(k))
