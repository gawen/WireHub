function help()
    print('Usage: wh bid <base64 public key> <base64 public key>')
end

if not arg[2] or arg[2] == 'help' or not arg[3] then
    return help()
end

if arg[2] == '-' and arg[3] == '-' then
    print("ERROR: only one argument may read STDIN")
    return -1
end

local function read_key(idx)
    local b64k = arg[idx]
    if b64k == '-' then b64k = io.stdin:read() end
    local ok, value = pcall(wh.fromb64, b64k)
    if not ok then return false, string.format("Invalid key: %s", b64k) end
    return true, value
end

local ok, k1 = read_key(2)
if not ok then
    print(k1)
    return help()
end

local ok, k2 = read_key(3)
if not ok then
    print(k2)
    return help()
end

local bid = wh.bid(k1, k2)

print(bid)

