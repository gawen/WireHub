local TIMEOUT = 2
local CMD = string.format("curl -m %s -s ", TIMEOUT)

local function generate_url(path)
    local hostname, user = string.match(path, "(.+)%.(.+)")

    if not hostname and not user then
        user = path
        hostname = "default"
    end

    return string.format("https://%s.keybase.pub/wirehub/%s", user, hostname)
end

return function(n, k, cb)
    local path = string.match(k, "(.+)%.kb.wh")

    if not path then
        return cb(nil)
    end

    local url = generate_url(path)
    local cmd = CMD .. url

    n.ns.worker:pcall(
        function(ok, resp)
            if resp then
                local ok, k = pcall(wh.fromb64, resp)

                if ok then
                    return cb(k)
                end
            end

            return cb(nil)
        end,
        function(cmd)
            return io.popen(cmd):read()
        end,
        cmd
    )
end
