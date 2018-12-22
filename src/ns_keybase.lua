-- Keybase Name reSolver example
--
-- WireHub can assign names to peers through a private network configuration
-- file. It does not provide any native decentralized name resolver to find the
-- key of a peer given its name. This is considered out of the scope of WireHub,
-- as many solutions exist and depend on the requirements of the private
-- network (e.g. DNS, namecoin, Keybase, ...).
--
-- However, it is possible to implement a name resolver and plug it to WireHub
-- to make it able to resolve peer's names. This file shows an example of name
-- resolving using Keybase (https://keybase.io/)
--
-- # Example: Keybase
--
-- This example takes advantage of the Keybase filesystem to resolve peer's
-- name. Each Keybase user may make a directory named 'wirehub/' in the root of
-- its public folder. Each file in the 'wirehub/' directory is named after a
-- subdomain, and contains the base64 form of the peer's public key.
--
-- Peer's names resolvable via Keybase are of the form:
--
--     <user>.kb.wh
--     ... or ...
--     <subdomain>.<user>.kb.wh
--
-- The base64 key of 'foo.bar.kb.wh' is stored in the file
-- '/keybase/public/bar/wirehub/foo'. If no subdomain is defined, the file name
-- is 'default' (e.g. 'bar.kb.wh' => '/keybase/public/bar/wirehub/default')
--
-- For example, see https://keybase.pub/gawenr/wirehub/

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
