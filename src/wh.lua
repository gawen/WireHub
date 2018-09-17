--DEBUG = true

-- variable's nomenclature:
-- a for Authentication session
-- M for Module
-- n for Node
-- t for kademila Tree
-- s for Search session
-- d for nat Detecting session
-- p for Peer address
-- sc for Search & Connect
--
-- Nomenclature:
-- by default, a key is public (a key <=> a public key)
-- a secret key <=> a private key

-- wh is a global
assert(wh == nil)
_G['wh'] = require('whcore')

local VERSION = {0, 1, 0}

-- check version
do
    local major, minor, revision = wh.version()

    if major ~= VERSION[1] or minor ~= VERSION[2] or revision ~= VERSION[3] then
        error(string.format("version mismatch: version is %d.%d.%d, core's is %d.%d.%d",
            major, minor, revision,
            VERSION[1], VERSION[2], VERSION[3]
        ))
    end

    wh.version = setmetatable(VERSION, {
        __tostring = function(v)
            return string.format('%d.%d.%d', table.unpack(VERSION))
        end
    })
end

-- constants
wh.AUTH_RETRY = 4
wh.CONNECTIVITY_CHECK_EVERY = 5*60
wh.DEFAULT_PORT = 62096
wh.FRAGMENT_MAX = 4
wh.FRAGMENT_MTU = 1024   -- XXX
wh.FRAGMENT_TIMEOUT = 4
wh.KADEMILIA_K = 20
wh.KEEPALIVE_TIMEOUT = 25
wh.MAX_PUNCH_RETRY = 10
wh.MAX_PUNCH_TIMEOUT = .5
wh.NAT_TIMEOUT = 25
wh.PING_BACKOFF = .5
wh.PING_RETRY = 4
wh.SEARCH_TIMEOUT = 5
wh.UPNP_REFRESH_EVERY = 10*60

-- sanity check
assert(wh.FRAGMENT_MTU >= 1024, "65536/MTU <= 64")

-- additional extensions
require('key')  -- add method wh.key
require('conf') -- add wh.fromconf & wh.toconf
wh.new = require('node').new

_G['now'] = 0
