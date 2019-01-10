-- Entry-point of the WireHub engine.
--
-- To import WireHub in Lua, do:
--
--   require('helpers')
--   require('wh')
--
-- If you're looking for the main loop of a WireHub peer, please refer to
-- `src/tools/up.lua`.
--
-- # Overall structure
--
-- * auth.lua: Peer authentication mechanism (alias)
-- * bwlog.lua: BandWidth LOG code. Used by nodes to log their bandwidth.
--              Optional.
-- * conf.lua: WireHub configuration reader/writer.
-- * connectivity.lua: Connectivity manager. Checks the network topology where
--                     a WireHub peer is (e.g. behind a NAT, what type, ...) and
--                     manages UPnP IGD if present.
-- * handlers.lua: WireHub protocol packet handlers.
-- * handlers_ipc.lua: WireHub IPC handlers. See ipc.lua
-- * helpers.lua: Helpers for WireHub (e.g. printing, math, code security, ...)
-- * ipc.lua: WireHub IPC manager. Used by the WireHub CLI tool.
-- * kad.lua: Peer maintenance (e.g. check if alive, remove offline peers, ...)
-- * kadstore.lua: Kademilia store object.
-- * key.lua: Helpers to manipulate peer's keys.
-- * lo.lua: Loopback manager. Used to detect application traffic going through
--           a WireGuard tunnel and automatically take action to send traffic to
--           WireHub peers.
-- * nat.lua: NAT discovery mechanism. Think a very light version of STUN.
-- * node.lua: WireHub node logic. Entry-point.
-- * ns_keybase.lua: Name resolver using Keybase. Optional.
-- * packet.lua: Defines WireHub protocol packets.
-- * peer.lua: Define peer's methods.
-- * queue.lua: FIFO queue implementation
-- * search.lua: Peer DHT searching logic
-- * sink-udp.lua: binds and receives UDP packets and discard them.
-- * time.lua: Time helpers
-- * wgsync.lua: WireGuard <-> WireHub data synchronization
-- * wh.lua: this file. entry-point.
--
-- # Native code
--
-- Lua native code is stored in src/core/. The native module is 'whcore' and
-- defined in src/core/whcorelib.c. Current module 'wh' inherits from 'whcore'
-- and extends with Lua methods.
--
-- # Nomenclature
--
-- Short variable names are chosen to make the code more compact:
--
-- * M: Module
-- * MT: lua Meta-Table
-- * a: Authentication session. See 'n.authenticate()' and 'auth.lua'
-- * d: nat Detecting session. See 'n.detect_nat()' and 'nat.lua'
-- * k: public Key of a peer, in its binary form
-- * lo: LOopback manager. See 'lo.lua'
-- * m: Message. Content of a received packet.
-- * me: Message Encrypted. Content of a received packet, but still encrypted.
-- * n: wirehub Node. See 'node.lua'
-- * now: Current timestamp. Global. Updated after every return of the polling
--        function (wh.select).
-- * ns: Name reSolver. See 'ns_*.lua'.
-- * p: Peer table, contains all information regarding a peer. See 'peer.lua'.
-- * s: Search session. See 'n.search()' and 'search.lua'
-- * sk: Secret Key (private key) of a peer, stored as a `secret` pointer
-- * t: generic Table
--
-- By default, a key is public (a key <=> a public key). A secret key <=> a
-- private key

-- wh is a global
assert(wh == nil)
_G['wh'] = require('whcore')

-- check version
local VERSION = {0, 1, 0}
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

do  -- constants
    local constants = {
        -- Seconds. Minimum interval between checking if peers are alive. If one
        -- peer appears to be alive, it will not be checked during this amount
        -- of seconds)
        ALIVE_INTERVAL = 1 * 60,

        -- Authentication retry before failure.
        AUTH_RETRY = 4,

        -- Seconds. Interval to check connectivity.
        CONNECTIVITY_CHECK_EVERY = 5*60,

        -- Default WireHub (and underlying WireGuard) port
        DEFAULT_PORT = 62096,

        -- Count of fragments to temporarily store while WireHub is trying to
        -- connect to a peer.
        FRAGMENT_MAX = 4,

        -- Bytes. WireHub fragment MTU.
        FRAGMENT_MTU = 1024,   -- XXX

        -- Seconds. Timeout when to discard a fragment packet.
        FRAGMENT_TIMEOUT = 4,

        -- Ideal amount of peers to store in one Kademilia bucket (see Kademilia
        -- paper: http://www.scs.stanford.edu/%7Edm/home/papers/kpos.pdf)
        KADEMILIA_K = 20,

        -- Seconds. Keep-alive for direct peers timeout.
        KEEPALIVE_DIRECT_TIMEOUT = 5 * 60,

        -- Seconds. Keep-alive timeout for NAT-ed peers. Should be less than NAT timeout.
        KEEPALIVE_NAT_TIMEOUT = 25,

        -- Maximum tentative of UDP hole punching before failure.
        MAX_PUNCH_RETRY = 10,

        -- Seconds. Time to wait between each UDP hole punching tentative
        MAX_PUNCH_TIMEOUT = .5,

        -- Seconds. NAT timeout.
        NAT_TIMEOUT = 25,

        -- Seconds. Amount of seconds to wait after each failed ping.
        PING_BACKOFF = .5,

        -- Maximum tentative of PING before stating peer is offline.
        PING_RETRY = 4,

        -- Maximum count of peers to keep while searching for a node.
        SEARCH_COUNT = 20,

        -- Seconds. Default peer searching timeout before search is stopped.
        SEARCH_TIMEOUT = 5,

        -- Seconds. Interval to refresh UPnP IGD router with port mapping.
        UPNP_REFRESH_EVERY = 10*60,
    }

    local env_prefix = 'WH_'
    for k, v in pairs(constants) do
        local env_v = os.getenv(env_prefix .. k)

        if env_v and env_v ~= '' then
            env_v = tonumber(env_v)
            if env_v == nil then
                error(string.format("env var %s is not a number", env_prefix .. k))
            else
                v = env_v
            end
        end

        wh[k] = v
    end
end

-- sanity check (see n.send_datagram())
assert(wh.FRAGMENT_MTU >= 1024, "65536/MTU <= 64")

-- additional extensions
require('key')  -- add method wh.key
require('conf') -- add wh.fromconf & wh.toconf
wh.new = require('node').new

-- initialize time global
_G['now'] = 0
