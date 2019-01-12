-- Main WireHub server daemon
--
-- This file initializes and runs a WireHub peer. The overall structure of the
-- file is the following:
--
--   Parse CLI arguments
--   Read the private network configuration
--   Check WireGuard interface, if any
--   Initialize a WireHub node (wh.new())
--   Initialize WireHub IPC server
--   Configure WireHub with peers (trusted, bootstrap, ...)
--   Initialize loopback manager
--   Initialize WireGuard <-> WireHub synchronization manager
--
--   while running do    -- main loop
--       list file descriptors to wait for and ...
--       ... calculate next deadline for the I/O event poller
--
--       wait for I/O events
--
--       ask managers to read readable file descriptors
--   end
--
--   De-initialize wgsync
--   De-initialize loopback manager
--   De-initialize WireHub node
--   Exit

local cmd = arg[1]

function help()
    printf('Usage: wh up <network name> {interface <interface> | [private-key <file path>] [listen-port <port>]} [mode {unknown | direct | nat}]')
end

-- XXX move this after configuration is checked
do
    local FG = os.getenv('FG')
    local FG = FG == 'y' or FG == '1'
    if not FG then
        wh.daemon()
    end
end

do
    local log_path = os.getenv('WH_LOGPATH')
    if log_path then
        local log_fh = io.open(log_path, "a")

        function log(s)
            log_fh:write(s .. '\n')
            log_fh:flush()
        end

        atexit(log_fh.close, log_fh)
    end
end
-- XXX ----------------------------------------

local name = arg[2]

if not name then
    return help()
end

local private_key_path
local wg
local opts = parsearg(3, {
    interface = function(s)
        wg = wh.wg.get(s)
        return s
    end,
    ["private-key"] = function(path)
        private_key_path = path
        return wh.readsk(path)
    end,
    ["listen-port"] = tonumber,
    mode = function(s)
        if s ~= 'unknown' and
           s ~= 'direct' and
           s ~= 'nat' then
           s = nil
       end
       return s
   end,
})

if not opts then
    return help()
end

local conf = wh.fromconf(wh.readconf(name))

if not conf then
    printf("Unknown network `%s'", name)
    return help()
end

if not opts.interface and not opts['private-key'] then
    printf('no key specified. generates an ephemeron one. this might be long...')
    local _, _, sk, k = wh.genkey(
        conf.namespace,
        conf.workbit or 0,
        0
    )

    opts['private-key'] = sk
end

-- now is a global
now = wh.now()
local start_time = now

--

status("starting...")

local private_key
local listen_port
local n

--

if opts.interface then
    if not conf.subnet then
        printf('subnetwork not defined: %s', name)
        return help()
    end

    if wg then
        if not wg.private_key or not wg.public_key then
            printf("Interface %s does not have a private key", opts.interface)
            return
        end

        if not wg.listen_port then
            wg.listen_port = wh.DEFAULT_PORT
            -- XXX
            execf('wg set %s listen-port %d', opts.interface, wg.listen_port)
        end

        local wb = wh.workbit(wg.public_key, conf.namespace)
        if wb < (conf.workbit or 0) then
            printf("Insufficient workbit: %d (minimum is %d)", wb, conf.workbit or 0)
            return
        end

        private_key = wg.private_key
        listen_port = wg.listen_port
    else
        error("ephemeron wireguard interface not implemented")
        --execf("ip link add dev %s type wireguard", opts.interface)
        --execf("wg set %s private-key %s listen-port 0", opts.interface, skpath)
        --execf("ip link set %s up", opts.interface)
    end
else
    private_key = opts['private-key']
    listen_port = opts['listen-port'] or wh.DEFAULT_PORT

    if listen_port == 0 then
        listen_port = randomrange(1024, 65535)
    end

    assert(private_key)
end

--

local n_log = tonumber(os.getenv('LOG')) or 0

n = wh.new{
    name=name,
    sk=private_key,
    port=listen_port,
    port_echo=listen_port+1, -- XXX ?
    namespace=conf.namespace,
    workbit=conf.workbit,
    mode=opts.mode,
    log=n_log,
    ns={
        require('ns_keybase'),
    },
}

atexit(n.close, n)

--

local ipc_conn
local handlers = require('handlers_ipc')(n)
ipc_conn = require('ipc').bind(opts.interface or wh.tob64(n.k), handlers)
atexit(ipc_conn.close, ipc_conn)

--

for _, pconf in ipairs(conf.peers) do
    -- do not bootstrap with self
    local p
    if pconf.k then
        p = n.kad:touch(pconf.k)
        p.addr = pconf.addr
    elseif pconf.alias then
        p = n.kad:touch(pconf.alias)
        p.alias = true
    end

    if p then
        p.trust = pconf.trust
        p.hostname = pconf.hostname
        p.ip = pconf.ip
        p.is_gateway = pconf.is_gateway
        p.is_router = pconf.is_router
        p.bootstrap = pconf.bootstrap

        if false then
            local m = {}
            m[#m+1] = string.format("add %s %s",
                p.alias and 'alias' or 'peer',
                p.hostname or wh.tob64(p.k)
            )

            if p.is_router then m[#m+1] = " (router)" end
            if p.is_gateway then m[#m+1] = " (gateway)" end

            printf(table.concat(m))
        end


        if p.bootstrap then
            printf("bootstrap with $(yellow)%s$(reset) (%s)", wh.tob64(p.k), p.addr)
        end
    end
end

--[[
local s
if n.mode == 'unknown' then
    n:detect_nat(nil, function(mode)
        -- mode=blocked, cone, direct, offline
        printf("$(magenta)NAT TYPE: %s", mode)

        n.is_nated = mode ~= 'direct'

        s = n:search(n.k, 'lookup')
    end)
else
    s = n:search(n.k, 'lookup')
end
--]]

-- log

do
    local msg = {"wirehub listening as $(yellow)", wh.tob64(wh.publickey(private_key)), "$(reset)"}
    if DEVICE then msg[#msg+1] = string.format(" for $(yellow)%s$(reset)", DEVICE) end
    msg[#msg+1] = string.format(" on $(yellow)%d$(reset) (port echo %d)", n.port, n.port_echo)
    msg[#msg+1] = string.format(" (mode: $(yellow)%s$(reset))", n.mode)
    printf(table.concat(msg))
end

-- main loop

if opts.interface then
    n.lo = require('lo'){
        n = n,
        auto_connect = true,
    }
end

if n.lo and true then
    n.wgsync = require('wgsync').new{
        n = n,
        interface = opts.interface,
        subnet = conf.subnet,
    }
end

local self = {}

local LOADING_CHARS = {'-', '\\', '|', '/'}
local LOADING_CHARS = {'▄▄', '█▄', '█ ', '█▀', '▀▀', '▀█', ' █', '▄█'}
local lc_idx = 1

-- main loop
now = wh.now()
while n.running do
    local socks = {}
    local timeout

    -- update file descriptors to poll and next deadlines
    do
        local deadlines = {}
        deadlines[#deadlines+1] = n:update(socks)

        if ipc_conn then
            deadlines[#deadlines+1] = ipc_conn:update(socks)
        end

        --

        local deadline = min(deadlines)

        if deadline ~= nil then
            timeout = deadline-now
            if timeout < 0 then timeout = 0 end
        end
    end

    -- XXX
    do
        if self.ip ~= n.p.ip then
            self.ip = n.p.ip

            local ip_subnet = (
                self.ip:addr() ..
                string.sub(conf.subnet, string.find(conf.subnet, '/'), -1)
            )

            printf('$(green)new ip: %s$(reset)', ip_subnet)
            execf('ip addr add %s dev %s', ip_subnet, opts.interface)
        end

        if self.hostname ~= n.p.hostname then

        end
    end

    status(
        '%s waiting (fds: %d, timeout: %s)',
        LOADING_CHARS[lc_idx],
        #socks,
        timeout and string.format('%.1fs', timeout) or '(none)'
    )

    n.kad:clear_touched()

    -- I/O event poller
    local r
    do
        -- Not sure why, but one pcall is not enough to catch the "interrupted"
        -- launched by lua if the user press CTRL+C
        pcall(pcall, function() r = wh.select(socks, {}, {}, timeout) end)
        if not r then break end
        now = wh.now()
    end

    do
        lc_idx = (lc_idx % (#LOADING_CHARS)) + 1
        status('%s', LOADING_CHARS[lc_idx])
    end

    -- notify something needs to be read
    do
        n:on_readable(r)

        if ipc_conn then
            ipc_conn:on_readable(r)
        end
    end
end

status('exiting...')
