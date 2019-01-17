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
    printf(
"Usage: wh up <network name> [private-key <file path>] [interface <interface>] [listen-port <port>] [mode {unknown | direct | nat}]\n" ..
"\n" ..
"If the argument 'private-key' is not set, one ephemeron key will be generated\n" ..
"for the session, and destroyed when the daemon stops.\n" ..
"\n" ..
"If a WireGuard 'interface' is not set, it will be be default the concatenation\n" ..
"of 'wh-' and the 8 first characters of the base64 form of public key.\n" ..
"\n" ..
"If 'listen-port' is not set, it will be by default 0. If 'listen-port is 0,\n" ..
"WireHub will pick a random listen port between 1024 and 65535.\n" ..
"\n" ..
"Example:\n" ..
"  Starts an ephemeron peer for network 'public'\n" ..
"    wh up public\n" ..
"\n" ..
"  Starts a peer for network 'foo'\n" ..
"    wh up foo private-key /my/keys/foo.sk\n" ..
""
)
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

        function LOG(s)
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

local opts = parsearg(3, {
    interface = tostring,
    ["private-key"] = wh.readsk,
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

-- now is a global
now = wh.now()
local start_time = now

status("starting...")

-- if no private key is set, generate an ephemeron one
if not opts['private-key'] then
    local workbit = conf.workbit or 0

    printf('no key specified. generates an ephemeron one (ns: %q, workbit: %d). this might be long...',
        conf.namespace, workbit)

    _, _, opts['private-key'], _ = wh.genkey(conf.namespace, workbit, 0)
end
assert(opts['private-key'])


-- if the interface is not set, set a default one, which depends on the (public)
-- key.
if not opts.interface then
    local k = wh.publickey(opts['private-key'])
    opts.interface = 'wh-' .. string.sub(wh.tob64(k), 1, 8)
end

-- if no listen port is set, takes the default
if not opts['listen-port'] then
    opts['listen-port'] = 0
end

-- if listen port is set to 0, pick one randomly between 1024 and 65535
if opts['listen-port'] == 0 then
    opts['listen-port'] = randomrange(1024, 65535)
end

-- create node
local n = wh.new{
    name=name,
    sk=opts['private-key'],
    port=opts['listen-port'],
    port_echo=opts['listen-port']+1, -- XXX ?
    namespace=conf.namespace,
    workbit=conf.workbit,
    mode=opts.mode,
    log=tonumber(os.getenv('LOG')),
    ns={
        require('ns_keybase'),
    },
}

atexit(n.close, n)

if wh.WIREGUARD_ENABLED then
    n.lo = require('lo'){
        n = n,
        auto_connect = true,
    }

    n.wgsync = require('wgsync').new{
        n = n,
        interface = opts.interface,
    }
end

--

local ipc_conn
local handlers = require('handlers_ipc')(n)
ipc_conn = require('ipc').bind(opts.interface or wh.tob64(n.k), handlers)
atexit(ipc_conn.close, ipc_conn)

-- log

do
    local msg = {"wirehub listening as $(yellow)", wh.tob64(n.k), "$(reset)"}
    if DEVICE then msg[#msg+1] = string.format(" for $(yellow)%s$(reset)", DEVICE) end
    msg[#msg+1] = string.format(" on $(yellow)%d$(reset) (port echo %d)", n.port, n.port_echo)
    msg[#msg+1] = string.format(" (mode: $(yellow)%s$(reset))", n.mode)
    printf(table.concat(msg))
end

-- Load peers from configuration
local ok, err = n:reload(conf)

if not ok then
    print("Configuration incorrect: %s", err)
    return -1
end

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

        if ipc_conn then
            deadlines[#deadlines+1] = ipc_conn:update(socks)
        end

        deadlines[#deadlines+1] = n:update(socks)

        --

        local deadline = min(deadlines)

        if deadline ~= nil then
            timeout = deadline-now
            if timeout < 0 then timeout = 0 end
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
