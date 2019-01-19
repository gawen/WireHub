-- Entry-point of 'wh'
--
-- Read sub-commands and load the subcommands Lua program

function help()
    print(
        "Usage: wh <cmd> [<args>]\n" ..
        "\n" ..
        "Available setup subcommands\n" ..
        "  addconf: Appends a configuration file to a WireHub network\n" ..
        "  clearconf: Clear the current network configuration\n" ..
        "  down: Detach a Wireguard interface from a WireHub network (daemon)\n" ..
        "  genkey: Generates a new private key for a WireHub network\n" ..
        "  pubkey: Reads a private key from stdin and writes a public key to stdout\n" ..
        "  reload: Reload the configuration\n" ..
        "  set: Change the current network configuration\n" ..
        "  setconf: Applies a configuration file to a WireHub network\n" ..
        "  showconf: Shows the current configuration of a given WireHub network\n"..
        "  up: Create a WireHub network and interface (daemon)\n" ..
        "  workbit: Print workbits for a given WireGuard public key\n" ..
        "\n" ..
        "Available status subcommands\n" ..
        "  show: Shows the current configuration\n" ..
        "\n" ..
        "Available network subcommands\n" ..
        "  auth: Authenticate with an alias' private key\n" ..
        "  forget: Forget one WireHub peer\n" ..
        "  lookup Lookup for a WireHub peer\n" ..
        "  p2p: Establish a peer-to-peer communication with a WireHub peer\n" ..
        "  ping: Ping a WireHub peer\n" ..
        "  resolve: Resolve a hostname among all WireHub networks\n" ..
        "\n" ..
        "Available advanced subcommands\n" ..
        "  bid: Calculate BID between two keys\n" ..
        "  check-wg: Check that WireGuard is ready to be used\n" ..
        "  completion: Auto-completion helper\n" ..
        "  inspect: Return low-level information on WireHub network\n" ..
        "  ipc: Send a IPC command to a WireHub daemon\n" ..
        "  orchid: Print the ORCHID IPv6 of a given node\n" ..
        ""
    )
end

function check_wg()
    local r = wh.wg.check()

    if r == 'oldkernel' then
        printf(
            "==========\n" ..
            "$(red)$(bold)Sorry, Linux kernel must be >%s.$(reset)\n" ..
            "More info: https://www.wireguard.com/install/#kernel-requirements\n" ..
            "==========$(reset)\n",
            string.join('.', wh.wg.LINUX_MINVER)
        )

        return false
    elseif r == 'notloaded' then
        printf(
            "==========\n" ..
            "$(red)$(bold)WireGuard module is not loaded!$(reset)\n" ..
            "\n" ..
            "    $(bold)You might want to install WireGuard first!$(reset)\n" ..
            "    https://www.wireguard.com/install/\n" ..
            "==========$(reset)\n"
        )

        return false
    end

    return true
end

require('wh')
require('helpers')

SUBCMDS = {
    -- private methods
    '_completion',

    -- public methods
    "addconf",
    "authenticate",
    "bid",
    "check-wg",
    "clearconf",
    "completion",
    "down",
    "forget",
    "genkey",
    "help",
    "inspect",
    "ipc",
    "lookup",
    "orchid",
    "p2p",
    "ping",
    "pubkey",
    "reload",
    "resolve",
    "set",
    "setconf",
    "show",
    "showconf",
    "up",
    "workbit",
}
for _, k in ipairs(SUBCMDS) do SUBCMDS[k] = true end

wh.ipc.prepare()

local cmd = arg[1] or 'show'

if cmd == 'auth' then cmd = 'authenticate' end
if cmd == '_completion' then cmd = 'completion' end

if not SUBCMDS[cmd] then
    printf("Invalid subcommand: `%s'", cmd)
    cmd = 'help'
end

if cmd == 'p2p' or cmd == 'ping' or cmd == 'lookup' then
    cmd = 'search'
end

if cmd == 'addconf' or cmd == 'clearconf' or cmd == 'setconf' then
    cmd = 'conf'
end

-- secret cannot be revealed except in these modes
if  cmd ~= 'genkey' and
    cmd ~= 'genconf'
    then
    wh.reveal_secret = nil
end

if cmd == 'help' or cmd == '--help' then
    return help()
end

if cmd == 'up' then
    check_wg()
end

disable_globals()

local retcode = cpcall(require, 'tools.' .. cmd)
if retcode == true then retcode = 0 end

_do_atexits()
status(nil)
os.exit(retcode or 0)

