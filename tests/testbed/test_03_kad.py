from whtest import *
from collections import defaultdict

KADEMILIA_K = 4
KADEMILIA_EXTRA_K = KADEMILIA_K * 20

lua_generate_large_network_keys = """
require('wh')
require('helpers')

local name = arg[1]
local max_bid = tonumber(arg[2])

local conf = wh.fromconf(wh.readconf(name))

if not conf then
    printf("Unknown network `%s'", name)
    return help()
end

local sks = {}
local ks = {}
local mat = {}

local function counter(t)
    local r = {}
    for _, v in ipairs(t) do
        r[v] = (r[v] or 0) + 1
    end
    return r
end

local function net_big_enough()
    for _, l in ipairs(mat) do
        for bid, count in pairs(counter(l)) do
            if count > max_bid then
                return true
            end
        end
    end

    return false
end

while true do
    local sign_sk, sign_k, sk, k = wh.genkey(
        conf.namespace or 'public',
        conf.workbit or 0,
        0
    )

    local curline = {}
    for _, k2 in ipairs(ks) do
        curline[#curline+1] = wh.bid(k, k2)
    end

    for i = 1, #curline do
        mat[i][#mat[i]+1] = curline[i]
    end

    curline[#curline+1] = wh.bid(k, k)
    mat[#mat+1] = curline
    ks[#ks+1] = k
    sks[#sks+1] = sk

    if net_big_enough() then
        break
    end

    --printf("not enough, generate new key #%s", #ks+1)
end

for i = 1, #sks do
    io.stdout:write(wh.tob64(wh.revealsk(sks[i]), 'wg') .. ' ')
    io.stdout:write(wh.tob64(ks[i]) .. ' ')

    for _, j in ipairs(mat[i]) do
        io.stdout:write(tostring(j) .. ' ')
    end

    io.stdout:write('\\n')
end
"""

def test_kad():
    unet = """
    W = wan()
    M(W | peer{up_ip=subnet('1.1.1.1', 0)})

    for i = 1, 1 do M(W | peer{}) end
    """

    ENVS = {
        'WH_KADEMILIA_K': KADEMILIA_K,
    }

    with env(unet) as e:
        e.setup_public(workbit=0, env=ENVS)

        # start as many daemon necessary to have a network where some peers does not know each other

        ret = e.lua(lua_generate_large_network_keys, "public", KADEMILIA_EXTRA_K)

        keys = []
        mat_bid = []
        for line in ret.split('\n'):
            line = line.strip().split()
            sk, k = line[:2]
            keys.append((sk, k))
            mat_bid.append([int(i) for i in line[2:]])

        # distribute keys among peers
        keys_per_n = defaultdict(list)
        for i, k in enumerate(keys):
            peer_id = (i%(e.peer_count-1))+2
            keys_per_n[peer_id].append((i, k))

        keys = {}
        for peer_id, l in keys_per_n.items():
            for i_ks in l:
                i = i_ks[0]
                sk, k = i_ks[1]

                with e[peer_id].shell() as sh:
                    sh(f"echo {sk} > /sk.{i}")

                keys[i] = k

        peers = [(peer_id, n) for peer_id, n in e.nodes.items() if peer_id > 1]

        for peer_id, n in peers:
            n.daemon_wh = n.wh()

            for i_ks in keys_per_n[peer_id]:
                i = i_ks[0]
                k = keys[i]

                n.daemon_wh("up", "public", private_key=f"/sk.{i}", listen_port=0, blocking=False, env=ENVS)

        for peer_id, n in peers:
            with n.wh() as wh:
                for i_ks in keys_per_n[peer_id]:
                    i = i_ks[0]
                    k = keys[i]

                    @retry()
                    def f():
                        return wh.inspect(k) != None

        time.sleep(30)

        r = {}

        from pprint import pprint
        for peer_id, n in e.nodes.items():
            with n.wh() as wh:
                for i, k in enumerate(wh.interfaces()):
                    r[i] = wh.inspect(k)

        import json
        with open('log.json', 'w') as fh:
            json.dump(r, fh)

        assert False
