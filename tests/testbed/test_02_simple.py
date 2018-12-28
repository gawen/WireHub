from whtest import *

def test_ping():
    unet = """
    W = wan()
    M(W | peer{up_ip=subnet('1.1.1.1', 0)})
    M(W | peer{up_ip=subnet('1.1.1.2', 0)})
    M(W | peer{up_ip=subnet('1.1.1.3', 0)})
    """

    net = "public"

    with env(unet) as e:
        # setup network
        for n in e.nodes.values():
            with n.wh() as wh:
                wh("clearconf", "public")
                wh("set", "public", workbit=8)

        # generate keys
        keys = {}
        for peer_id, n in e.nodes.items():
            with n.wh() as wh:
                sk, k = keys[peer_id] = wh.genkey("public")
                wh.sh(f"echo {sk} > /sk")

        # setup bootstrap
        for peer_id, n in e.nodes.items():
            with n.wh() as wh:
                wh("set", "public", endpoint="1.1.1.1", bootstrap="yes", untrusted=True, peer=keys[1][1])

        # start daemon
        whs = {}
        for peer_id, n in e.nodes.items():
            wh = whs[peer_id] = n.wh()
            k = keys[peer_id][1]

            cmd = ["up", "public", "private-key", "/sk"]
            if peer_id == 1:
                cmd.extend(("mode", "direct"))

            wh(*cmd, blocking=False)

        time.sleep(2)

        # get ipc
        for peer_id, n in e.nodes.items():
            k = keys[peer_id][1]

            with n.wh() as wh:
                #print("all", repr(wh("show", "all")))
                print("specific", repr(wh("ipc", k, "dumpkad")))

        assert False
