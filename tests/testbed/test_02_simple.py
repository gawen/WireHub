from whtest import *

def test_ping():
    unet = """
    W = wan()
    M(W | peer{up_ip=subnet('1.1.1.1', 0)})

    for i = 1, 4 do
        M(W | peer{})
    end
    """

    with env(unet) as e:
        e.setup_public()

        # start daemon
        for peer_id, n in e.nodes.items():
            if peer_id == 1:
                continue

            wh = n.daemon_wh = n.wh()

            wh("up", "public", "private-key", "/sk", blocking=False)

        with e.nodes[1].wh() as wh:
            _, fake_k = wh.genkey("public")

        for peer_id, n in e.nodes.items():
            if peer_id == 1:
                continue

            with n.wh() as wh:
                @retry()
                def f():
                    return wh.inspect(n.k) != None

                for other_id, other_n in e.nodes.items():
                    if peer_id == other_id:
                        continue

                    wh('ping', n.k, other_n.k)
                    assert(wh.sh.value == 0)

                wh('ping', n.k, fake_k)
                assert wh.sh.value != 0

