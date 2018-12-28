from whtest import *

def test_unet_ping():
    unet = """
    W = wan()
    M(W | peer{up_ip=subnet('1.1.1.1', 0)})
    M(W | peer{up_ip=subnet('1.1.1.2', 0)})
    """

    with env(unet) as e:
        with e.nodes[1].shell() as sh:
            sh("ping -c 1 -W 2 1.1.1.1")
            assert sh.value == 0

            sh("ping -c 1 -W 2 1.1.1.2")
            assert sh.value == 0

            sh("ping -c 1 -W 2 1.1.1.3")
            assert sh.value == 1

        with e.nodes[2].shell() as sh:
            sh("ping -c 1 -W 2 1.1.1.1")
            assert sh.value == 0

            sh("ping -c 1 -W 2 1.1.1.2")
            assert sh.value == 0

            sh("ping -c 1 -W 2 1.1.1.3")
            assert sh.value == 1

def test_conf():
    with env_single_node() as n:
        with n.wh() as wh:
            assert wh("showconf", "public") == ""
            wh("set", "public", workbit=8, subnet="10.0.42.1/24")
            wh("set", "public", endpoint="1.1.1.1", bootstrap="yes", untrusted=True, peer="P17zMwXJFbBdJEn05RFIMADw9TX5_m2xgf31OgNKX3w")

            assert wh("showconf", "public") == "[Network]\r\nName = public\r\nNamespace = public\r\nWorkbits = 8\r\nSubNetwork = 10.0.42.1/24\r\n\r\n[Peer]\r\n# Trust = no\r\nBootstrap = yes\r\nPublicKey = P17zMwXJFbBdJEn05RFIMADw9TX5_m2xgf31OgNKX3w\r\nEndpoint = 1.1.1.1:62096\r\n"

            wh("clearconf", "public")
            assert wh("showconf", "public") == ""

def test_key():
    with env_single_node() as n:
        with n.wh() as wh:
            for workbit in range(0, 16):
                wh("clearconf", "test")
                wh("set", "test", workbit=workbit, subnet="10.0.42.1/24")
                sk, k = wh.genkey("test")

                assert sk and k

                wb = wh('workbit', 'test', stdin=k)
                wb = int(wb)
                assert wb >= workbit, f"key {k} has workbit {wb} lower than {workbit}"


