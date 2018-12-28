from whtest import env

def test_docker():
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




"""
def main():
    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)

    c = docker.from_env()

    if not check_images(c):
        return

    clean(c)

    with open("micronet.conf", "r") as fh:
        unet_buf = fh.read()

    with env(unet_buf) as e:
        #for peer_id, n in e.nodes.items(): print(peer_id, n.ip)

        n = e.nodes[1]
        with n.wh() as wh:
            wh.set("public", workbit=8, subnet="10.0.42.1/24")
            wh.set("public", endpoint="1.1.1.1", bootstrap="yes", untrusted=True, peer="P17zMwXJFbBdJEn05RFIMADw9TX5_m2xgf31OgNKX3w")

            print(wh.genkey("public"))

            #print(wh.showconf("public"))

    #create(c, "test", unet_buf)

if __name__ == '__main__':
    main()
"""
