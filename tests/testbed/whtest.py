#!/usr/bin/env python3

from base64 import b16encode
import contextlib
import docker
import functools
import io
import logging
import os
import tarfile
import telnetlib
import tempfile
import time
import weakref

def constant(func):
    @property
    @functools.wraps(func)
    def wrapper(self):
        attr = f'_attr_{func.__name__}'
        if not hasattr(self, attr):
            setattr(self, attr, func(self))

        return getattr(self, attr)
    return wrapper


PREFIX = "wh-testbed-"

def check_images(c):
    IMAGES = set((
        'wirehub/testbed-micronet:latest',
        'wirehub/testbed-wh:latest',
    ))

    installed_images = set()
    for i in c.images.list():
        installed_images.update(i.tags)

    missing_images = IMAGES.difference(installed_images)

    if missing_images:
        print("ERROR: missing Docker images")
        for i in sorted(missing_images):
            print(f"- {i}")

        return False

    return True

def clean(c):
    print("cleaning...")
    conts = [c for c in c.containers.list(all=True) if c.name.startswith(PREFIX)]

    for ct in conts:
        if ct.status == "running":
            ct.kill()
        ct.remove()

    nets = [n for n in c.networks.list() if n.name.startswith(PREFIX)]

    for n in nets:
        n.remove()

def write_file(ct, filepath, content):
    fh = io.BytesIO(content)
    tar_info = tarfile.TarInfo(filepath)
    tar_info.size = len(content)

    tar_fh = io.BytesIO()
    t = tarfile.TarFile(mode='w', fileobj=tar_fh)
    t.addfile(tar_info, fh)
    t.close()

    tar_buf = tar_fh.getvalue()
    return ct.put_archive("/", tar_buf)

def read_micronet_conf(c, micronet_conf):
    ct = c.containers.create("wirehub/micronet", "micronet read /conf")
    write_file(ct, "/conf", micronet_conf.encode('utf-8'))
    ct.start()
    resp = ct.logs().decode('utf-8')
    ct.kill()
    ct.remove()

    r = {}
    for i in resp.strip().split('\n'):
        peer_id, peer_type, peer_up = i.split()

        peer_id = int(peer_id)
        peer_up = int(peer_up)

        r[peer_id] = {"type": peer_type, "up": peer_up}

    return r

class Shell:
    PS1 = b"telnet# "

    def __init__(self, ip):
        self.ip = ip

        self.t = telnetlib.Telnet(self.ip)
        self.t.read_until(b"login:")
        self.t.write(b"root\n")
        self.t.read_until(b"# ")
        self.t.write(b"export PS1=\"" + self.PS1 + b"\"\n")
        self.t.read_until(b"\n" + self.PS1)

    def execute(self, cmd, encoding='utf-8', blocking=True):
        line = f"{cmd}\n"

        if encoding is not None:
            line = line.encode(encoding)

        self.t.write(line)

        if blocking:
            self.t.read_until(b"\r\n")
            log = self.t.read_until(self.PS1)

            assert(log.endswith(self.PS1))
            log = log[:-(2+len(self.PS1))]

            if encoding is not None:
                log = log.decode(encoding)

            return log

    __call__ = execute

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.t.close()

    @property
    def value(self):
        return int(self("echo $?"))

class Container:
    def __init__(self):
        self.ct = None

    def stop(self):
        if self.ct:
            self.ct.reload()
            if self.ct.status == 'running':
                self.ct.kill()

            self.ct.remove()
            self.ct = None

    @constant
    def ip(self):
        self.ct.reload()
        while self.ct.status != 'running':
            self.ct.reload()
            time.sleep(.5)

        return self.ct.attrs['NetworkSettings']['Networks'][self.net.name]['IPAddress']

    @property
    def hostname(self):
        return self.ct.attrs['Config']['Hostname']

    def shell(self):
        return Shell(self.ip)

class Micronet(Container):
    def __init__(self, c, net, unet_conf, name):
        super().__init__()

        self.c = c
        self.net = net
        self.unet_conf = unet_conf
        self.name = name

    def start(self):
        self.ct = self.c.containers.create(
            image="wirehub/micronet",
            command="micronet server /conf",
            detach=True,
            hostname=self.name,
            name=self.name,
            network=self.net.name,
        )

        write_file(self.ct, "/conf", self.unet_conf.encode('utf-8'))

        self.ct.start()

class WHClient:
    def __init__(self, sh):
        self.sh = sh

    def __enter__(self):
        self.sh.__enter__()
        return self

    def __exit__(self, *exc):
        self.sh.__exit__(*exc)

    def showconf(self, conf):
        return self.sh(f"wh showconf \"{conf}\"")

    def set(self, conf, **kwargs):
        cmd = ["wh set", conf]

        for k, v in sorted(kwargs.items()):
            if v == True:
                cmd.append(k)

            else:
                cmd.append(k)
                cmd.append(str(v))

        cmd = " ".join(cmd)
        return self.sh(cmd)

    def genkey(self, conf):
        sk = self.sh(f"wh genkey {conf}")
        k = self.sh(f"echo \"{sk}\" | wh pubkey")

        return sk, k

class Node(Container):
    def __init__(self, c, net, name):
        super().__init__()

        self.c = c
        self.net = net
        self.name = name

    def start(self):
        self.ct = self.c.containers.run(
            image="wirehub/testbed-wh",
            cap_add = ("NET_ADMIN", ),
            detach=True,
            hostname=self.name,
            name=self.name,
            network=self.net.name,
        )

    def start_micronet(self, server_ip, peer_id):
        sh = self.shell()
        sh("mkdir /dev/net")
        sh("mknod /dev/net/tun c 10 200")
        sh(f"UNET_SERVERNAME={server_ip} micronet client {peer_id}", blocking=False)

        self.unet_sh = sh

        # check micronet is started
        with self.shell() as sh:
            for _ in range(5):
                sh("ip link show micronet")
                if sh.value == 0:   # found
                    break
            else:
                raise Exception("something wrong with micronet")

    def wh(self):
        return WHClient(self.shell())

class Env:
    def __init__(self, unet_conf, c=None, name=None):
        if c is None:
            c = docker.from_env()

        if name is None:
            name = b16encode(os.urandom(4)).decode('ascii').lower()

        self.logger = logging.getLogger(f"env.{name}")
        self.c = c
        self.prefix = f"{PREFIX}{name}"
        self.unet_conf = unet_conf

        self.unet = None
        self.nodes = {}

    @constant
    def unet_desc(self):
        return read_micronet_conf(self.c, self.unet_conf)

    @constant
    def peer_count(self):
        return max(k for k, v in self.unet_desc.items() if v["type"] == "peer")

    def start(self):
        self.logger.info(f"initialize network")

        self.net = self.c.networks.create(
            name=self.prefix,
            driver="bridge"
        )

        self.logger.info("run micronet network")
        self.unet = Micronet(self.c, self.net, self.unet_conf, f"{self.prefix}-micronet")
        self.unet.start()

        for i in range(self.peer_count):
            peer_id = i+1

            self.logger.info(f"run node #{peer_id}")
            n = Node(self.c, self.net, f"{self.prefix}-{peer_id}")
            n.start()
            n.start_micronet(self.unet.ip, peer_id)

            with n.shell() as sh:
                sh("rm -f /etc/wirehub/*")

            self.nodes[peer_id] = n

    def stop(self):
        self.logger.info("stopping environment")
        for n in self.nodes.values():
            n.stop()

        if self.unet:
            self.unet.stop()

    def __getitem__(self, i):
        return self.nodes[i]

@contextlib.contextmanager
def env(*kargs, **kwargs):
    e = Env(*kargs, **kwargs)
    try:
        e.start()
        yield e

    finally:
        e.stop()

