import subprocess
from datetime import datetime


def get_date(raw_date, left, right):
    start = raw_date.index(left) + len(left)
    end = raw_date.index(right, start)
    raw_date = raw_date[start:end]
    return datetime.strptime(raw_date, '%b %d %H:%M:%S %Y')


def get_proc_name(proc_info, interesting_procs):
    """
    Obtain the proper process name.

    In case the comm field is cut to 15 chars
    it will return the name of the interesting process.
    """
    if proc_info:
        command = proc_info.comm
        if command in interesting_procs:
            return command
        elif len(command) == 15:
            for name in interesting_procs:
                if name.startswith(command):
                    return name
    return None


def subprocess_out(command):
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            check=False
        )
        output = result.stdout.decode('utf-8').strip().split("\n")
    except AttributeError:
        result = subprocess.check_output(command)
        output = result.decode('utf-8').strip().split("\n")
    return output


class WireGuardPeer:
    """
    Cleans up peer output from `wg show wg# dump` commands and provides useful,
    typed properties.
    """
    def __init__(self, wg_dump_line, server_pubkey):
        self.wg_dump_line = wg_dump_line
        (
            self.pubkey,  # WG public key
            self.preshared_key,  # shared key key or "(none)"
            self.endpoint,  # real, public "ip_address:port" or "(none)"
            self.allowed_ips,  # internal IP address in CIDR notation
            self.last_handshake,  # epoch or 0
            self.bytes_down,  # down = received from the peer
            self.bytes_up,  # up = sent to the peer
            self.keepalive,  # 'off' or 'on'
        ) = wg_dump_line.split('\t')
        self.server_pubkey = server_pubkey
        # clean up our data to be easier to process
        self.last_handshake = int(self.last_handshake)
        self.bytes_up = int(self.bytes_up)
        self.bytes_down = int(self.bytes_down)
        if self.preshared_key == '(none)':
            self.preshared_key = None
        if self.endpoint == '(none)':
            self.endpoint = None
        self.keepalive = (self.keepalive == 'on')

    @classmethod
    def yield_peers(cls):
        interfaces = subprocess_out(["wg", "show", "interfaces"])
        for interface in interfaces:
            peer_dump = subprocess_out(["wg", "show", interface, "dump"])
            # first line is server info: privkey, pubkey, port, fwmark
            server_pubkey = peer_dump[0].split('\t')[1]
            for peer_data in peer_dump[1:]:
                yield cls(peer_dump, server_pubkey)

    def is_handshake_recent(self, epoch_now=None, minutes=4):
        if not epoch_now:
            epoch_now = int(datetime.utcnow().timestamp())
        return (epoch_now - self.last_handshake) <= (minutes * 60)

    @property
    def ipv4_addr(self):
        allowed_ips = self.allowed_ips.split(':')
        if not allowed_ips:
            raise Exception(
                f'Failed to process "allowed_ips" from {self.wg_dump_line}'
            )
        ipv4_addr, _ = allowed_ips[0].split('/')
        return ipv4_addr

    @property
    def ipv6_addr(self):
        allowed_ips = self.allowed_ips.split(':')
        if not allowed_ips:
            raise Exception(
                f'Failed to process "allowed_ips" from {self.wg_dump_line}'
            )
        if len(allowed_ips) < 2:
            return None
        ipv6_addr, _ = allowed_ips[1].split('/')
        return ipv6_addr
