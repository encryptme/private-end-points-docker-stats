"""Gather system statistics."""

from datetime import datetime
import glob
import logging
import os
import re
import select
import socket
import time

import netifaces
import proc.core
import psutil
import uptime
from docker import from_env as docker_from_env
from parse import parse

from encryptme_stats.const import (
    INTERESTING_CONTAINERS,
    INTERESTING_PROCESSES,
    INTERESTING_TAGS,
)
from encryptme_stats.lib import (
    get_date,
    get_proc_name,
    subprocess_out,
    WireGuardPeer,
)


__all__ = ["vpn", "cpu", "network", "memory", "filesystem", "process",
           "docker", "openssl", "contentfiltering", "vpn_session", "wireguard"]


# IPSEC helpers
# ---------------------------------------------------------------------------

def _get_ipsec_stats():
    """Get stats for IPSEC connections."""
    num_ipsec = 0
    try:
        output = subprocess_out(["/usr/sbin/ipsec", "status"])
        for line in output:
            if 'ESTABLISHED' in line:
                num_ipsec += 1
    except Exception as exc:
        logging.debug("Error gathering openvpn stats: %s", exc)

    return num_ipsec


def _get_ipsec_session_stats():
    KEYS = {
       'bytes_i': 'bytes_up',
       'bytes_o': 'bytes_down',
    }
    SECONDS = {
        'second': 1,
        'seconds': 1,
        'minutes': 60,
        'hours': 3600,
    }
    info = []
    obj = None
    try:
        output = subprocess_out(["/usr/sbin/ipsec", "statusall"])
        for line in output:
            if 'ESTABLISHED' in line:
                line = line.strip()
                result = parse(
                    "{} ESTABLISHED {} {} ago, {}[{}]...{}[{}CN={},{}", line)

                time_quantity = result[1]
                time_unit = result[2]

                duration_seconds = int(time_quantity) * SECONDS[time_unit]
                logged_at = int(datetime.utcnow().timestamp())
                started_at = logged_at - duration_seconds

                # real_ip should be `result[5]`
                # but we are worry about your privacy
                obj = {
                    'stats_type': 'vpn_session',
                    'vpn_session': {
                        'public_id': result[7],
                        'private_ip': result[3],
                        'real_ip': '127.0.0.1',
                        'started_at': started_at,
                        'logged_at': logged_at,
                        'duration_seconds': duration_seconds,
                        'bytes_up': '',
                        'bytes_down': '',
                        'protocol': 'ipsec',
                    }
                }
            elif obj and "bytes_i" in line and "bytes_o" in line:
                for value in ("bytes_i", "bytes_o"):
                    match = re.search(r'(\d+) {}'.format(value), line)
                    obj['vpn_session'][KEYS[value]] = match.group(1) if match else ''

                info.append(obj)
                obj = None

        return info
    except Exception as exc:
        logging.debug("Error gathering ipsec_session stats: %s", exc)
        return []


# WireGuard helpers
# ---------------------------------------------------------------------------

def _get_wireguard_stats():
    """Get number of WireGuard connections."""

    num_wireguard = 0
    try:
        epoch_now = int(datetime.utcnow().timestamp())
        for peer in WireGuardPeer.yield_peers():
            if peer.is_handshake_recent(epoch_now):
                num_wireguard += 1
    except Exception as exc:
        logging.debug("Error getting wireguard connections: %s", exc)

    return num_wireguard


def _get_wireguard_session_stats():
    """Gather Wireguard statistics."""
    info = []
    try:
        epoch_now = int(datetime.utcnow().timestamp())
        for peer in WireGuardPeer.yield_peers():
            if not peer.is_handshake_recent(epoch_now):
                continue
            info.append({
                'stats_type': 'vpn_session',
                'vpn_session': {
                    'public_id': peer.server_pubkey,
                    'private_ip': peer.ipv4_addr,
                    'last_handshake': peer.last_handshake,
                    'logged_at': epoch_now,
                    'bytes_up': peer.bytes_up,
                    'bytes_down': peer.bytes_down,
                    'protocol': 'wireguard',
                }
            })
    except Exception as exc:
        logging.debug("Error gathering wireguard bandwidth: %s", exc)

    return info


# OpenVPN Helpers
# ---------------------------------------------------------------------------

def _get_openvpn_stats(path="/var/run/openvpn/server-0.sock"):
    """Get stats for OpenVPN connections."""
    try:
        logging.debug("Getting metrics from %s", path)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(path)
            sock.send(b"load-stats\n")
            sock.setblocking(0)

            ready = select.select([sock], [], [], 5.0)
            if ready[0]:
                data = sock.recv(4096)
                if not data:
                    logging.debug("No result?")
                    return 0
                data = data.decode('utf-8')
                logging.debug("Received %s", data)
                data_match = re.search(r'nclients=(\d+)', data)
                logging.debug("pattern match result %s", data_match)
                if data_match:
                    logging.debug("%s connections", data_match.group(1))
                    return int(data_match.group(1))
    except Exception as exc:
        logging.debug("Error gathering openvpn stats: %s", exc)

    return 0


def _get_openvpn_session_stats():
    info = []
    stat_routing = {}
    try:
        # Obtain the common_name when client-disconnect is executed
        CN_FILE = "/tmp/common_names.txt"
        common_names = []
        if os.path.exists(CN_FILE):
            with open(CN_FILE, 'r') as f:
                common_names = f.read().splitlines()

        output = subprocess_out(["cat", "/var/run/openvpn/server-0.status"])
        output = "\n".join(output)
        top = output.split('GLOBAL STATS')[0]
        client_block, routing_block = top.split('ROUTING TABLE')

        client_list = client_block.strip().split('\n')[3:]
        routing_list = routing_block.strip().split('\n')[1:]

        for row in routing_list:
            private_ip, device = row.split(",")[:2]
            stat_routing[device] = private_ip

        pattern = "%a %b %d %H:%M:%S %Y"
        for line in client_list:
            stat_client = line.split(',')

            # Avoid sending stats of just recently disconnected client
            public_id = stat_client[0]
            if public_id in common_names:
                continue

            started_at = int(datetime.strptime(stat_client[4], pattern).timestamp())
            logged_at = int(datetime.utcnow().timestamp())
            duration_seconds = logged_at - started_at

            # real ip should be `stat_client[1].split(':')[0]`
            # but for now... no need to log that by default
            obj = {
                'stats_type': 'vpn_session',
                'vpn_session': {
                    'public_id': public_id,
                    'private_ip': stat_routing[public_id],
                    'real_ip': '127.0.0.1',
                    'started_at': started_at,
                    'logged_at': logged_at,
                    'duration_seconds': duration_seconds,
                    'bytes_up': stat_client[3],
                    'bytes_down': stat_client[2],
                    'protocol': 'openvpn',
                }
            }
            info.append(obj)

        return info
    except Exception as exc:
        logging.debug("Error gathering openvpn_session stats: %s", exc)
        return []


# Metrics
# ---------------------------------------------------------------------------

def vpn():
    """
    Gather VPN connection statistics.

    :return: dictionary with vpn statistics
    """
    num_ipsec = _get_ipsec_stats()
    num_openvpn = _get_openvpn_stats()
    num_wireguard = _get_wireguard_stats()

    return {
        "stats_type": "vpn",
        "vpn": {
            "ipsec_connections": num_ipsec,
            "openvpn_connections": num_openvpn,
            "wireguard_connections": num_wireguard,
        }
    }


def cpu():
    """
    Gather CPU metrics.

    :return: dictionary with CPU statistics
    """
    keep_cpu_stats = [
        'user', 'idle', 'system', 'nice', 'iowait', 'irq', 'softirq'
    ]
    # Ignoring: steal, guest, guest_nice

    def _cpu_stats(stats):
        return {
            stat: value
            for stat, value in stats._asdict().items()
            if stat in keep_cpu_stats
        }

    info = {
        "stats_type": "cpu",
        "num_cpus": psutil.cpu_count(),
        "loadavg": dict(zip(("1min", "5min", "15min"), os.getloadavg())),
        "cpu": {
            "all": _cpu_stats(psutil.cpu_times(percpu=False)),
        },
        "uptime": uptime.uptime(),
    }
    per_cpu_stats = psutil.cpu_times(percpu=True)
    for cpu_no in range(0, len(per_cpu_stats)):
        info['cpu'][str(cpu_no)] = _cpu_stats(per_cpu_stats[cpu_no])

    info['cpu']['all'].update(psutil.cpu_stats()._asdict())

    return info


class Network:
    """
    Gather network encryptme_stats on the primary gateway interface.

    :return: list of dictionaries with Network statistics for default gateway
             interfaces
    """

    def __call__(self, *args, **kwargs):
        return self.compute_metrics()

    def __init__(self):
        self.start_time = time.time()
        self.last_metrics = self.metrics()

    def metrics(self):
        """Gather metrics."""
        info = {}

        gw_interfaces = set()
        all_gateways = netifaces.gateways()
        for gateway in all_gateways.get('default', {}).values():
            gw_interfaces.add(gateway[1])

        for interface, metrics in psutil.net_io_counters(pernic=True).items():
            if interface in gw_interfaces:
                info[interface] = metrics._asdict()
        return info

    def compute_metrics(self):
        current_counters = self.metrics()

        info = []
        for interface, metrics in current_counters.items():
            if interface not in self.last_metrics:
                self.last_metrics[interface] = {}

            delta = {}
            for key, value in metrics.items():
                delta[key] = value - self.last_metrics[interface].get(key, 0)

            if_info = {
                "stats_type": "net",
                "net_interface": interface,
                "net": metrics,
                "net_delta": delta,
            }
            info.append(if_info)

        self.last_metrics = current_counters

        return info

network = Network()


def memory():
    """
    Gather memory statistics.

    :return: dictionary of Memory statistics
    """
    return {
        "stats_type": "mem",
        "mem": psutil.virtual_memory()._asdict(),
        "swap": psutil.swap_memory()._asdict()
    }


def filesystem():
    """
    Gather filesystem encryptme_stats.

    :return: list of dictionaries of Filesystem encryptme_stats
    """
    info = []

    # Disabled this as it was including filesystems that aren't interesting.
    # filesystems = psutil.disk_partitions(all=False)
    # if '/' not in (fs.mountpoint for fs in psutil.disk_partitions()):

    def fs_ok(fs_info):
        """Check if we want to include a filesystem in the results."""
        if fs_info.mountpoint == '/':
            return True

        if (fs_info.device == fs_info.fstype or fs_info.fstype == 'nullfs' or
                '/docker' in fs_info.mountpoint or
                fs_info.mountpoint.startswith('/etc') or
                fs_info.mountpoint.startswith('/lib/modules')):
            return False

        if fs_info.device.startswith('/dev/'):
            return True

        return False

    filesystems = [fs for fs in psutil.disk_partitions(all=True) if fs_ok(fs)]

    seen_device = set()
    for fs_info in filesystems:
        if fs_info.device in seen_device:
            continue
        if '/docker' in fs_info.mountpoint:
            continue
        doc = {
            "stats_type": "fs",
            "mountpoint": fs_info.mountpoint,
            "device": fs_info.device,
            "fstype": fs_info.fstype,
            "fs": psutil.disk_usage(fs_info.mountpoint)._asdict()
        }
        info.append(doc)
        seen_device.add(fs_info.device)

    return info


def process():
    """
    Check if processes that we care about are running.

    :return: dictionary of interesting process information
    """
    interesting_procs = set(INTERESTING_PROCESSES)

    pids = psutil.pids()
    info = {
        "stats_type": "process",
        "proc": {
            "count": len(pids),
        }
    }
    proc_root = os.environ.get("PROC_ROOT", "/proc")
    for pid in pids:
        proc_info = proc.core.Process.from_path(
            os.path.join(proc_root, str(pid)))

        proc_name = get_proc_name(proc_info, interesting_procs)
        if not proc_name:
            continue

        if 'sshd' in proc_name and ':' in proc_info.cmdline:
            continue

        if proc_name not in info['proc']:
            info['proc'][proc_name] = {
                'running': proc_info.state in ('R', 'S', 'D', 'T', 'W'),
                'pid': proc_info.pid,
                'ppid': proc_info.ppid,
                'user_time': int(proc_info.stat_fields[16]),  # cutime
                'sys_time': int(proc_info.stat_fields[17]),  # cstime
                'vsize': proc_info.vsize,
                'rss': proc_info.rss,
                'voluntary_ctxt_switches': int(proc_info.status_fields[
                    'voluntary_ctxt_switches']),
                'nonvoluntary_ctxt_switches': int(proc_info.status_fields[
                    'nonvoluntary_ctxt_switches']),
                'age': proc_info.runtime,
                'count': 1
            }
        else:
            pinfo = info['proc'][proc_name]
            pinfo['count'] += 1

            def append(dest, field, value):
                """Append values for an existing process."""
                if isinstance(dest[field], list):
                    dest[field].append(value)
                else:
                    dest[field] = [dest[field], value]

            # append('state', proc_info.state)
            append(pinfo, 'pid', proc_info.pid)
            append(pinfo, 'ppid', proc_info.ppid)
            pinfo['user_time'] += int(proc_info.stat_fields[16])  # cutime
            pinfo['sys_time'] += int(proc_info.stat_fields[17])  # cstime
            pinfo['vsize'] += proc_info.vsize
            pinfo['rss'] += proc_info.rss
            pinfo['voluntary_ctxt_switches'] = \
                int(proc_info.status_fields['voluntary_ctxt_switches'])
            pinfo['nonvoluntary_ctxt_switches'] = \
                int(proc_info.status_fields['nonvoluntary_ctxt_switches'])
            append(pinfo, 'age', proc_info.runtime)

    return info


def docker():
    """
    Obbtain information on docker containers, if possible.

    :return: list of dictionaries
    """
    try:
        client = docker_from_env(
            version=os.environ.get('DOCKER_API_VERSION', '1.24'))

        containers = []

        for container in client.containers.list():
            include_container = False
            if INTERESTING_CONTAINERS.search(container.name):
                include_container = True
            else:
                for tag in container.image.attrs.get('RepoTags', []):
                    if INTERESTING_TAGS.match(tag):
                        include_container = True
                        break

            if not include_container:
                continue

            docker_metrics = {
                "stats_type": "docker",
                "docker": {
                    "id": container.short_id,
                    "name": container.name,
                    "status": container.status,
                    "labels": ["%s=%s" % (k, v)
                               for k, v in container.labels.items()],
                    "tags": container.image.attrs['RepoTags'],
                    'created': container.image.attrs['Created'],
                }
            }
            if 'version' in container.labels:
                docker_metrics['docker']['image_version'] = \
                    container.labels['version']
            containers.append(docker_metrics)

    except Exception as exc:
        logging.debug("Error gathering Docker info: %s", exc)
        return []

    return containers


def openssl():
    try:
        output = subprocess_out([
            'openssl', 'crl',
            '-inform', 'PEM',
            '-text', '-noout',
            '-in', '/etc/encryptme/pki/crls.pem'
        ])

        # get " Last Update: Feb 16 06:04:54 2018 GMT" and " Next Update: Feb 16 09:04:54 2018 GMT"
        last_update_line = next(i for i in output if 'Last Update' in i)
        next_update_line = next(i for i in output if 'Next Update' in i)
        last_update = get_date(last_update_line, ': ', ' GMT')
        next_update = get_date(next_update_line, ': ', ' GMT')

        cert_filename = subprocess_out(['find', '/etc/encryptme', '-iname', 'cert.pem'])[0]
        output = subprocess_out(['openssl', 'x509', '-dates', '-noout', '-in', cert_filename])

        # get "notBefore=Feb 16 05:41:58 2018 GMT" and "notAfter=May 17 05:41:58 2018 GMT"
        start_date_line = next(i for i in output if 'notBefore' in i)
        end_date_line = next(i for i in output if 'notAfter' in i)
        start_date = get_date(start_date_line, 'notBefore=', ' GMT')
        end_date = get_date(end_date_line, 'notAfter=', ' GMT')

        now = datetime.now()

        return {
            'stats_type': 'openssl',
            'openssl': {
                'crl_last_update': last_update.isoformat(),
                'crl_next_update': next_update.isoformat(),
                'crl_remaining_hours': float((next_update - now).total_seconds() / 3600.0),
                'certificate_start_date': start_date.isoformat(),
                'certificate_end_date': end_date.isoformat(),
                'certificate_remaining_days': (end_date - now).days
            }
        }
    except Exception as exc:
        logging.debug("Error gathering openssl stats: %s", exc)
        return {}


def wireguard():
    """Gather Wireguard statistics."""
    info = []
    try:
        now_epoch = int(datetime.utcnow().timestamp())
        server_pubkey = None
        server_iface = None
        num_peers = 0
        num_connections = 0
        latest_handshake = 0
        # technically we COULD have 2 iterfaces... but we don't do that
        for peer in WireGuardPeer.yield_peers():
            num_peers += 1
            if not server_pubkey:
                server_pubkey = peer.server_pubkey
            if not server_iface:
                server_iface = peer.server_iface
            if peer.last_handshake > latest_handshake:
                latest_handshake = peer.last_handshake
        info.append({
            'stats_type': 'wireguard',
            'wireguard': {
                'interface': server_iface,
                'num_peers': num_peers,  # TOTAL, not necessarily active
                'public_key': server_pubkey,
                'latest_handshake': latest_handshake,
            }
        })
    except Exception as exc:
        logging.debug("Error gathering wireguard stats: %s", exc)

    return info


def contentfiltering(path="/etc/encryptme/filters"):
    """
    Gather Content-Filtering statistics.

    :return: dictionary with content-filtering statistics
    """
    try:
        # blocked domains
        os.chdir(path)
        domain_stats = {}
        for file in glob.glob("*.blacklist"):
            count = 0
            content_type = file.split('.')[0]
            for line in open(os.path.join(path, file)):
                count += 1
            domain_stats[content_type] = count

        # blocked IPs
        ip_stats = {}
        output = subprocess_out(["/usr/sbin/ipset", "-n", "list"])
        for sublist in output:
            if not sublist:
                continue
            list_name = sublist.split('.')[0]
            lines = subprocess_out(["/usr/sbin/ipset", "list", sublist])

            index = lines.index('Members:')
            lines = lines[index + 1:]
            while "" in lines:
                del lines[lines.index("")]

            if list_name in ip_stats:
                ip_stats[list_name] += len(lines)
            else:
                ip_stats[list_name] = len(lines)

        return {
            "stats_type": "contentfiltering",
            "contentfiltering": {
                "domains": domain_stats,
                "ips": ip_stats
            }
        }
    except Exception as exc:
        logging.debug("Error gathering contentfiltering stats: %s", exc)
        return {}


def vpn_session():
    """
    Gather per-connection stats.

    :return: list of dictionaries with connections statistics
    """
    empty = []
    try:
        openvpn_stat = _get_openvpn_session_stats()
        ipsec_stat = _get_ipsec_session_stats()
        wireguard_stat = _get_wireguard_session_stats()

        result = openvpn_stat + ipsec_stat + wireguard_stat
        if len(result) == 0:
            return empty

        return result
    except Exception as exc:
        logging.debug("Error gathering vpn_session stats: %s", exc)
        return empty
