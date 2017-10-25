"""Gather system statistics."""

import os
import re
import select
import socket
import subprocess

import netifaces
import proc.core
import psutil
import uptime
from docker import from_env as docker_from_env

from .const import INTERESTING_TAGS, INTERESTING_CONTAINERS, \
    INTERESTING_PROCESSES

__all__ = ["vpn", "cpu", "network", "memory", "filesystem", "process",
           "docker"]


def _get_ipsec_stats():
    """Get stats for IPSEC connections."""
    num_ipsec = 0
    try:
        result = subprocess.run(["ipsec", "status"],
                                stdout=subprocess.PIPE,
                                check=False)
        for line in result.stdout.decode('utf-8').split("\n"):
            if 'ESTABLISHED' in line:
                num_ipsec += 1
    except Exception:
        pass  # yummy

    return num_ipsec


def _get_openvpn_stats(path="/var/run/openvpn/server-0.sock"):
    """Get stats for OpenVPN connections."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(path)
            sock.setblocking(0)

            ready = select.select([sock], [], [], 1.0)
            if ready[0]:
                data = sock.recv(4096)
                data_match = re.search(r'nclients=(\d+)', data)
                if data_match:
                    return int(data_match.group(1))
    except Exception:
        pass  # yummy

    return 0


def vpn():
    """
    Gather VPN connection statistics.

    :return: dictionary with vpn statistics
    """

    # Get IPSEC encryptme_stats
    num_ipsec = _get_ipsec_stats()

    # Get OpenVPN Stats
    num_openvpn = _get_openvpn_stats()

    return {
        "stats_type": "vpn",
        "vpn": {
            "ipsec_connections": num_ipsec,
            "openvpn_connections": num_openvpn
        }
    }


def cpu():
    """
    Gather CPU metrics

    :return: dictionary with CPU statistics
    """

    keep_cpu_stats = ['user', 'idle', 'system', 'nice', 'iowait', 'irq', 'softirq']
    # Ignoring: steal, guest, guest_nice

    def _cpu_stats(stats):
        return {stat: value for stat, value in stats._asdict().items()
                if stat in keep_cpu_stats}

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


def network():
    """
    Gather network encryptme_stats on the primary gateway interface.

    :return: list of dictionaries with Network statistics for default gateway
             interfaces
    """

    gw_interfaces = set()
    all_gateways = netifaces.gateways()
    for gateway in all_gateways.get('default', {}).values():
        gw_interfaces.add(gateway[1])

    info = []
    for interface, metrics in psutil.net_io_counters(pernic=True).items():
        if interface in gw_interfaces:
            if_info = {
                "stats_type": "net",
                "net_interface": interface,
                "net": metrics._asdict(),
            }
            info.append(if_info)
    return info


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
    #filesystems = psutil.disk_partitions(all=False)
    #if '/' not in (fs.mountpoint for fs in psutil.disk_partitions()):

    def fs_ok(fs_info):
        """Check if we want to include a filesystem in the results."""
        if fs_info.mountpoint == '/':
            return True
        if fs_info.device == fs_info.fstype or fs_info.fstype == 'nullfs':
            return False
        if '/docker' in fs_info.mountpoint:
            return False
        if fs_info.mountpoint.startswith('/etc'):
            return False
        if fs_info.mountpoint.startswith('/lib/modules'):
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
    """Check if processes that we care about are running.

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
        if proc_info and proc_info.exe_name in interesting_procs:
            if 'sshd' in proc_info.exe_name and ':' in proc_info.cmdline:
                continue
            if proc_info.exe_name not in info['proc']:
                info['proc'][proc_info.exe_name] = {
                    'running': proc_info.state in ('R', 'S', 'D', 'T', 'W'),
                    # 'state': proc_info.state,
                    'pid': proc_info.pid,
                    'ppid': proc_info.ppid,
                    'user_time': int(proc_info.stat_fields[16]),  #cutime
                    'sys_time': int(proc_info.stat_fields[17]),  #cstime
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
                pinfo = info['proc'][proc_info.exe_name]
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

    except Exception:
        return []

    return containers
