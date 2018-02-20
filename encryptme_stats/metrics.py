"""Gather system statistics."""
from datetime import datetime
import logging
import os
import re
import select
import socket
import subprocess
import re

import netifaces
import proc.core
import psutil
import time
import uptime
from docker import from_env as docker_from_env

from encryptme_stats.const import INTERESTING_TAGS, INTERESTING_CONTAINERS, \
    INTERESTING_PROCESSES

__all__ = ["vpn", "cpu", "network", "memory", "filesystem", "process",
           "docker", "openssl"]


def subprocess_out(command):
    try:
        # Python 3.5+
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            check=False
        )
        output = result.stdout.decode('utf-8').split("\n")
    except AttributeError:
        result = subprocess.check_output(["ipsec", "status"])
        output = result.decode('utf-8').split("\n")
    return output


def _get_ipsec_stats():
    """Get stats for IPSEC connections."""
    num_ipsec = 0
    try:
        output = subprocess_out(["ipsec", "status"])
        for line in output:
            if 'ESTABLISHED' in line:
                num_ipsec += 1
    except Exception as exc:
        logging.debug("Error gathering openvpn stats: %s", exc)

    return num_ipsec


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


class Network(object):
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
    #filesystems = psutil.disk_partitions(all=False)
    #if '/' not in (fs.mountpoint for fs in psutil.disk_partitions()):

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

    except Exception as exc:
        logging.debug("Error gathering Docker info: %s", exc)
        return []

    return containers


def find_between(s, left, right):
    try:
        start = s.index(left) + len(left)
        end = s.index(right, start)
        return s[start:end]
    except ValueError:
        return ""


def get_date(raw_date, left, right):
    start = raw_date.index(left) + len(left)
    end = raw_date.index(right, start)
    raw_date = raw_date[start:end]
    return datetime.strptime(raw_date, '%b %d %H:%M:%S %Y')


def openssl():
    try:
        output = subprocess_out(
            ['openssl', 'crl', '-inform', 'PEM', '-text', '-noout', '-in', '/etc/encryptme/pki/crls.pem'])

        #get " Last Update: Feb 16 06:04:54 2018 GMT" and " Next Update: Feb 16 09:04:54 2018 GMT"
        last_update_line = next(i for i in output if 'Last Update' in i)
        next_update_line = next(i for i in output if 'Next Update' in i)
        last_update = get_date(last_update_line, ': ', ' GMT')
        next_update = get_date(next_update_line, ': ', ' GMT')

        # output = subprocess_out(['find', '/etc/encryptme', '|', 'grep', 'cert1.pem'])
        cert_filename = subprocess_out(['find', '/etc/encryptme', '|', 'grep', 'cert1.pem'])[0]
        output = subprocess_out(['openssl', 'x509', '-noout', '-in', cert_filename])

        # get "notBefore=Feb 16 05:41:58 2018 GMT" and "notAfter=May 17 05:41:58 2018 GMT"
        start_date_line = next(i for i in output if 'notBefore' in i)
        end_date_line = next(i for i in output if 'notAfter' in i)
        start_date = get_date(start_date_line, 'notBefore=', ' GMT')
        end_date = get_date(end_date_line, 'notAfter=', ' GMT')

        return {
            'crl_last_update': last_update.isoformat(),
            'crl_next_update': next_update.isoformat(),
            'certificate_start_date': start_date.isoformat(),
            'certificate_end_date': end_date.isoformat()
        }
    except Exception as exc:
        raise
        logging.debug("Error gathering openssl stats: %s", exc)
        return {'exp': str(exc)}
