"""Encrypt.me Statistics sending engine."""

import argparse
import json
import logging
import os
import sys
import time

from encryptme_stats import metrics
from encryptme_stats.config import load_configs
from encryptme_stats.scheduler import Scheduler


def dump(server_info=None):
    """Print JSON document from all exported metrics."""
    for metric_fn in metrics.__all__:
        output = getattr(metrics, metric_fn)()
        if not isinstance(output, list):
            output = [output]
        for doc in output:
            if server_info:
                doc.update(server_info)
            print(json.dumps({metric_fn: doc}, indent=2))

    # Wait a moment to test network delta
    time.sleep(1)
    for doc in metrics.network():
        if server_info:
            doc.update(server_info)
        print(json.dumps({"network": doc}, indent=2))


def setup_logging(loglevel="INFO"):
    """Setup logging module."""
    root = logging.getLogger('')
    root.setLevel(getattr(logging, loglevel))

    channel = logging.StreamHandler(sys.stdout)
    channel.setLevel(getattr(logging, loglevel))
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    channel.setFormatter(formatter)
    root.addHandler(channel)


def main():
    """Argument parsing and main loop."""
    parser = argparse.ArgumentParser(
        description='Send JSON-formatted statistics to an HTTP listener',)
    parser.add_argument('--dump', action='store_true',
                        help='Dump what would be sent and exit')
    parser.add_argument('--loglevel', type=str,
                        default='warning', help='Loglevel to use')
    parser.add_argument('--server-config', '-C',
                        type=str, default="/etc/encryptme/encryptme.conf",
                        help="Location of encryptme.conf server config")
    parser.add_argument('--config', '-c',
                        type=str, default='/etc/encryptme-stats.conf',
                        help='Location of encryptme_stats.conf encryptme_stats config')
    parser.add_argument('--now', action='store_true', default=False,
                        help='Force the next send to be immediately')
    parser.add_argument("--auth-key",
                        type=str,
                        help="Authorization key to include in stats as @auth_key")
    parser.add_argument("--extra-node-information",
                        action='store_true', default=False,
                        help="Include other node identifiers such as "
                             "server_id, server name, target_id, and "
                             "target name, if available.")
    parser.add_argument("--server",
                        type=str,
                        help="Specify server URL to send stats to")
    parser.add_argument("--metric",
                        type=str,
                        help="Specify one metric to be sent and exit")

    args = parser.parse_args()

    # For Docker containers
    if os.environ.get("PROC_ROOT", None):
        import psutil

        psutil.PROCFS_PATH = os.environ["PROC_ROOT"]

    setup_logging(args.loglevel.upper())
    info, cfg = load_configs(args)

    if args.dump:
        dump(info)
        sys.exit(0)

    Scheduler.init(info, cfg, now=args.now, server=args.server, auth_key=args.auth_key)

    if args.metric:
        Scheduler.gather(args.metric, getattr(metrics, args.metric))
        sys.exit(0)

    Scheduler.start()
