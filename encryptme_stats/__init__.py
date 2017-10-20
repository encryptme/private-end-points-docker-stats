"""Encrypt.me Statistics sending engine."""

import argparse
import json
import logging
import sys

import os

from encryptme_stats.config import load_configs
from encryptme_stats import metrics
from encryptme_stats.scheduler import Scheduler


def dump():
    """Print JSON document from all exported metrics."""
    for metric_fn in metrics.__all__:
        output = getattr(metrics, metric_fn)()
        if isinstance(output, list):
            output = [output]
        for doc in output:
            print(json.dumps(doc, indent=4))


def setup_logging(loglevel="INFO"):
    """Setup logging module."""
    root = logging.getLogger()
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
        description='Send statistics to Encrypt.me.')
    parser.add_argument('--dump', help='Dump what would be sent and exit')
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

    args = parser.parse_args()

    # For Docker containers
    if os.environ.get("PROC_ROOT", None):
        import psutil

        psutil.PROCFS_PATH = os.environ["PROC_ROOT"]

    if args.dump:
        dump()
        sys.exit(0)

    setup_logging(args.loglevel.upper())
    server_id, cfg = load_configs(args)

    Scheduler.start(server_id, cfg, now=args.now)
