"""Constants."""

import re


INTERESTING_PROCESSES = [
    "sshd",
    "unbound",
    "charon",
    "openvpn",
    "starter",
]
INTERESTING_CONTAINERS = re.compile(r'encryptme|watchtower')
INTERESTING_TAGS = re.compile(r'/(encryptme|watchtower)')

DEFAULT_STATS_INTERVAL = 300  # seconds
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_DELAY = 60  # seconds
