"""Constants."""

import re



# Because of an existing length limit of 15 characters in comm (command) field  
# only the first 15 chars in the process name will be used to match 
# a running process. 
# So we must avoid using process names that start with the same 15 chars.


INTERESTING_PROCESSES = [
    "sshd",
    "unbound",
    "charon",
    "openvpn",
    "starter",
    "filter_server.py",
]
INTERESTING_CONTAINERS = re.compile(r'encryptme|watchtower')
INTERESTING_TAGS = re.compile(r'/(encryptme|watchtower)')

DEFAULT_STATS_INTERVAL = 300  # seconds
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_DELAY = 60  # seconds
