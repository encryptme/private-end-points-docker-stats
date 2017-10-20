"""Configuration handling functions."""

import configparser

from encryptme_stats import metrics
from encryptme_stats.const import DEFAULT_STATS_INTERVAL, DEFAULT_SERVER, \
    DEFAULT_MAX_RETRIES, DEFAULT_RETRY_DELAY


def load_config(path, defaults=None):
    """Load a config file."""
    if not defaults:
        defaults = {}

    cfg = configparser.ConfigParser()
    cfg['DEFAULT'] = defaults
    cfg.read(path)

    return cfg


def load_configs(args):
    """Load both config files and establish defaults."""
    server_config = load_config(args.server_config)
    config = load_config(args.config,
                         {
                             'interval': str(DEFAULT_STATS_INTERVAL),
                             'server': str(DEFAULT_SERVER),
                             'max_retries': str(DEFAULT_MAX_RETRIES),
                             'retry_interval': str(DEFAULT_RETRY_DELAY),
                         })

    # Ensure all config sections exist so config fetching code is simple
    for method in metrics.__all__:
        if method not in config.sections():
            config.add_section(method)
    if 'encryptme_stats' not in config.sections():
        config.add_section('encryptme_stats')

    # Validation
    if 'serverapi' not in server_config.sections():
        raise Exception('section [serverapi] not found in %s' %
                        args.server_config)
    if 'server_id' not in server_config['serverapi']:
        raise Exception('section [serverapi] not found in %s' %
                        args.server_config)

    server_id = server_config['serverapi']['server_id']

    return server_id, config
