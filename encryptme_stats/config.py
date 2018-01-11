"""Configuration handling functions."""

import configparser
import json

import os

from encryptme_stats import metrics
from encryptme_stats.const import (
    DEFAULT_STATS_INTERVAL, 
    DEFAULT_MAX_RETRIES,
    DEFAULT_RETRY_DELAY,
)


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
    if 'base_url' not in server_config['serverapi']:
        raise Exception('base_url not found in section serverapi in %s' %
                        args.server_config)

    info = {
        "api_url": server_config['serverapi']['base_url']
    }

    def _add_info(name, value):
        if value:
            info[name] = value

    if args.extra_node_information:
        if 'server_id' in server_config['serverapi']:
            _add_info('server_id', server_config['serverapi']['server_id'])

        if os.path.exists("/etc/encryptme/data/server.json"):
            try:
                with open("/etc/encryptme/data/server.json") as data_file:
                    data = json.load(data_file)
                    _add_info('server_name', data.get('name', None))
                    _add_info('target_id',
                              data.get('target', {}).get('target_id', None))
                    _add_info('target_name',
                              data.get('target', {}).get('name', None))
            except Exception as exc:  # noqa
                pass

    return info, config
