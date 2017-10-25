# Python encryptme-stats package

This module gathers statistics about things of interest for Encrypt.me private endpoint quality of service management, such as:

* VPN connections
* CPU utilization
* Network utilization
* Filesystem usage
* Docker containers related to Encrypt.me
* Processes related to Encrypt.me

### Installation

```bash
   pip install git+https://gitlab.toybox.ca/krayola/encryptme-metrics.git
```

### Testing

```bash

    docker build -t test .
    docker run -v `pwd`/encryptme.conf:/etc/encryptme/encryptme.conf \
        -v `pwd`/server.json:/etc/encryptme/data/server.json \
        --rm -it test encryptme-stats --extra-node-information --dump
```

### Configuration

```
[DEFAULT]
; interval = 300
; server = https://stats.getcloakvpn.com
; max_retries = 3
; retry_interval = 60

[vpn]
; interval = 300
; max_retries = 3
; retry_interval = 60

[cpu]
; interval = 300
; max_retries = 3
; retry_interval = 60

[network]
; interval = 300
; max_retries = 3
; retry_interval = 60

[memory]
interval = 900
; max_retries = 3
; retry_interval = 60

[filesystem]
interval = 900
; max_retries = 3
; retry_interval = 60

[process]
interval = 900
; max_retries = 3
; retry_interval = 60

[docker]
interval = 900
; max_retries = 3
; retry_interval = 60

```