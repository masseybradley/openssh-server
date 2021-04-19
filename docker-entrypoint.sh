#!/bin/bash

set -e

if [ -S "/var/run/rsyslog/dev/log" ]; then
    ln -sf /var/run/rsyslog/dev/log /dev/log
fi

exec "$@"
