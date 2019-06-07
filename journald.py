#!/usr/bin/env python3

import systemd.journal

reader = systemd.journal.Reader()
reader.add_match('CONTAINER_NAME=openssh')

for msg in reader:
    print('{CONTAINER_NAME}: {MESSAGE}'.format(**msg))
