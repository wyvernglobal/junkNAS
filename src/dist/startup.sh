#!/bin/bash

i2pd --daemon --datadir=/var/lib/i2pd

/usr/local/bin/junknasd \
    --daemon \
    --data=/var/lib/junknas \
    --storage=/var/lib/junknas/storage \
    --smb-user=junknas

