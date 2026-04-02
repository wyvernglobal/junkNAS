#!/bin/bash

/usr/local/bin/junknasd \
    --daemon \
    --data=/var/lib/junknas \
    --storage=/var/lib/junknas/storage \
    --smb-user=junknas

