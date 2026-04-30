FROM debian:stable-slim

# JunkNAS runs entirely in userspace. The container only needs FUSE for the
# mergerfs unified mount; if /dev/fuse is unavailable the daemon transparently
# falls back to a virtual-union mode using symlinks.
#
# Recommended run command (full functionality):
#   docker run --device /dev/fuse --cap-add SYS_ADMIN <image>
# Minimal run (no mergerfs, virtual-union fallback):
#   docker run <image>

RUN apt-get update && apt-get install -y --no-install-recommends \
        golang-go cmake i2pd samba samba-common-bin cifs-utils mergerfs fuse \
        ca-certificates build-essential sudo \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /junknas
COPY ./src/ /junknas/
RUN chmod +x /junknas/dist/install.sh /junknas/dist/startup.sh
RUN mkdir -p /etc/junknas && touch /etc/junknas/smb.secret
WORKDIR /junknas/dist
RUN /junknas/dist/install.sh

ENTRYPOINT ["/junknas/dist/startup.sh"]
