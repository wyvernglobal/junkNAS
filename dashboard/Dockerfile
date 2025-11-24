FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      busybox-static python3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m junknas

WORKDIR /home/junknas

# Static files
COPY --chown=junknas:junknas static/ /srv/junknas-dashboard/
# Entrypoint script
COPY --chown=root:root init-dashboard.sh /usr/local/bin/init-dashboard.sh
RUN chmod 755 /usr/local/bin/init-dashboard.sh

USER junknas

ENV DASHBOARD_PORT=80

EXPOSE 80
ENTRYPOINT ["/usr/local/bin/init-dashboard.sh"]
