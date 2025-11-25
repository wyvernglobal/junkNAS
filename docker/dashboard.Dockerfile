FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      busybox-static python3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m junknas

WORKDIR /home/junknas

# Static dashboard assets
COPY --chown=junknas:junknas dashboard/static/ /srv/junknas-dashboard/

# Entrypoint script to configure and serve the dashboard
COPY --chown=root:root dashboard/init-dashboard.sh /usr/local/bin/init-dashboard.sh
RUN chmod 755 /usr/local/bin/init-dashboard.sh

USER junknas

ENV DASHBOARD_PORT=8080

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/init-dashboard.sh"]
