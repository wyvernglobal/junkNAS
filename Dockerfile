FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends golang-go cmake i2pd samba samba-common-bin cifs-utils mergerfs fuse ca-certificates build-essential sudo kmod
RUN mkdir -p /junknas
COPY ./src/ /junknas/
RUN chmod +x /junknas/dist/install.sh
RUN chmod +x /junknas/dist/startup.sh
RUN mkdir -p /etc/junknas
RUN touch /etc/junknas/smb.secret
WORKDIR /junknas/dist
RUN /junknas/dist/install.sh
ENTRYPOINT ["/junknas/dist/startup.sh"]
