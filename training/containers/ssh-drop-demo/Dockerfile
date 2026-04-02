FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y procps && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/demo

COPY authorized_keys /root/.ssh/authorized_keys
COPY .bash_history /root/.bash_history
COPY preload.conf /etc/ld.so.preload
COPY backdoor.service /etc/systemd/system/backdoor.service

CMD ["sleep", "3600"]
