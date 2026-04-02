FROM alpine:3.20

RUN apk add --no-cache busybox-suid

WORKDIR /opt/demo

COPY cronjob /etc/crontabs/root
COPY harmless-job.sh /opt/demo/harmless-job.sh
COPY suspicious-note.txt /tmp/suspicious-note.txt

RUN chmod +x /opt/demo/harmless-job.sh

CMD ["crond", "-f", "-l", "2"]
