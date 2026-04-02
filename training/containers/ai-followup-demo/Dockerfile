FROM alpine:3.20

RUN apk add --no-cache busybox-suid

WORKDIR /opt/demo

COPY startup.sh /opt/demo/startup.sh
COPY bootstrap.sh /opt/demo/bootstrap.sh
COPY ai-followup.cron /etc/cron.d/ai-followup

RUN chmod +x /opt/demo/startup.sh /opt/demo/bootstrap.sh && \
    chmod 0644 /etc/cron.d/ai-followup && \
    touch /tmp/demo-payload.b64 /root/.bash_history && \
    echo "echo reviewing suspicious script" >> /root/.bash_history && \
    echo "cat /opt/demo/bootstrap.sh" >> /root/.bash_history

CMD ["/opt/demo/startup.sh"]
