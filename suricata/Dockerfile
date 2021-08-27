FROM jasonish/suricata:master-amd64

COPY /capture-filter.bpf /etc/suricata/capture-filter.bpf

VOLUME /var/log/suricata
VOLUME /var/lib/suricata
VOLUME /etc/suricata

ENTRYPOINT ["/docker-entrypoint.sh"]
