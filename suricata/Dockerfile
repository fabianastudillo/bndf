<<<<<<< HEAD
FROM jasonish/suricata:master-amd64
=======
FROM centos:8 AS builder
>>>>>>> 8ba527d0c176f3b81567124451d19e47bd854b40

COPY /capture-filter.bpf /etc/suricata/capture-filter.bpf

VOLUME /var/log/suricata
VOLUME /var/lib/suricata
VOLUME /etc/suricata

<<<<<<< HEAD
ENTRYPOINT ["/docker-entrypoint.sh"]
=======
COPY /docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]
>>>>>>> 8ba527d0c176f3b81567124451d19e47bd854b40
