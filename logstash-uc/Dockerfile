ARG ELK_VERSION

FROM logstash:${ELK_VERSION:-7.13.1}

ADD GeoLite2-City.mmdb /usr/share/GeoIP/

RUN /usr/share/logstash/bin/logstash-plugin install logstash-filter-tld
RUN /usr/share/logstash/bin/logstash-plugin install logstash-input-gelf
RUN /usr/share/logstash/bin/logstash-plugin install logstash-filter-dns

USER 0
RUN yum install -y tcpdump
RUN touch /var/log/logs.graylog
RUN chown logstash:root /var/log/logs.graylog

USER 1000

EXPOSE 10000
