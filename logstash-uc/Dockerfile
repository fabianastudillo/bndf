ARG ELK_VERSION

FROM logstash:${ELK_VERSION:-7.13.1}

ADD GeoLite2-City.mmdb /usr/share/GeoIP/

RUN /usr/share/logstash/bin/logstash-plugin install logstash-filter-tld
RUN /usr/share/logstash/bin/logstash-plugin install logstash-input-gelf

USER 0
RUN yum install -y tcpdump

USER 1000
