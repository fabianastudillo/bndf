ARG ELK_VERSION

FROM logstash:${ELK_VERSION:-7.13.1}

ADD GeoLite2-City.mmdb /usr/share/GeoIP/

RUN /usr/share/logstash/bin/logstash-plugin install logstash-filter-tld
