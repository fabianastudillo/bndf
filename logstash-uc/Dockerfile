ARG ELK_VERSION

FROM logstash:${ELK_VERSION:-7.13.1}

RUN /usr/share/logstash/bin/logstash-plugin install logstash-filter-tld
