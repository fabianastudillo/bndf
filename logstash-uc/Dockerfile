FROM logstash:${ELK_VERSION:-7.13.1}

LABEL Fabian Astudillo-Salinas <fabian.astudillos@ucuenca.edu.ec>

# Install required Logstash plugins
RUN /usr/share/logstash/bin/logstash-plugin install \
      logstash-filter-tld \
      logstash-input-gelf \
      logstash-filter-dns
# RUN /usr/share/logstash/bin/logstash-plugin install logstash-filter-tld
# RUN /usr/share/logstash/bin/logstash-plugin install logstash-input-gelf
# RUN /usr/share/logstash/bin/logstash-plugin install logstash-filter-dns

USER 0

# Install tcpdump and prepare log file with correct permissions
RUN yum install -y tcpdump && \
    touch /var/log/logs.graylog && \
    chown logstash:root /var/log/logs.graylog && \
    yum clean all && \
    rm -rf /var/cache/yum

# RUN yum install -y tcpdump
# RUN touch /var/log/logs.graylog
# RUN chown logstash:root /var/log/logs.graylog

USER 1000

EXPOSE 10000
