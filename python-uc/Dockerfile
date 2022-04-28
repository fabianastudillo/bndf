FROM python:3.7.11-bullseye
LABEL Fabian Astudillo-Salinas <fabian.astudillos@ucuenca.edu.ec>

#EXPOSE 8000
#ADD queries.py .
#ADD fingerprint_generator.py .
#COPY cedia-dnsmirror /root/cedia-dnsmirror
#RUN eval `ssh-agent -s` & ssh-add /root/cedia-dnsmirror
ADD crontab /etc/cron.d/crontab
#ADD queries.py .
#ADD fingerprint_generator.py .
#ADD new_entrypoint.sh .
#ADD cedia-dnsmirror /root/
#ADD whitelist.txt /root/

#RUN echo "America/Guayaquil" > /etc/timezone
#RUN dpkg-reconfigure -f noninteractive tzdata
RUN chmod 0644 /etc/cron.d/crontab
#RUN chmod +x /new_entrypoint.sh

RUN touch /var/log/cron.log

RUN mkdir /var/log/bndf
RUN apt-get update
RUN apt-get install -y cron
RUN python -m pip install requests==2.26.0 elasticsearch==7.14.0 pandas==1.3.2 pysocks==1.7.1
RUN python -m pip install -U scikit-learn
RUN python -m pip install matplotlib
RUN python -m pip install plotly chart_studio
RUN python -m pip install tabulate termcolor
#RUN chmod +x fingerprint_generator.py
#CMD [ "python", "./fingerprint_generator.py" ]
#RUN (crontab -l -u root; echo "*/2 * * * * /new_entrypoint.sh") | crontab
RUN mkdir /bndf
CMD cron && tail -f /var/log/cron.log

#ENTRYPOINT ["/bin/sh", "-c", "/bin/bash"]
