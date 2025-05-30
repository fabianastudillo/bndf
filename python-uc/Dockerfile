FROM python:3.7.11-bullseye

LABEL Fabian Astudillo-Salinas <fabian.astudillos@ucuenca.edu.ec>

# Set working directory
WORKDIR /bndf

# Add crontab and set permissions
ADD crontab /etc/cron.d/crontab
RUN chmod 0644 /etc/cron.d/crontab && \
    touch /var/log/cron.log && \
    mkdir -p /var/log/bndf /bndf

# Install system dependencies and clean up
RUN apt-get update && \
    apt-get install -y cron && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies in one layer
RUN pip install --no-cache-dir \
    requests==2.26.0 \
    elasticsearch==7.14.0 \
    pandas==1.3.2 \
    pysocks==1.7.1 \
    scikit-learn \
    matplotlib \
    plotly \
    chart_studio \
    tabulate \
    termcolor

# Optional: Healthcheck for cron
HEALTHCHECK CMD pgrep cron || exit 1

# Default command
CMD cron && tail -f /var/log/cron.log
#ENTRYPOINT ["/bin/sh", "-c", "/bin/bash"]







