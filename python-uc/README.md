# Botnet Detection Framework

The framework is composed by several modules:

1. logstash: this module receive the information from a graylog server. Events are received throught port 10000 using the Graylog Extended Log Format (GELF). The DNS events are filtered using the pipeline configuration file; in this configuration file is set up the attributes which will send to the elasticsearch. The configuration file is in '/containers-data/logstash/conf.d/logstash.conf'
2. elasticsearch: in this module is stored all the filtered attributes of each DNS event. 
3. python: in this module is all the scripts used to process the DNS events from elasticsearch.
    1. Fingerprints are generated each hour. For execute this process has been configured a cron event; this event executes the 'FingerprintGenerator.py' script each hour. The script generates a file by day in the docker called '/var/log/bndf/fingerprints-<yyyy-mm-dd>'.
    2. The fingerprints has to be generated during 10 days. When there exist 10 days of fingerprints, it is executed the script 'IsolationForest.py'. First, all the fingerprint files are join in a unique file in the python docker called '/bndf/adf/full.csv.'. After, it is executed the Isolation Forest algorithm changing the estimator parameter from 2 to 1000. The results are stored in the file '/bndf/adf/estimators.csv'; this results are plotted using the gnuplot script of 'Figura12'.
    3. When the number of estimators value is manually selected; it is used in the 'AnomalyDetection.py' script. From the first results, we decide to select 70 trees to train the algorithm. 

Some useful commands
    docker cp crontab b720b796ed96:/etc/cron.d/crontab