#!/bin/bash
set -e

#eval `ssh-agent -s`
#ssh-add /root/cedia-dnsmirror
#ssh -D 9000 -C -N -f root@201.159.222.218
#TZ='America/Guayaquil'; export TZ

d=`date -d '1 hour ago' '+%Y.%m.%d'`
hour=$((`date -d '1 hour ago' '+%H'`)) 

#python fingerprint_generator.py -d "2021.08.18" -o 5 -w "/root/whitelist.txt" -i "172.17.1.73"
/usr/local/bin/python /fingerprint_generator.py -d "$d" -o "$hour" -w "/root/whitelist.txt" -i "elasticsearch"
#python fingerprint_generator.py -l -i "elasticsearch"