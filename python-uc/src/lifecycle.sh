#!/bin/bash

#"""
#Created on Fri Jan 15 17:32:43 2021
#
#@author: Fabian Astudillo-Salinas <fabian.astudillos@ucuenca.edu.ec>
#"""

#indices=`curl -s -X GET 'http://localhost:9200/_cat/indices?v' | awk '$3~/logstash-dns-/{print $3}'`

indices=`curl -s -X GET 'http://elasticsearch:9200/_cat/indices/logstash-dns-*?v=true' | awk 'NR>1{print $3}'`

#indices=( logstash-dns-2022.02.10 logstash-dns-2022.02.09 logstash-dns-2022.02.08 logstash-dns-2022.02.07 logstash-dns-2022.02.06 logstash-dns-2022.02.05 logstash-dns-2022.02.04 logstash-dns-2022.02.03 logstash-dns-2022.02.02 logstash-dns-2022.02.01 logstash-dns-2022.01.31 logstash-dns-2022.01.30 logstash-dns-2022.01.29 logstash-dns-2022.01.28 logstash-dns-2022.01.27 logstash-dns-2022.01.26 logstash-dns-2022.01.25 )

old=`date --date="-10 day" '+%Y.%m.%d'`

echo $old

echo ${indices[@]}

for index in ${indices[@]}
do
	d=(${index//-/ })
	d=`echo ${d[2]} | sed 's/\./-/g'`	
	di=$(date -d "${d}" '+%Y.%m.%d')
	echo $di
	if [[ $di < $old ]];
	then
		echo "Removing $index ..."
		curl -X DELETE "http://elasticsearch:9200/$index"
	fi
done
