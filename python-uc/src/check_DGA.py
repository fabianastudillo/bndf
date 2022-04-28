#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jan 15 20:55:45 2021

@author: Vicente Quezada
@modified by: Fabian Astudillo <fabian.astudillos@ucuenca.edu.ec>
"""

from sqlite3 import Timestamp
import pandas as pd
import queries
#import socket
#import socks
import requests
from elasticsearch import Elasticsearch
from collections import Counter
import statistics
import math
import numpy as np
from tabulate import tabulate
from termcolor import colored
#import datetime
import datetime as dt
import dateutil.parser
import re
from itertools import groupby
import ssl

#check por DGA
#vow=["a","e","i","o","u","y","A","E","I","O","U","Y"]
#cons=["b","c", "d", "f", "g", 
#             "h", "j", "k", "l", "m", 
#             "n", "ñ", "p", "q", "r", 
#             "s", "t", "v", "w", "x", "z",
#             "B","C", "D", "F", "G", 
#             "H", "J", "K", "L", "M", 
#             "N", "Ñ", "P", "Q", "R", 
#             "S", "T", "V", "W", "X", "Z"]

def ConvertTime(time):
    return(time.strftime("%Y-%m-%dT%H:%M:%SZ"))

# ln=len of word; max_cons
def rma(ln,max_cons,max_voc,entropy):
    if (entropy <= 2) and (ln<5):
        category=0 #"clean"
    elif (entropy>3.24):
        category=1 #"bot"
    elif (max_cons >= 4) or (max_voc >=4):
        category=1 #"bot"
    else:
        category=0 #"clean"
    return(category)
    
def getMetrics(word):
    # Max number of sequential vowels
    max_vow=0
    # Max number of sequential consonants
    max_cons=0
    #con_vow=0
    #con_cons=0
    
    # Len of the word
    # ln = len(word)
    word1 = word.lower()
    
    # vowel = [ch for ch in word if ch in 'aeiouy']
    # con_vow = len(vowel)
    
    # consonant = [ch for ch in word if ch not in 'aeiouy']
    # con_cons = len(consonant)
    
    word1 = re.sub('[eiouy]', 'a', word1)
    word1 = re.sub('[^aeiouy\-\_]', 'c', word1)
    #print(word1)
    result = [(label, sum(1 for _ in group)) for label, group in groupby(word1)]
    
    for key, count in result:
        if (key=='a' and count > max_vow):
            max_vow = count
        elif (key=='c' and count > max_cons):
            max_cons = count
    
    num_elem = len(word)
    prob_elem = 1/num_elem
    elem_set = set(word)
    c_pro_elem = []
    for element in elem_set:
    #    print(element + " " + str(word.count(element)))
        if (not element in '-_'):
            c_pro_elem.append(word.count(element))
    #print(c_pro_elem)
    f_pro=[i*prob_elem for i in c_pro_elem]
    entropy=0
    for prob in f_pro:
        entropy=entropy+(prob*math.log(prob,2))
    entropy=round(entropy*(-1),2)
    return(num_elem,max_cons,max_vow,entropy)
#

# TODO: Add anomaly file as argument 

#socks.set_default_proxy(socks.SOCKS5, "localhost", 9000)
#socket.socket = socks.socksocket

try:
  es = Elasticsearch([{'host':'elasticsearch','port':9200,}])
  print ("Connected")
except Exception as ex:
  print ("Error:", ex)
  
HEADERS = {
        'Content-Type': 'application/json'
        }

## remove elements
"""
lista_blanca=["200.0.29.68",
              "45.182.117.5",
              "186.3.44.231",
              "201.159.222.92",
              "181.198.63.86",
              "2800:0068:0000:bebe:0000:0000:0000:0004"]

df=pd.read_csv("/home/vicente/Escritorio/Tesis/FP_anomalies_target.csv")
df.head()
metrics_df=df
for item in lista_blanca:
    metrics_df=metrics_df.loc[metrics_df['ip']!=item]

long=len(metrics_df)
valores=range(1,long+1)
metrics_df['index']=valores

metrics_df.to_csv(r'FP_anomalies_target1.csv',index=False)
"""
#Load anomalies' file
metrics_df=pd.read_csv("/bndf/adf/FP_anomalies_target-2022.04.28.csv")
outliers=metrics_df.loc[metrics_df['anomaly']==-1]
#print(outliers)

# It is get all the infected footprints
print("Number of infected footprints:",len(outliers))

# It is get all the infected hosts, set is used to remove duplicates
print("Number of infected hosts:",len(set(outliers['ip'])))
print("Times hosts have been cataloged:")

# For each IP count the number of appearances 
a=Counter(outliers['ip'])
a=dict(a)
#print(a)

print("Minimum number of times detected:",min(a.values()))
print("Maximum times detected:",max(a.values()))
print("Average times detected:",statistics.mean(a.values()))
from datetime import datetime
current_date=ConvertTime(datetime.now())

whitelist_file = open("/bndf/whitelist.txt", "r")

whitelist = whitelist_file.readlines()

output = open("/bndf/adf/domains_dga-"+current_date+".txt", "a") 
output_abs = open("/bndf/adf/domains_dga_abstract" + current_date + ".txt", "a") 
for item in outliers.index:
    #Get ip, gte y lte
    ip = metrics_df['ip'][item]
    ip_time=[metrics_df['ip'][item],metrics_df['@timestamp'][item]]
    
    #gte=datetime.datetime.strptime(ip_time[1],'%Y-%m-%dT%H:%M:%SZ')
    gte = dateutil.parser.isoparse(ip_time[1])
    lte = gte + dt.timedelta(hours=1)
    
    #lte=(gte+datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")   
    day=gte.strftime("%Y.%m.%d")
    timestamp=gte.strftime("%Y.%m.%d")
    indice="logstash-dns-"+day
    uri = "http://elasticsearch:9200/"+indice+"/_search"
    
    gte = ConvertTime(gte)
    lte = ConvertTime(lte)
    
    print(gte)
    print(lte)
    
    query=queries.statement_pNX0(ip_time[0],gte,lte)
    r = requests.get(uri,headers=HEADERS, data=query).json()
    num_sites=r["aggregations"]["filter_type"]["filter_ip"]["unique_ids"]["value"]
    if num_sites>65000:
        num_sites=65000
    print("Num Sitios: " + str(num_sites))
    if num_sites!=0:       
        query=queries.statement_pNX(ip_time[0],num_sites,gte,lte)
        #print("aqui")
        r = requests.get(uri,headers=HEADERS, data=query).json()
        #print(r)
        #for item in r["aggregations"]["filter_type"]["filter_ip"]["NX_filter"]["sld_filter"]["buckets"]:
        #    print(item['key'])
        #    P9_1=item['key'].rsplit(sep='.',maxsplit=2)
        P9_1=[item['key'].rsplit(sep='.',maxsplit=2)
              for item in r["aggregations"]["filter_type"]["filter_ip"]["NX_filter"]["sld_filter"]["buckets"]]
        #P9_1b=[item['key'].rsplit(sep='.',maxsplit=2)
        #      for item in r["aggregations"]["filter_type"]["filter_ip"]["NX_filter"]["tld_filter"]["buckets"]]
        sites=[ row[1] + "." + row[2] if len(row)>2 else row[0] + "." + row[1] if len(row)==2 else row[0] for row in P9_1]
        tlds=[ row[1] + "." + row[2] if len(row)>2 else row[0] + "." + row[1] if len(row)==2 else row[0] for row in P9_1]
        sites=set(sites)
        #print(sites)
    
        #contar bo
        #ii=0;
        sites_dga=[]
        #output.write(metrics_df['ip'][item]+metrics_df['@timestamp'][item]+"\n")
        #print(colored(metrics_df['ip'][item],"red"),colored(metrics_df['@timestamp'][item],"red"))
        #sites_dga.append(metrics_df['ip'][item])
        totalnumber=0
        totalbots=0
        for item1 in sites:
            if item1!="":
                totalnumber+=1
                site=item1.rsplit(sep=".",maxsplit=2)[0]
                metrics = getMetrics(site)
                v_rma = rma(metrics[0],metrics[1],metrics[2],metrics[3])
                metrics_str=str(metrics).translate({ord(i): None for i in '() '})
                metrics_str=metrics_str.replace(',',';')
                print(">>>" + gte + ";" + ip + ";" + str(item1) + ";" + metrics_str + ";" + str(v_rma))
                output.write(gte + ";" + str(item1) + ";" + metrics_str + ";" + str(v_rma)+"\n")
                #print(ssl.get_server_certificate((v_rma, 443)))
                if (v_rma==1): # Is iqual to Bot
                    totalbots+=1
                    sites_dga.append(item1)
                    
                    #ii+=1
                    #print(ii,metrics_df['ip'][item],item1,metricas[3])
        if (totalnumber>0):
            output_abs.write(gte + ";" + ip + ";" + str(totalnumber) + ";" + str(totalbots) + ";" + str(totalbots/totalnumber) + ";" + str(sites_dga)+"\n")
        #print(metrics,v_rma)
        #print(sites_dga)
        #output.write(str(sites_dga)+"\n")
    else:
        print("Theres is no site")
              
output.close()
