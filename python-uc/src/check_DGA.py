#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jan 15 20:55:45 2021

@author: Vicente Quezada
@modified by: Fabian Astudillo <fabian.astudillos@ucuenca.edu.ec>
"""

import pandas as pd
import datetime
import queries
import socket
import socks
import requests
from elasticsearch import Elasticsearch
from collections import Counter
import statistics
import math
import numpy as np
from tabulate import tabulate
from termcolor import colored

#check por DGA
voc=["a","e","i","o","u","y","A","E","I","O","U","Y"]
cons=["b","c", "d", "f", "g", 
             "h", "j", "k", "l", "m", 
             "n", "ñ", "p", "q", "r", 
             "s", "t", "v", "w", "x", "z",
             "B","C", "D", "F", "G", 
             "H", "J", "K", "L", "M", 
             "N", "Ñ", "P", "Q", "R", 
             "S", "T", "V", "W", "X", "Z"]


def rma(ln,max_cons,max_voc,entropy):
    if (entropy <= 2) and (ln<5):
        category="clean"
    elif (entropy>3.24):
        category="bot"
    elif (max_cons >= 4) or (max_voc >=4):
        category="bot"
    else:
        category="clean"
    return(category)
    
def getMetrics(word):
    max_voc=0
    max_cons=0
    con_voc=0
    con_cons=0
    
    ln = len(word)
    
    l_ant="n"
    for letter in word:
        if letter in voc:
            if l_ant=="c":
                if (con_cons > max_cons):
                    max_cons=con_cons
                con_cons=0
            con_voc=con_voc+1 
            l_ant="v"
        elif letter in cons:
            if l_ant=="v":
                if (con_voc > max_voc):
                    max_voc=con_voc
                con_voc=0
            con_cons=con_cons+1
            l_ant="c"
        else:
            if l_ant=="c":
                if (con_cons > max_cons):
                    max_cons=con_cons
                con_cons=0
            elif l_ant=="v":
                if (con_voc > max_voc):
                    max_voc=con_voc
                con_voc=0
            l_ant="n"
    
    if l_ant=="c":
        if (con_cons > max_cons):
            max_cons=con_cons
    elif l_ant=="v":
        if (con_voc > max_voc):
            max_voc=con_voc
    
    num_elem = len(word)
    prob_elem = 1/num_elem
    elem_set = set(word)
    c_pro_elem = []
    for element in elem_set:
        c_pro_elem.append(word.count(element))
    f_pro=[i*prob_elem for i in c_pro_elem]
    entropy=0
    for prob in f_pro:
        entropy=entropy+(prob*math.log(prob,2))
    entropy=round(entropy*(-1),2)
    return(ln,max_cons,max_voc,entropy)
#

# TODO: Add anomaly file as argument 

socks.set_default_proxy(socks.SOCKS5, "localhost", 9000)
socket.socket = socks.socksocket

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
metrics_df=pd.read_csv("./FP_anomalies_target1.csv")
outliers=metrics_df.loc[metrics_df['anomaly']==-1]

print("Number of infected footprints:",len(outliers))
print("Number of infected hosts:",len(set(outliers['ip'])))
print("Times hosts have been cataloged:")
a=Counter(outliers['ip'])
a=dict(a)

print("Minimum number of times detected:",min(a.values()))
print("Maximum times detected:",max(a.values()))
print("Average times detected:",statistics.mean(a.values()))

output = open("dominios_dga.txt", "w") 
for item in outliers['index']:
    #Get ip, gte y lte
    ip_time=[metrics_df['ip'][item-1],metrics_df['@timestamp'][item-1]]
    
    gte=datetime.datetime.strptime(ip_time[1],'%Y-%m-%dT%H:%M:%SZ')
    lte=(gte+datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")   
    indice="logstash-dns-"+gte.strftime("%Y.%m.%d")
    uri = "http://elasticsearch:9200/"+indice+"/_search"
    
    query=consultas.statement_pNX0(ip_time[0],gte.strftime("%Y-%m-%dT%H:%M:%SZ"),lte)
    r = requests.get(uri,headers=HEADERS, data=query).json()
    num_sitios=r["aggregations"]["filter_type"]["filter_ip"]["unique_ids"]["value"]
    if num_sitios>65000:
        num_sitios=65000
    if num_sitios!=0:       
        query=consultas.statement_pNX(ip_time[0],num_sitios,gte.strftime("%Y-%m-%dT%H:%M:%SZ"),lte)
        r = requests.get(uri,headers=HEADERS, data=query).json()
        P9_1=[item['key'].rsplit(sep='.',maxsplit=2) for item in r["aggregations"]["filter_type"]["filter_ip"]["Filtro_NX"]["Filtro_dls"]["buckets"]]
        sitios=[row[1]+"."+row[2] if len(row)>2 else row[0]+"."+row[1] if len(row)==2 else row[0] for row in P9_1]
        sitios=set(sitios)
    
    #contar bo
    #ii=0;
    sitios_dga=[]
    output.write(metrics_df['ip'][item-1]+metrics_df['@timestamp'][item-1]+"\n")
    #print(colored(metrics_df['ip'][item-1],"red"),colored(metrics_df['@timestamp'][item-1],"red"))
    #sitios_dga.append(metrics_df['ip'][item-1])
    for item1 in sitios:
        if item1!="":
            sit=item1.rsplit(sep=".",maxsplit=2)[0]
            metricas = getMetrics(sit)
            v_rma = rma(metricas[0],metricas[1],metricas[2],metricas[3])
            if (v_rma=="bot"):
                sitios_dga.append(item1)
                #ii+=1
                #print(ii,metrics_df['ip'][item-1],item1,metricas[3])
    #print(metricas,v_rma)
    #print(sitios_dga)
    output.write(str(sitios_dga)+"\n")
              
output.close()