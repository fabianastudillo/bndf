#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jan 15 20:55:45 2021

@author: Vicente Quezada
@modified by: Fabian Astudillo <fabian.astudillos@ucuenca.edu.ec>
"""
__author__ = "Fabian Astudillo <fabian.astudillos@ucuenca.edu.ec>"
__version__ = "1.0"

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
from datetime import datetime
from datetime import date
import datetime as dt
import dateutil.parser
import re
from itertools import groupby
import ssl
import os
from os.path import exists
from argparse import ArgumentParser
import warnings
import logging

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


class AntiDomainGenerationAlgorithm:
    """This class check if a domain was generated using a Domain Generation Algorithm"""
     
    def __init__(self, all_fingerprints=True, clean_index=False):
        #from datetime import datetime
        #current_date=ConvertTime(datetime.now())
        self.__clean_index = clean_index
        if (all_fingerprints):
            logging.info("Enable all fingerprints")
        else:
            logging.info("Only the last fingerprints")
        self.__ip_elasticsearch__="elasticsearch"
        today = date.today()
        self.current_date = today.strftime("%Y.%m.%d")
        if (all_fingerprints):
            self.fpano_filename = "/bndf/adf/FP_anomalies_target-last.csv"
        else:
            self.fpano_filename = "/bndf/adf/predictions-last.csv"
        if not exists(self.fpano_filename):
            logging.warning("File not exist: " + self.fpano_filename)
            exit(1)
        self.__filename_domains__="/bndf/adf/domains_dga_" + (self.current_date if all_fingerprints else "last") + ".csv"
        self.__filename_domains_abs__="/bndf/adf/domains_dga_abstract_" + (self.current_date if all_fingerprints else "last") + ".csv"
            
        self.__HEADERS__ = {
            'Content-Type': 'application/json'
        }
        
    def ConvertTime(self,time):
        return(time.strftime("%Y-%m-%dT%H:%M:%SZ"))

    # Randomness Measuring Algorithm
    # ln=len of word; max_cons
    def __RMA(self, ln,max_cons,max_voc,entropy):
        if (entropy <= 2) and (ln<5):
            category=0 #"clean"
        elif (entropy>3.24):
            category=1 #"bot"
        elif (max_cons >= 4) or (max_voc >=4):
            category=1 #"bot"
        else:
            category=0 #"clean"
        return(category)
        
    def __GetMetrics(self, word):
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

    def Convert(self,a):
        it = iter(a)
        res_dct = dict(zip(it, it))
        return res_dct

    def ConnectToElasticsearch(self):
        # TODO: Add anomaly file as argument 

        #socks.set_default_proxy(socks.SOCKS5, "localhost", 9000)
        #socket.socket = socks.socksocket

        try:
            self.__es = Elasticsearch([{'host':self.__ip_elasticsearch__,'port':9200,}])
            logging.info ("Connected")
        except Exception as ex:
            logging.warning ("Error:", ex)
            exit(0)
        
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

    def LoadAnomalies(self):
        #Load anomalies' file
        self.__metrics_df__ = pd.read_csv(self.fpano_filename)
        self.__outliers__= self.__metrics_df__.loc[self.__metrics_df__['anomaly']==-1]

        # It is get all the infected footprints
        logging.info("Number of infected footprints:",len(self.__outliers__))

        # It is get all the infected hosts, set is used to remove duplicates
        logging.info("Number of infected hosts:",len(set(self.__outliers__['ip'])))
        logging.info("Times hosts have been cataloged:")

        # For each IP count the number of appearances 
        a=Counter(self.__outliers__['ip'])
        a=dict(a)
        #print(a)

        logging.info("Minimum number of times detected:",min(a.values()))
        logging.info("Maximum times detected:",max(a.values()))
        logging.info("Average times detected:",statistics.mean(a.values()))
        
    def LoadWhitelist(self):
        whitelist_file = open("/bndf/whitelist.txt", "r")
        #self.__whitelist = [line[:-1] for line in whitelist_file]
        self.__whitelist = [line.replace("\n", "") for line in whitelist_file]
        print(self.__whitelist)

        #whitelist = whitelist_file.readlines()

    def Check(self):
        if os.path.exists(self.__filename_domains__):
            os.remove(self.__filename_domains__)
        output = open(self.__filename_domains__, "a") 
        if os.path.exists(self.__filename_domains_abs__):
            os.remove(self.__filename_domains_abs__)
        output_abs = open(self.__filename_domains_abs__, "a") 
        output_abs.write("@timestamp,ip,member,totalnumber,totalbots,botrate,sites\n")
        for item in self.__outliers__.index:
            #Get ip, gte y lte
            ip = self.__metrics_df__['ip'][item]
            ip_time=[self.__metrics_df__['ip'][item],self.__metrics_df__['@timestamp'][item]]
            
            #gte=datetime.datetime.strptime(ip_time[1],'%Y-%m-%dT%H:%M:%SZ')
            gte = dateutil.parser.isoparse(ip_time[1])
            lte = gte + dt.timedelta(hours=1)
            
            #lte=(gte+datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")   
            day=gte.strftime("%Y.%m.%d")
            timestamp=gte.strftime("%Y.%m.%d")
            indice="logstash-dns-"+day
            uri = "http://" + self.__ip_elasticsearch__ + ":9200/"+indice+"/_search"
            
            gte = self.ConvertTime(gte)
            lte = self.ConvertTime(lte)
            
            logging.info(gte)
            logging.info(lte)
            
            query=queries.statement_pNX0(ip_time[0],gte,lte)
            r = requests.get(uri,headers=self.__HEADERS__, data=query).json()
            #TODO: We have to add the error when the index does not exists
            num_sites=r["aggregations"]["filter_type"]["filter_ip"]["unique_ids"]["value"]
            if num_sites>65000:
                num_sites=65000
            logging.info("Num Sitios: " + str(num_sites))
            if num_sites!=0:       
                query=queries.statement_pNX(ip_time[0],num_sites,gte,lte)
                #print("aqui")
                r = requests.get(uri,headers=self.__HEADERS__, data=query).json()
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
                sites = [i for i in sites if not (i in self.__whitelist or i == "")]
                for item1 in sites:
                    if item1!="":
                        totalnumber+=1
                        site=item1.rsplit(sep=".",maxsplit=2)[0]
                        metrics = self.__GetMetrics(site)
                        v_rma = self.__RMA(metrics[0],metrics[1],metrics[2],metrics[3])
                        metrics_str=str(metrics).translate({ord(i): None for i in '() '})
                        metrics_str=metrics_str.replace(',',';')
                        logging.info(">>>" + gte + ";" + ip + ";" + str(item1) + ";" + metrics_str + ";" + str(v_rma))
                        output.write(gte + ";" + str(item1) + ";" + metrics_str + ";" + str(v_rma)+"\n")
                        #print(ssl.get_server_certificate((v_rma, 443)))
                        if (v_rma==1): # Is iqual to Bot
                            totalbots+=1
                            sites_dga.append(item1)
                            
                            #ii+=1
                            #print(ii,metrics_df['ip'][item],item1,metricas[3])
                if (totalbots>0):
                    date_from=dateutil.parser.isoparse(gte)
                    index='logstash-dns-' + date_from.strftime("%Y.%m.%d")
                    query=queries.getMember(ip)
                    uri_search = "http://" + self.__ip_elasticsearch__ + ":9200/"+index+"/_search"
                    r = requests.get(uri_search,headers=self.__HEADERS__, data=query).json()
                    if (len(r["aggregations"]["members"]["buckets"])>0):
                        membername=r["aggregations"]["members"]["buckets"][0]["key"]
                    else:
                        membername="Not found"
                    output_abs.write(gte + "," + ip + "," + membername + "," + str(totalnumber) + "," + str(totalbots) + "," + str(totalbots/totalnumber) + ",\"" + str(sites_dga)+"\"\n")
                #print(metrics,v_rma)
                #print(sites_dga)
                #output.write(str(sites_dga)+"\n")
            else:
                logging.warning("Theres is no site")
        output.close()
        
    def UploadToElasticsearch(self):
        self.ConnectToElasticsearch()
        # self.__filename_domains_abs__
        if not exists(self.__filename_domains_abs__):
            logging.info("File not exist: " + self.__filename_domains_abs__)
            exit(1)
            
        today = datetime.now().replace(minute=0, second=0, microsecond=0)

        df=pd.read_csv(self.__filename_domains_abs__)

        #index_fp="last-bots-" + today.strftime("%Y")
        index_fp="last-bots-" + today.strftime("%Y-%m-%d-%H")

        if (self.__clean_index):
            self.RemoveIndex(index_fp)

        metrics_df=pd.read_csv(self.__filename_domains_abs__)

        #for item in metrics_df:
        #    print(item)

        final_data=[["@timestamp",time,
                        "ip",ip,"member",member,"totalnumber",totalnumber,
                        "totalbots",totalbots,"botrate",botrate,"sites",sites ] 
                        for time,ip,member,totalnumber,totalbots,botrate,sites 
                        in zip(metrics_df['@timestamp'],metrics_df['ip'],metrics_df['member'],
                            metrics_df['totalnumber'],metrics_df['totalbots'],
                                metrics_df['botrate'],metrics_df['sites'])]

        #logging.info(final_data)
        #datos_finales_json=[item for item in metrics_df]
        json_final_data=[self.Convert(item) for item in final_data]

        #logging.info(json_final_data)
        print("Uploading")
        ii = 1
        for item in json_final_data:
        #    logging.info(item)
            res=self.__es.index(index=index_fp,id=ii,body=item)
            ii=ii+1
        #logging.info("ii> "+str(ii))
        ####
        #init_notebook_mode(connected=True)
        warnings.filterwarnings('ignore')
    
    def RemoveIndex(self, index_fp):
        try:
            res=self.__es.indices.delete(index=index_fp)
        except:
            pass
        
    def Run(self):
        self.ConnectToElasticsearch()
        self.LoadAnomalies()
        self.LoadWhitelist()
        self.Check()

def main():
    parser = ArgumentParser(
            description='Anti Domain Genaration Algorithm Detection to detect if the dns are generated using an algorithm.'
                        + 'If there is no option, it processes the fingerprints of the last hour using the prediction model. ',
            epilog="This script generates a file with the infected hosts.")

    # Add the arguments to the parser
    parser.add_argument("-a", "--all", dest="all", action='store_true', required=False,
    help="Process the fingerprints from the anomaly detection algorithm")
    parser.add_argument("-l", "--last", dest="last", action='store_true', required=False,
    help="Process the fingerprints of the last hour using prediction model")
    parser.add_argument("-u", "--upload", dest="upload", action='store_true', required=False,
    help="Upload the detected bots to elasticsearch")
    parser.add_argument("-r", "--removeindex", dest="removeindex", action='store_true', required=False,
    help="Remove the last index from elasticsearch")



    #args = vars(ap.parse_args())
    args = parser.parse_args()
    
    
    all = False
    if args.all:
        all = True
    elif args.last:
        all = False
    adga=AntiDomainGenerationAlgorithm(all_fingerprints=all)
    if (args.all or args.last):
        adga.Run()
#    elif args.last:
#        all = False
    if args.upload:
        adga.UploadToElasticsearch()
        
    if args.removeindex:
        today = datetime.now().replace(minute=0, second=0, microsecond=0)
        index_fp="last-bots-" + today.strftime("%Y-%m-%d-%H")
        adga.RemoveIndex(index_fp)
        
if __name__ == "__main__":
    main()