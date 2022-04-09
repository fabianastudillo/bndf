#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Oct  6 09:55:19 2020

This script generate the fingerprint for all the DNS packets, from
a specific hour of a date. The enter parameters are de date and hour
to process.

@author: Vicente Quezada
@modified by: Fabian Astudillo-Salinas <fabian.astudillos@ucuenca.edu.ec>
"""

from pathlib import Path
import os.path
import requests
from elasticsearch import Elasticsearch
from statistics import mean
import pandas as pd
import datetime
import dateutil.parser
import os
import queries
import numpy as np
import re
from argparse import ArgumentParser
from os import path
import logging
import pdb; pdb.set_trace()

class FingerprintGenerator:
    """This class generates the fingerprints"""

    def __init__(self, ip_elasticsearch, datestep, fn_whitelist):
       # logging.basicConfig(filename='/var/log/bndf/fingerprints.log', filemode='a', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',level=logging.INFO)

        self.__ip_elasticsearch=ip_elasticsearch
        self.__white_list=[ ]

        self.__output_dir = Path('/var/log/bndf/')

        self.__output_dir.mkdir(parents=True, exist_ok=True)
        
        logging.info("Fingerprint Generator")
        if (fn_whitelist and os.path.exists(fn_whitelist)):
            with open(fn_whitelist) as f:
                print ("Open white list")
                for line in f:
                    line = line.strip()
                    self.__white_list.append(line)
        else:
            raise Exception("Whitelist file not found with the name " + fn_whitelist)

        try:
            self.__elasticsearch = Elasticsearch([{'host':ip_elasticsearch,'port':9200,}])
            print ("- The application is connected to elasticsearch server")
        except Exception as ex:
            raise ex

        self.SetDatestep(datestep)

    def ConvertTime(self,time):
        return(time.strftime("%Y-%m-%dT%H:%M:%SZ"))
    
    def Convert(self,a):
        it = iter(a)
        res_dct = dict(zip(it, it))
        return res_dct

    def GetIndices(self):
        for index in self.__elasticsearch.indices.get('logstash-dns-*'):
            print(index)
        print("")
    
    def SetDatestep(self, datestep):
        self.__datestep=datestep
        #list existing DNS indexes
        self.__dns_indices=[]
        logging.info("- Loading the indices from elasticsearh")
        #logging.info("- The loaded indices are ", end = '')
        logging.info("- The loaded indices are ")
        try:
            for index in self.__elasticsearch.indices.get('logstash-dns-' + self.__datestep.strftime("%Y.%m.%d")):
                #logging.info(index, end = ',')
                logging.info(index)
                self.__dns_indices.append(index)
            logging.info("")
        except Exception as ex:
            raise ex
        
    def getHostByHour(self):
        indexs=1
        matriz_num_host=[]
        for indice in self.__dns_indices:
            #hosts_number=[]
            gte=self.ConvertTime(self.__datestep)
            lte=self.ConvertTime(self.__datestep+datetime.timedelta(hours=1))

            HEADERS = {
            'Content-Type': 'application/json'
            }
            uri = "http://" + self.__ip_elasticsearch + ":9200/"+indice+"/_search"
            print(uri)
            #number of hosts per hour
            query=queries.statement_p1_1(gte,lte)
            r = requests.get(uri,headers=HEADERS, data=query).json()
            num_host=r["aggregations"]["filter_type"]["num_hosts"]["value"]
            
            try:
                print(self.__datestep.strftime("%Y-%m-%d; %H:%M:%S")+';'+str(num_host))
            
                with open('/var/log/bndf/num_host-' + self.__datestep.strftime("%Y-%m-%d") + '.csv', 'a') as f:
                    f.write(self.__datestep.strftime("%Y-%m-%d; %H:%M:%S")+';'+str(num_host))
            except Exception as inst:
                
                print(type(inst))
                print(inst.args)
                print(inst)
                exit(0)

    def Generate(self):
        # try:
        #     res=es.indices.delete(index='fingerprints')
        # except:
        #     pass

        # """
        # # Agregar un parámetro de entrada en el script que permita eliminar los registros

        # try:
        #     os.remove("fingerprints.csv")
        # except:
        #     pass

        # try:
        #     os.remove("num_host.csv")
        # except:
        #     pass

        # """

        # # ii = 1
        indexs=1

        matriz_num_host=[]
        for indice in self.__dns_indices:
            hosts_number=[]
            #indice_date=indice[13:24]
            #print ("Indice: " + indice)
            #indice_date=indice.split("-")[2]
            #indice_date=self.__datestep.split(".")
            #t1=datetime.datetime(
            #    int(indice_date[0]),
            #    int(indice_date[1]),
            #    int(indice_date[2]),
            #    00,00,00)
            
    #        hours=[]
    #        for i in range(24):
    #            hours.append(t1+datetime.timedelta(hours=i))
            
    #       for item_hours in hours:
                #gte=ConvertTime(item_hours)
                #lte=ConvertTime(item_hours+datetime.timedelta(hours=1))
            #hour = int(args.hour)
            gte=self.ConvertTime(self.__datestep)
            lte=self.ConvertTime(self.__datestep+datetime.timedelta(hours=1))

            HEADERS = {
                'Content-Type': 'application/json'
            }
            uri = "http://" + self.__ip_elasticsearch + ":9200/"+indice+"/_search"

            #number of hosts per hour
            logging.info("Get Number of hosts")
            query=queries.statement_p1_1(gte,lte)
            r = requests.get(uri,headers=HEADERS, data=query).json()
            num_host=r["aggregations"]["filter_type"]["num_hosts"]["value"]

            #hosts_number.append(num_host)
            try:
                with open('/var/log/bndf/num_host-' + self.__datestep.strftime("%Y-%m-%d") + '.csv', 'w') as f:
                    f.write(self.__datestep.strftime("%Y-%m-%d; %H:%M:%S")+';'+str(num_host))
            #print("num_host= " + str(num_host))
                if num_host!=0:
                    #Number of DNS requests per hour for each host
                    #Considering that each host has made a minimum of 100 requests
                    P1=[]
                    try:
                        query=queries.statement_p1(num_host,gte,lte)
                        r = requests.get(uri,headers=HEADERS, data=query).json()
                        ips=[]
                        logging.info("Get P1")
                        for item in r["aggregations"]["filter_type"]["get_ip"]["buckets"]:
                            #print(self.__white_list)
                            if (item['key'] in self.__white_list) == False:
                                #print(item['key'])
                                ips.append(item['key'])
                                P1.append(item['doc_count'])
                    except Exception as inst:
                        logging.warning(type(inst).__name__ +  " | "  + str(inst))
                        print(r)
                        exit(0)
                        
                    P1_1=[]
                    for i in range(len(P1)):
                        P1_1.append(gte)
                    
                    #number of dns requests per hour
                    P2=[]
                    logging.info("Get P2")
                    for item in ips:
                        try:
                            query=queries.statement_p2(item,gte,lte)
                            r = requests.get(uri,headers=HEADERS, data=query).json()
                            P2.append(r["aggregations"]["filter_type"]["filter_ip"]["unique_ids"]["value"])
                        except Exception as inst:
                            logging.warning(type(inst).__name__ +  " | "  + str(inst))
                            print(r)
                            exit(0)
                    
                    #max requests for a single domain
                    P3=[]
                    logging.info("Get P3")
                    for item,item2 in zip(ips,P2):
                        P4_1=[]
                        try:
                            query=queries.statement_p3(item,item2,gte,lte)
                            r = requests.get(uri,headers=HEADERS, data=query).json()
                            if r["aggregations"]["filter_type"]["filter_ip"]["dnss"]["buckets"] != []:
                                P3.append(r["aggregations"]["filter_type"]["filter_ip"]["dnss"]["buckets"][0]["doc_count"])
                            else:
                                P3.append(0)
                        except Exception as inst:
                            logging.warning(type(inst).__name__ +  " | "  + str(inst))
                            print(r)
                            exit(0)

                    #average requests per minute
                    P4=[]
                    #highest number of requests per minute
                    P5=[]
                    logging.info("Get P4 and P5")
                    for item  in ips:
                        P4_1=[]
                        try:
                            query=queries.statement_p4(item,gte,lte)
                            r = requests.get(uri,headers=HEADERS, data=query).json()
                            if r["aggregations"]["filter_type"]["filter_ip"]["times"]["buckets"]!=[]:       
                                P4_1=[item1['doc_count'] for item1 in r["aggregations"]["filter_type"]["filter_ip"]["times"]["buckets"]]
                                P4.append(round(mean(P4_1),4))
                                P5.append(max(P4_1))
                            else:
                                P4.append(0)
                                P5.append(0)
                        except Exception as inst:
                            logging.warning(type(inst).__name__ +  " | "  + str(inst))
                            print(r)
                            exit(0)

                    #MX per hour
                    P6=[]
                    logging.info("Get P6")
                    for item in ips:
                        try:
                            query=queries.statement_p6(item,gte,lte)
                            r = requests.get(uri,headers=HEADERS, data=query).json()
                            P6.append(r["aggregations"]["filter_type"]["filter_ip"]["filter_type"]["doc_count"])
                        except Exception as inst:
                            logging.warning(type(inst).__name__ +  " | "  + str(inst))
                            print(r)
                            exit(0)
                    
                    #PTR per hour
                    P7=[]
                    logging.info("Get P7")
                    for item in ips:
                        try:
                            query=queries.statement_p7(item,gte,lte)
                            r = requests.get(uri,headers=HEADERS, data=query).json()
                            P7.append(r["aggregations"]["filter_type"]["filter_ip"]["filter_type"]["doc_count"])
                        except Exception as inst:
                            logging.warning(type(inst).__name__ +  " | "  + str(inst))
                            print(r)
                            exit(0)
                    
                    # num different servers consulted per hour
                    P8=[]
                    logging.info("Get P8")
                    for item in ips:
                        try:
                            query=queries.statement_p8(item,gte,lte)
                            r = requests.get(uri,headers=HEADERS, data=query).json()
                            P8.append(r["aggregations"]["filter_type"]["filter_ip"]["unique_ids"]["value"])
                        except Exception as inst:
                            logging.warning(type(inst).__name__ +  " | "  + str(inst))
                            print(r)
                            exit(0)
                    
                    # TLD consulted per hour
                    P9=[] 
                    logging.info("Get P9")
                    for item in ips:
                        try:
                            query=queries.statement_p9(item,gte,lte)
                            r = requests.get(uri,headers=HEADERS, data=query).json()
                            P9.append(r["aggregations"]["filter_type"]["filter_ip"]["unique_ids"]["value"])
                        except Exception as inst:
                            logging.warning(type(inst).__name__ +  " | "  + str(inst))
                            print(r)
                            exit(0)

                    # SLD queried per hour
                    P10=[]
                    logging.info("Get P10")
                    for item in ips:
                        try:
                            query=queries.statement_p10(item,gte,lte)
                            r = requests.get(uri,headers=HEADERS, data=query).json()
                            P10.append(r["aggregations"]["filter_type"]["filter_ip"]["unique_ids"]["value"])
                        except Exception as inst:
                            logging.warning(type(inst).__name__ +  " | "  + str(inst))
                            print(r)
                            exit(0)
                            
                    # Uniqueness ratio per hour
                    P11=[round(ai/bi,4) if bi!=0 else 0 for ai,bi in zip(P1,P2)]
                    
                    #NXDOMAIN per hour
                    P12=[]
                    logging.info("Get P12")
                    for item in ips:
                        try:
                            query=queries.statement_p12(item,gte,lte)
                            r = requests.get(uri,headers=HEADERS, data=query).json()
                            P12.append(r["aggregations"]["filter_type"]["filter_ip"]["filter_type"]["doc_count"])
                        except Exception as inst:
                            logging.warning(type(inst).__name__ +  " | "  + str(inst))
                            print(r)
                            exit(0)
                    
                    #num different cities per hour
                    P13=[]
                    logging.info("Get P13")
                    for item in ips:
                        try:
                            query=queries.statement_p13(item,gte,lte)
                            r = requests.get(uri,headers=HEADERS, data=query).json()
                            P13.append(r["aggregations"]["filter_type"]["filter_ip"]["unique_ids"]["value"])
                        except Exception as inst:
                            logging.warning(type(inst).__name__ +  " | "  + str(inst))
                            print(r)
                            exit(0)
                        
                    #num different countries per hour
                    P14=[]
                    logging.info("Get P14")
                    for item in ips:
                        try:
                            query=queries.statement_p14(item,gte,lte)
                            r = requests.get(uri,headers=HEADERS, data=query).json()
                            P14.append(r["aggregations"]["filter_type"]["filter_ip"]["unique_ids"]["value"])
                        except Exception as inst:
                            logging.warning(type(inst).__name__ +  " | "  + str(inst))
                            print(r)
                            exit(0)
                    
                    #flow rate per hour
                    P15=[]
                    logging.info("Get P15")
                    for item in ips:
                        try:
                            query=queries.statement_p15(item,gte,lte)
                            r = requests.get(uri,headers=HEADERS, data=query).json()
                            P15.append(r["aggregations"]["filter_type"]["filter_ip"]["filter_type"]["doc_count"])
                        except Exception as inst:
                            logging.warning(type(inst).__name__ +  " | "  + str(inst))
                            print(r)
                            exit(0)

                    P15=[round(ai/bi,4) if bi!=0 else 0 for ai,bi in zip(P2,P15)]
                    
                    #print(P1_1,ips,P1,P2,P3,P4,P5,P6,P7,P8,P9,P10,P11,P12,P15)
                    """
                    datos_finales=[["@timestamp",time,
                                    "ip",ip,"p1",p1,"p2",p2,"p3",p3,"p4",p4,"p5",p5,
                                    "p6",p6,"p7",p7,"p8",p8,"p9",p9,"p10",p10,"p11",
                                    p11,"p12",p12,"p13",p13,"p14",p14,"p15",p15] 
                                    for time,ip,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15 
                                    in zip(P1_1,ips,P1,P2,P3,P4,P5,P6,P7,P8,P9,P10,P11,P12,P13,P14,P15)]
                            
                    datos_finales_json=[Convert(item) for item in datos_finales]

                    for item in datos_finales_json:
                        res=es.index(index='fingerprints',doc_type='fingerprints',id=ii,body=item)
                        ii=ii+1
                    """
                        
                    index_array=[j for j in range(indexs,indexs+len(P1))]
                    indexs=indexs+len(P1)
                    data={"@timestamp":P1_1,"ip":ips,'P1':P1,'P2':P2,'P3':P3,'P4':P4,'P5':P5,
                            'P6':P6,'P7':P7,'P8':P8,'P9':P9,'P10':P10,
                            'P11':P11,'P12':P12,'P13':P13,'P14':P14,'P15':P15}
                    
                    df=pd.DataFrame(data,columns=['@timestamp','ip','P1','P2','P3','P4','P5',
                                                    'P6','P7','P8','P9','P10',
                                                    'P11','P12','P13','P14','P15'])
                    logging.info("Save fingerprint ...")
                    path =  '/var/log/bndf/fingerprints-' + self.__datestep.strftime("%Y-%m-%d") + '.csv'
                    df.to_csv(path, index=None, mode="a", header=not os.path.isfile(path))
                    logging.info("Fingerprint saved")
            except Exception as inst:
                #TODO: manage this error {'error': {'root_cause': [{'type': 'circuit_breaking_exception', 'reason': '[parent] Data too large, data for [<reused_arrays>] would be [511424472/487.7mb], which is larger than the limit of [510027366/486.3mb], real usage: [500220696/477mb], new bytes reserved: [11203776/10.6mb], usages [request=11222208/10.7mb, fielddata=24381797/23.2mb, in_flight_requests=1378/1.3kb, model_inference=0/0b, eql_sequence=0/0b, accounting=8138920/7.7mb]', 'bytes_wanted': 511424472, 'bytes_limit': 510027366, 'durability': 'PERMANENT'}], 'type': 'search_phase_execution_exception', 'reason': 'all shards failed', 'phase': 'query', 'grouped': True, 'failed_shards': [{'shard': 0, 'index': 'logstash-dns-2022.04.01', 'node': 'IFUMFOfcSXGOsS40NdgGjA', 'reason': {'type': 'circuit_breaking_exception', 'reason': '[parent] Data too large, data for [<reused_arrays>] would be [511424472/487.7mb], which is larger than the limit of [510027366/486.3mb], real usage: [500220696/477mb], new bytes reserved: [11203776/10.6mb], usages [request=11222208/10.7mb, fielddata=24381797/23.2mb, in_flight_requests=1378/1.3kb, model_inference=0/0b, eql_sequence=0/0b, accounting=8138920/7.7mb]', 'bytes_wanted': 511424472, 'bytes_limit': 510027366, 'durability': 'PERMANENT'}}]}, 'status': 429}
	            #TODO: Agregar error de manera correcta
                #logging.warning("Fingerprint not generated for "+self.__datestep.strftime("%Y-%m-%d; %H:%M:%S")+ "-------|" + r)
                print(type(inst))
                print(inst.args)
                print(inst)
                exit(0)

        #matriz_num_host.append(hosts_number)
        #print(matriz_num_host)
        #M_N_H=np.array(matriz_num_host)
        #M_N_H=M_N_H.transpose()
        #np.savetxt("/var/log/bndf/num_host-" + self.__datestep.strftime("%Y-%m-%d") + ".csv",M_N_H,fmt="%d",delimiter=",")

        # while True:
        #     i=0

def main():
    parser = ArgumentParser(
            description='Fingerprint generator',
            epilog="This script generate the fingerprint for all the dns packets, from"
                    "a specific hour of a date. The enter parameters are de date and hour"
                    "to process.")

    # Add the arguments to the parser
    parser.add_argument("-d", "--date", dest="date", required=False,
    help="The date to be processed in ISO format example '2021-08-23T00:00:00Z'")
    parser.add_argument("-w", "--whitelist", dest="whitelist", required=False,
    help="The whitelist file")
    parser.add_argument("-i", "--ip_es", dest="ip_es", required=True,
    help="IP from the elastic search")
    parser.add_argument("-l", "--list_all_indices", dest="list_all_indices", action='store_true', required=False,
    help="List all indices")

    #args = vars(ap.parse_args())
    args = parser.parse_args()

    # socks.set_default_proxy(socks.SOCKS5, "localhost", 9000)
    # socket.socket = socks.socksocket
    ip_es = args.ip_es
    print("- The elastic search IP is " + ip_es)
    datefpg = date_from=dateutil.parser.isoparse(args.date);
    fgp=FingerprintGenerator(datefpg, args.ip_es, args.whitelist)

    if args.list_all_indices:
        fgp.GetIndices()
        exit(0)

if __name__ == "__main__":
    main()

