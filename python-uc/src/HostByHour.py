#import runpy
#import datetime
import datetime
import dateutil.parser
from FingerprintGenerator import FingerprintGenerator
#import socks
import socket
import logging
import os
import numpy as np

def main():

    #socks.set_default_proxy(socks.SOCKS5, "localhost", 9000)
    #socket.socket = socks.socksocket

    #date_from=date.fromisoformat('2021-08-23T00:00:00.000000Z')
    date_from=dateutil.parser.isoparse('2022-08-26T00:00:00Z')

    date_upto=dateutil.parser.isoparse("2022-09-06T00:00:00Z")
    date_offset = date_from

    #matriz_num_host=[]
    #matriz_num_host.append(5)
    #matriz_num_host.append(10)
    #matriz_num_host.append(15)
    #M_N_H=np.array(matriz_num_host)
    #M_N_H=M_N_H.transpose()
    #date_from=dateutil.parser.isoparse('2022-03-31T09:00:00Z')
    #np.savetxt("num_host.csv",M_N_H,fmt="%d",delimiter=",")

    #exit(0)
    
    IP_ES = os.getenv('IP_ES')
    if not IP_ES:
        IP_ES="elasticsearch"

    print(IP_ES)
    #fpg=""
    try:
        fpg = FingerprintGenerator(IP_ES, date_from, "/root/whitelist.txt")
    except Exception as ex:
        logging.info(str(ex))
        print("Error")
        exit(2)

    #fpg.GetIndices()
    print("Load Fingerprint")
    while (date_offset <= date_upto):
        #try:
        fpg.SetDatestep(date_offset)
        fpg.getHostByHour()
        #runpy.run_path(path_name='/fingerprint_generator.py -d ' + date_from.strftime("%Y-%m-%dT%H:%M:%SZ") + '-o ' + 0 + '-w "/root/whitelist.txt" -i "elasticsearch"')
        #except Exception as ex:
        #logging.info(str(ex))
        #    print(str(ex))
        date_offset+=datetime.timedelta(hours=1)
    

if __name__ == "__main__":
    main()
