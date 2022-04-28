#import runpy
#import datetime
import datetime
import dateutil.parser
from FingerprintGenerator import FingerprintGenerator
#import socks
import socket
import logging
import os
import sys
#import pdb; pdb.set_trace()

def main():

    #socks.set_default_proxy(socks.SOCKS5, "localhost", 9000)
    #socket.socket = socks.socksocket

    #date_from=date.fromisoformat('2021-08-23T00:00:00.000000Z')
    date_from=dateutil.parser.isoparse('2022-04-26T20:00:00Z')

    date_upto=dateutil.parser.isoparse("2022-04-28T00:00:00Z")
    date_offset = date_from
    logging.basicConfig(filename='/var/log/bndf/fingerprint.log', level=logging.INFO, filemode='a', format='%(name)s - %(levelname)s - %(message)s')
    logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))
    #logging.basicConfig(encoding='utf-8', format='%(levelname)s:%(message)s', level=logging.INFO)
    #logging.basicConfig(filename='/var/log/bndf/fingerprints.log', level=logging.INFO)
    #logging.basicConfig(filename='/var/log/bndf.log', filemode='a', format='%(name)s - %(levelname)s - %(message)s')

    IP_ES = os.getenv('IP_ES')
    if not IP_ES:
        IP_ES="elasticsearch"

    try:
        fpg = FingerprintGenerator(IP_ES, date_from, "/root/whitelist.txt")
        print("Fingerprint Generator created")
    except Exception as ex:
        logging.info(str(ex))
        print(str(ex))
        exit(0)

    #fpg.GetIndices()
    
    while (date_offset < date_upto):
        try:
            print("Setting dates: " + date_offset.strftime("%Y-%m-%d; %H:%M:%S"))
            fpg.SetDatestep(date_offset)
            print("Generating fingerprints ...")
            tstart = datetime.datetime.now()
            print(tstart)
            fpg.Generate()
            tend = datetime.datetime.now()
            elapsed=tend-tstart
            print("Fingerprints generated in " + str(elapsed.total_seconds()))
            #runpy.run_path(path_name='/fingerprint_generator.py -d ' + date_from.strftime("%Y-%m-%dT%H:%M:%SZ") + '-o ' + 0 + '-w "/root/whitelist.txt" -i "elasticsearch"')
        except Exception as ex:
            logging.info(str(ex))
        date_offset+=datetime.timedelta(hours=1)
    

if __name__ == "__main__":
    main()
