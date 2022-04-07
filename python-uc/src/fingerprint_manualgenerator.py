#import runpy
#import datetime
import datetime
import dateutil.parser
from FingerprintGenerator import FingerprintGenerator
#import socks
import socket
import logging
import os

def main():

    #socks.set_default_proxy(socks.SOCKS5, "localhost", 9000)
    #socket.socket = socks.socksocket

    #date_from=date.fromisoformat('2021-08-23T00:00:00.000000Z')
    date_from=dateutil.parser.isoparse('2022-03-29T00:00:00Z')

    date_upto=dateutil.parser.isoparse("2022-03-30T00:00:00Z")
    date_offset = date_from
    
    IP_ES = os.getenv('IP_ES')
    if not IP_ES:
        IP_ES="elasticsearch"

    try:
        fpg = FingerprintGenerator(IP_ES, date_from, "/root/whitelist.txt")
        print("Fingerprint Generator created")
    except Exception as ex:
        logging.info(str(ex))
        print(str(ex))

    #fpg.GetIndices()
    
    while (date_offset < date_upto):
        try:
            print("Setting dates: ")
            fpg.SetDatestep(date_offset)
            print("Generating fingerprints ...")
            fpg.Generate()
            print("Fingerprints generated")
            #runpy.run_path(path_name='/fingerprint_generator.py -d ' + date_from.strftime("%Y-%m-%dT%H:%M:%SZ") + '-o ' + 0 + '-w "/root/whitelist.txt" -i "elasticsearch"')
        except Exception as ex:
            logging.info(str(ex))
        date_offset+=datetime.timedelta(hours=1)
    

if __name__ == "__main__":
    main()
