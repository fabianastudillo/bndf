#import runpy
#import datetime
import datetime
import dateutil.parser
from FingerprintGenerator import FingerprintGenerator
import socks
import socket
import logging

def main():

    #socks.set_default_proxy(socks.SOCKS5, "localhost", 9000)
    #socket.socket = socks.socksocket

    #date_from=date.fromisoformat('2021-08-23T00:00:00.000000Z')
    date_from=dateutil.parser.isoparse('2021-08-23T00:00:00Z')

    date_upto=dateutil.parser.isoparse("2021-08-25T16:00:00Z")
    date_offset = date_from
    
    #fpg = FingerprintGenerator("elasticsearch", date_from, "/root/whitelist.txt")
    try:
        fpg = FingerprintGenerator("172.17.1.73", date_from, "/root/whitelist.txt")
    except Exception as ex:
        logging.info(str(ex))

    #fpg.GetIndices()
    
    while (date_offset <= date_upto):
        try:
            fpg.SetDatestep(date_offset)
            fpg.Generate()
            #runpy.run_path(path_name='/fingerprint_generator.py -d ' + date_from.strftime("%Y-%m-%dT%H:%M:%SZ") + '-o ' + 0 + '-w "/root/whitelist.txt" -i "elasticsearch"')
        except Exception as ex:
            logging.info(str(ex))
        date_offset+=datetime.timedelta(hours=1)
    

if __name__ == "__main__":
    main()