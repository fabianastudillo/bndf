#import runpy
import datetime as dt
from datetime import datetime
import dateutil.parser
from FingerprintGenerator import FingerprintGenerator
import socks
import socket
import logging

def main():

    socks.set_default_proxy(socks.SOCKS5, "localhost", 9000)
    socket.socket = socks.socksocket

    #today = datetime.today()
    today = datetime.now().replace(minute=0, second=0, microsecond=0)
    print(today)
    today = today - dt.timedelta(hours=1)
    print(today)
    try:
        #fpg = FingerprintGenerator("elasticsearch", date_from, "/root/whitelist.txt")
        fpg = FingerprintGenerator("172.17.1.73", today, "/root/whitelist.txt")
        fpg.Generate()
    except Exception as ex:
        logging.info(str(ex))

if __name__ == "__main__":
    main()