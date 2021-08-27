#import runpy
import datetime as dt
from datetime import datetime
from FingerprintGenerator import FingerprintGenerator
#import socks
import socket
import logging
import os

def main():

    #socks.set_default_proxy(socks.SOCKS5, "localhost", 9000)
    #socket.socket = socks.socksocket

    #today = datetime.today()
    today = datetime.now().replace(minute=0, second=0, microsecond=0)
    today = today - dt.timedelta(hours=1)

    IP_ES = os.getenv('IP_ES')
    if not IP_ES:
        IP_ES="elasticsearch"

    try:
        fpg = FingerprintGenerator(IP_ES, today, "/root/whitelist.txt")
        fpg.Generate()
    except Exception as ex:
        logging.info(str(ex))

if __name__ == "__main__":
    main()