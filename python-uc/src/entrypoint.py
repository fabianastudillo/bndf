#import runpy
import datetime as dt
from datetime import datetime
from FingerprintGenerator import FingerprintGenerator
import socks
import socket
import logging

def main():

    #socks.set_default_proxy(socks.SOCKS5, "localhost", 9000)
    #socket.socket = socks.socksocket

    #today = datetime.today()
    today = datetime.now().replace(minute=0, second=0, microsecond=0)
    today = today - dt.timedelta(hours=1)
    try:
        fpg = FingerprintGenerator("elasticsearch", today, "/root/whitelist.txt")
        fpg.Generate()
    except Exception as ex:
        logging.info(str(ex))

if __name__ == "__main__":
    main()