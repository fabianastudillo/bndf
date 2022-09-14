#import runpy
import datetime as dt
from datetime import datetime
from random import Random
from FingerprintGenerator import FingerprintGenerator
from RandomForestDetectionModel import RandomForestDetectionModel
from AntiDomainGenerationAlgorithm import AntiDomainGenerationAlgorithm
#import socks
import socket
import logging
import os
import sys

def main():

    logging.basicConfig(filename='/var/log/bndf/fingerprint.log', level=logging.INFO, filemode='a', format='%(name)s - %(levelname)s - %(message)s')
    logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))
    #socks.set_default_proxy(socks.SOCKS5, "localhost", 9000)
    #socket.socket = socks.socksocket

    #today = datetime.today()
    today = datetime.now().replace(minute=0, second=0, microsecond=0)
    today = today - dt.timedelta(hours=1)

    IP_ES = os.getenv('IP_ES')
    if not IP_ES:
        IP_ES="elasticsearch"

    try:
        logging.info(datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ") + " - Executing FingerprintGenerator")
        fpg = FingerprintGenerator(IP_ES, today, "/root/whitelist.txt")
        fpg.Generate()
        fpg.UploadLastToElasticsearch()
        logging.info(datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ") + " - Executing RandomForestDetectionModel")
        rfdm = RandomForestDetectionModel()
        rfdm.Predict()
        logging.info(datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ") + " - Executing AntiDomainGenerationAlgorithm")
        adga = AntiDomainGenerationAlgorithm(all_fingerprints=False, clean_index=False)
        adga.Run()
        logging.info(datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ") + " - Upload data to elasticsearch")
        adga.UploadToElasticsearch()
    except Exception as ex:
        logging.info(str(ex))

if __name__ == "__main__":
    main()