#import runpy
#import datetime
from datetime import date
import dateutil.parser
import FingerprintGenerator
import socks

def main():

    socks.set_default_proxy(socks.SOCKS5, "localhost", 9000)
    socket.socket = socks.socksocket

    #date_from=date.fromisoformat('2021-08-23T00:00:00.000000Z')
    date_from=dateutil.parser.isoparse('2021-08-23T00:00:00Z')

    date_upto=dateutil.parser.isoparse("2021-08-24T14:00:00Z")
    date_offset = date_from
    
    fpg = FingerprintGenerator(date_from, "elasticsearch", "/root/whitelist.txt")

    while (date_offset <= date_upto):
        fpg.SetDatestep(date_offset)
        fpg.Generate()
        #runpy.run_path(path_name='/fingerprint_generator.py -d ' + date_from.strftime("%Y-%m-%dT%H:%M:%SZ") + '-o ' + 0 + '-w "/root/whitelist.txt" -i "elasticsearch"')
        date_offset+=date.timedelta(hours=1)

if __name__ == "__main__":
    main()