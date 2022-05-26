from time import time
import queries
import pandas as pd
import requests
import dateutil.parser
import os.path


from os.path import exists

ip_elasticsearch="elasticsearch"

dga_filename = "/bndf/adf/domains_dga_abstract_2022-05-05T18:06:37Z.txt"
dgaout_filename = "/bndf/adf/domains_dga_abstract_output.txt"
if not exists(dga_filename):
    print("File not exist: " + dga_filename)
    exit(1)
    
df=pd.read_csv(dga_filename)

HEADERS = {
    'Content-Type': 'application/json'
}

df["member"] = pd.NaT

#for index, row in metrics_df.iterrows():
n = str(len(df.index))
for i in df.index:
    print("Processing " + str(i) + "/" + n)
    timestamp=df['@timestamp'][i]
    date_from=dateutil.parser.isoparse(timestamp)
    index='logstash-dns-' + date_from.strftime("%Y.%m.%d")
    #print(index)
    #print(df['ip'][i])
    query=queries.getMember(df['ip'][i])
    uri = "http://" + ip_elasticsearch + ":9200/"+index+"/_search"
    r = requests.get(uri,headers=HEADERS, data=query).json()
    #print(r)
    if (len(r["aggregations"]["members"]["buckets"])>0):
        membername=r["aggregations"]["members"]["buckets"][0]["key"]
    else:
        membername="Not found"
    #print(membername)
    df["member"][i] = membername
    #metrics_df.at[index,"member"] = membername
    
df.insert(2, 'member', df.pop('member'))
print(df)
#df.to_csv(dgaout_filename, index=None, mode="w", header=not os.path.isfile(dgaout_filename))
df.to_csv(dgaout_filename, index=None, mode="w")
#df['Address'] = address

