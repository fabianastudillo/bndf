#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jan 15 17:32:43 2021

@author: vicente
"""
import pandas as pd # data processing
import warnings
import glob, os
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import logging
import csv
import numpy as np

warnings.filterwarnings('ignore')
#print(os.listdir("../Tesis"))

df_list = []

for filename in sorted(glob.glob(os.path.join("/var/log/bndf/","fingerprints-*.csv"))):
    df_list.append(pd.read_csv(filename))
    full_df = pd.concat(df_list)
    full_df.to_csv('/var/log/bndf/full.csv', index=False)

df=pd.read_csv("/var/log/bndf/full.csv")
df.head()
metrics_df=df

metrics_df.columns
to_model_columns=metrics_df.columns[3:18]

#clf=IsolationForest(n_estimators=100, max_samples='auto', contamination=float(.12),
                    #max_features=1.0, bootstrap=False, n_jobs=-1, random_state=42, 
                    #verbose=0)
anomalies=[]
estimator=[]                
#for i in range(5,40): 
#    n_estimator=i*10
for i in range(2,1000):
    n_estimator=i
    clf=IsolationForest(n_estimators=n_estimator, max_samples='auto', contamination='auto',
                        max_features=1.0, bootstrap=False, n_jobs=-1, random_state=42, 
                        verbose=0)
    clf.fit(metrics_df[to_model_columns])
    pred= clf.predict(metrics_df[to_model_columns])
    metrics_df['anomaly']=pred
    outliers=metrics_df.loc[metrics_df['anomaly']==-1]
    outlier_index=list(outliers.index)
    #print(outlier_index)
    #Find the number of anomalies and normal points here points classified -1 are anomalous
    a=metrics_df['anomaly'].value_counts()
    estimator.append(n_estimator)
    anomalies.append(a.values[1])
    logging.info("IsolationForest: ", n_estimator, " ", metrics_df['anomaly'].value_counts())
#    print(n_estimator)
#    print(metrics_df['anomaly'].value_counts())

r = open('/var/log/bndf/estimators.csv', 'w')
writer = csv.writer(r)
writer.writerows(np.stack([estimator,anomalies], axis=1))
r.close()

f=plt.figure()
plt.title("Number of Anomalies Found")
plt.xlabel("Number of Trees")
plt.ylabel("Number of Anomalies")
plt.plot(estimator,anomalies)
plt.show()
f.savefig("full.pdf", bbox_inches='tight')

