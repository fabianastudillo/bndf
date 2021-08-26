#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jan 15 17:32:43 2021

@author: vicente
"""
import pandas as pd # data processing
import warnings
#import os
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt

warnings.filterwarnings('ignore')
#print(os.listdir("../Tesis"))

df=pd.read_csv("../Tesis/fingerprints.csv")
df.head()
metrics_df=df

metrics_df.columns
to_model_columns=metrics_df.columns[3:18]

#clf=IsolationForest(n_estimators=100, max_samples='auto', contamination=float(.12),
                    #max_features=1.0, bootstrap=False, n_jobs=-1, random_state=42, 
                    #verbose=0)
anomalias=[]
estimador=[]                
for i in range(5,40): 
    n_estimator=i*10
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
    estimador.append(n_estimator)
    anomalias.append(a.values[1])
    print(n_estimator)
    print(metrics_df['anomaly'].value_counts())

plt.figure()
plt.title("Número de Anomalías Encontradas")
plt.xlabel("Numero de Árboles")
plt.ylabel("Cantidad de Anomalías")
plt.plot(estimador,anomalias)
plt.show()
