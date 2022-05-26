#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Nov 27 17:36:20 2020

@author: Vicente Quezada
@modified by: Fabian Astudillo-Salinas <fabian.astudillos@ucuenca.edu.ec>

Execution example: python AnomalyDetection.py -o -s 70 -3 -2
"""

import glob, os
from os.path import exists
import datetime as dt
#import pandas as pd # data processing
import warnings
from argparse import ArgumentParser
from datetime import datetime
#import os
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from mpl_toolkits.mplot3d import Axes3D
from plotly.offline import download_plotlyjs, init_notebook_mode, plot, iplot
import chart_studio.plotly as py
import matplotlib as mpl
import plotly.graph_objs as go
import plotly.io as pio
import logging
from datetime import date
import sys
import csv

#################################3
#def plot_anomaly(df,metric_name):
    # Description
    #descrip=["P1","Number of DNS requests per hour",
    #        "P2","Number of different DNS requests per hour",
    #        "P3","Highest number of requests for a single domain per hour",
    #        "P4","Average number of requests per minute",
    #        "P5","Most requests per minute",
    #        "P6","Number of MX record queries per hour",
    #        "P7","Number of PTR records queries per hour",
    #        "P8","Number of different DNS servers queried per hour",
    #        "P9","Number of different TLD domains queried per hour",
    #        "P10","Number of different SLD domains consulted per hour",
    #        "P11","Uniqueness ratio per hour",
    #        "P12","Number of failed / NXDOMAIN queries per hour",
    #        "P13","Number of different cities of resolved IP addresses",
    #        "P14","Number of different countries of resolved IP addresse",
    #        "P15","Hourly flow rate"]
    #pio.renderers.default='browser'
    ##df.load_date = pd.to_datetime(df['load_date'].astype(str), format="%Y%m%d")
#    dates = df.load_date
    #identify the anomaly points and create a array of its values for plot
#    bool_array = (abs(df['anomaly']) > 0)
#    actuals = df["actuals"][-len(bool_array):]
#    anomaly_points = bool_array * actuals
#    anomaly_points[anomaly_points == 0] = np.nan

#    r = open('/var/log/bndf/anomalies.csv', 'w')
#    writer = csv.writer(r)
#    writer.writerows(np.stack([dates,df['actuals'],anomaly_points], axis=1))
#    r.close()

def ClassifyAnomalies(df,metric_name):
    df['metric_name']=metric_name
    df = df.sort_values(by='load_date', ascending=False)
    #Shift actuals by one timestamp to find the percentage change between current and previous data point
    df['shift'] = df['actuals'].shift(-1)
    #df['percentage_change'] = ((df['actuals'] - df['shift']) / df['actuals']) * 100
    #Categorise anomalies as 0-no anomaly, 1- low anomaly , 2 - high anomaly
    df['anomaly'].loc[df['anomaly'] == 1] = 0
    df['anomaly'].loc[df['anomaly'] == -1] = 2
    df['anomaly_class'] = df['anomaly']
    max_anomaly_score = df['score'].loc[df['anomaly_class'] == 2].max()
    #print("Max Anomaly Score")
    #print(max_anomaly_score)
    medium_percentile = df['score'].quantile(0.24)
    #print(medium_percentile)
    df['anomaly_class'].loc[(df['score'] > max_anomaly_score) & (df['score'] <= medium_percentile)] = 1
    print(df['anomaly_class'])
    return df

##################################

def Convert(a):
    it = iter(a)
    res_dct = dict(zip(it, it))
    return res_dct

def main():

    logging.basicConfig(filename='/var/log/bndf/fingerprint.log', level=logging.INFO, filemode='a', format='%(name)s - %(levelname)s - %(message)s')
    logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))

    parser = ArgumentParser(
            description='Fingerprint generator',
            epilog="This script detects the anomalies from a fingerprint file.")

    # Add the arguments to the parser
    parser.add_argument("-o", "--outliers", dest="opt_outliers", action='store_true', required=False,
    help="This option generates the outliers file")
    parser.add_argument("-3", "--reduce3d", dest="opt_reduce3d", action='store_true', required=False,
    help="Reduce to 3 dimensions using PCA")
    parser.add_argument("-2", "--reduce2d", dest="opt_reduce2d", action='store_true', required=False,
    help="Reduce to 2 dimensions using PCA")
    parser.add_argument("-e", "--es", dest="opt_es", action='store_true', required=False,
    help="Upload the anomalies to elasticsearch")
    parser.add_argument("-g", "--graylog", dest="opt_graylog", action='store_true', required=False,
    help="Execute the algorithm removing certain attributs from fingerprints file")
    parser.add_argument("-a", "--onebyone", dest="opt_onebyone", action='store_true', required=False,
    help="Execute the algorithm for each attribute")
    parser.add_argument("-s", "--estimators", type=int, dest="opt_est", required=False,
    help="Set the number of estimators for the Anomaly Detection Algorithm")

    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    logging.basicConfig(filename='/var/log/bndf.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')
    today = date.today()
    current_date = today.strftime("%Y.%m.%d")
    
    #anomalies_filename=r'/bndf/adf/FP_anomalies_target-' + current_date + '.csv'
    fullfilename=r'/bndf/adf/full-' + current_date + '.csv'
    fullglfilename=r'/bndf/adf/full-graylog-' + current_date + '.csv'
    fpfilename=r'/bndf/adf/FP_anomalies_target-' + current_date + '.csv'
    fplastfilename=r'/bndf/adf/FP_anomalies_target-last.csv'
    loadfull=False
    n_estimators=110
    
    f = open("/var/log/bndf/cron-anomaly-detection.log", "a")
    f.write("Executed: " + current_date)
    f.close()
    
    if args.opt_est:
        n_estimators = args.opt_est
        logging.info("The number of estimators is " + str(n_estimators))
    graylog=True # TODO: In the final version change to False
    if args.opt_graylog:
        graylog=True

    # TODO: improve the next code, it has redundant code
    import pandas as pd # data processing
    if args.opt_outliers:
        logging.info("Generate outliers ...")
        warnings.filterwarnings('ignore')

        # Dataframe list of all entries
        df_list = []

        try:
            today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            today = today - dt.timedelta(days=10)
            for i in range(10):
                __today = today.strftime("%Y-%m-%d")
                filename=os.path.join("/var/log/bndf/","fingerprints-" + __today + ".csv")
                print(filename)
                df_list.append(pd.read_csv(filename))
                full_df = pd.concat(df_list)
                full_df.to_csv(fullfilename, index=False)
                today = today + dt.timedelta(days=1)
            
#            for filename in sorted(glob.glob(os.path.join("/var/log/bndf/","fingerprints-*.csv"))):
#                print(filename)
#                df_list.append(pd.read_csv(filename))
#                full_df = pd.concat(df_list)
#                full_df.to_csv(fullfilename, index=False)
        except Exception as inst:
            print(type(inst))
            print(inst.args)
            print(inst)
            exit(0)

        if graylog:
            stream = os.popen("cut -d',' -f 1-14,17 " + fullfilename + " > " + fullglfilename)
            output = stream.read()
            fullfilename = fullglfilename

        df=pd.read_csv(fullfilename)
        df.head()
        metrics_df=df
        logging.info("Number of hosts: " + str(len(set(metrics_df['ip']))))


        #metrics_df.columns
        # take csv columns from 2 to 16
        if graylog:
            to_model_columns=metrics_df.columns[2:15]
        else:
            to_model_columns=metrics_df.columns[2:17]
        
        #clf=IsolationForest(n_estimators=100, max_samples='auto', contamination=float(.12),
                            #max_features=1.0, bootstrap=False, n_jobs=-1, random_state=42, 
                            #verbose=0)
        clf=IsolationForest(n_estimators=n_estimators, max_samples='auto', contamination='auto',
                            max_features=1.0, bootstrap=False, n_jobs=-1, random_state=42, 
                            verbose=0)
        clf.fit(metrics_df[to_model_columns])
        # Execute the predictions from data

        pred=clf.predict(metrics_df[to_model_columns])

        # Create a new column called anomaly
        metrics_df['anomaly']=pred
        # Get all the outliers (-1) from data frame metrics_df
        outliers=metrics_df.loc[metrics_df['anomaly']==-1]
        outlier_index=list(outliers.index)
        #print(outlier_index)
        #Find the number of anomalies and normal points here points classified -1 are anomalous
        logging.info("Anomalies: " + str(metrics_df['anomaly'].value_counts()))
        ####
        metrics_df.to_csv(fpfilename,index=False)
        metrics_df.to_csv(fplastfilename,index=False)
        loadfull=True

    #if exists(full_filename):
    #    print("Load full anomalies file ...")
    #    df=pd.read_csv(full_filename)
    #    df.head()
    #    metrics_df=df
    #    to_model_columns=metrics_df.columns[3:18]
    if loadfull:
        if args.opt_reduce3d:
            # Reduce to k=3 dimensions
            pca = PCA(n_components=3)  
            scaler = StandardScaler()
            # Normalize the metrics
            X = scaler.fit_transform(metrics_df[to_model_columns])
            X_reduce = pca.fit_transform(X)
            fig = plt.figure()
            fig.suptitle('DNS Fingerprints 3D')
            ax = fig.add_subplot(111, projection='3d')
            # Plot the compressed data points
            ax.scatter(X_reduce[:, 0], X_reduce[:, 1], X_reduce[:, 2], s=4, lw=1, label="normal",c="green")
            # Plot x's for the ground truth outliers
            ax.scatter(X_reduce[outlier_index,0],X_reduce[outlier_index,1], X_reduce[outlier_index,2],
                    lw=1, s=4, c="red", label="anormal")
            ax.legend()

            plt.show()
            fig.savefig("/bndf/adf/dns_fingerprints_3d-1-" + current_date + ".pdf")

            #pca = PCA(n_components=3)  # Reduce to k=3 dimensions
            #scaler = StandardScaler()
            #normalize the metrics
            #X = scaler.fit_transform(metrics_df[to_model_columns])
            #X_reduce = pca.fit_transform(X)
            fig = plt.figure()
            fig.suptitle('DNS Fingerprints 3D')
            ax = fig.add_subplot(111, projection='3d')
            # Plot the compressed data points
            ax.scatter(X_reduce[:, 0], X_reduce[:, 1], X_reduce[:, 2], s=4, lw=1, label="normal",c="green")
            # Plot x's for the ground truth outliers
            ax.scatter(X_reduce[outlier_index,0],X_reduce[outlier_index,1], X_reduce[outlier_index,2],
                    lw=1, s=4, c="red", label="anormal")
            ax.legend()
            ax.set_zlim3d(-10,5)
            ax.set_xlim3d(-3,4)
            ax.set_ylim3d(0,4)
            #ax.axis('off')
            plt.show()
            fig.savefig("/bndf/adf/dns_fingerprints_3d-2-" + current_date + ".pdf")

            fig=plt.figure()

        if args.opt_reduce2d:
            import numpy as np # linear algebra
            fig = plt.figure()
            pca = PCA(n_components=2)
            pca.fit(metrics_df[to_model_columns])
            res=pd.DataFrame(pca.transform(metrics_df[to_model_columns]))
            Z = np.array(res)
            plt.title("DNS Fingerprints 2D")
            plt.contourf( Z, cmap=plt.cm.Blues_r)
            b1 = plt.scatter(res[0], res[1], c='green',
                            s=20,label="normal")
            b1 = plt.scatter(res.iloc[outlier_index,0],res.iloc[outlier_index,1], c='red',
                            s=20,label="anormal")
            plt.legend(loc="upper right")
            plt.show()
            fig.savefig("/bndf/adf/dns_fingerprints_2d-" + current_date + ".pdf")
    else:
        #logging.info("You have to run the script with the generation of outliers option [-o]")
        print("You have to run the script with the generation of outliers option [-o]")

    if args.opt_es:
        from elasticsearch import Elasticsearch
        import pandas as pd
        #import socket
        #import socks
        import numpy as np

        ii = 1

        #socks.set_default_proxy(socks.SOCKS5, "localhost", 9000)
        #socket.socket = socks.socksocket

        try:
            es = Elasticsearch([{'host':'elasticsearch','port':9200,}])
            print ("Connected")
        except Exception as ex:
            print ("Error:", ex)
            exit()

        # Index of cataloged footprints
        index_fp="cataloged_footprints-" + current_date

        try:
            res=es.indices.delete(index=index_fp)
        except:
            pass

        metrics_df=pd.read_csv(fpfilename)

        if graylog:
            datos_finales=[["@timestamp",time,
                            "ip",ip,"p1",p1,"p2",p2,"p3",p3,"p4",p4,"p5",p5,
                            "p6",p6,"p7",p7,"p8",p8,"p9",p9,"p10",p10,"p11",
                            p11,"p12",p12,"p15",p15,"an",an] 
                            for time,ip,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p15,an 
                            in zip(metrics_df['@timestamp'],metrics_df['ip'],metrics_df['P1'],metrics_df['P2'],metrics_df['P3'],
                    metrics_df['P4'],metrics_df['P5'],metrics_df['P6'],metrics_df['P7'],metrics_df['P8'],metrics_df['P9'],
                    metrics_df['P10'],metrics_df['P11'],metrics_df['P12'],metrics_df['P15'],
                    metrics_df['anomaly'])]
        else:
            datos_finales=[["@timestamp",time,
                            "ip",ip,"p1",p1,"p2",p2,"p3",p3,"p4",p4,"p5",p5,
                            "p6",p6,"p7",p7,"p8",p8,"p9",p9,"p10",p10,"p11",
                            p11,"p12",p12,"p13",p13,"p14",p14,"p15",p15,"an",an] 
                            for time,ip,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,an 
                            in zip(metrics_df['@timestamp'],metrics_df['ip'],metrics_df['P1'],metrics_df['P2'],metrics_df['P3'],
                    metrics_df['P4'],metrics_df['P5'],metrics_df['P6'],metrics_df['P7'],metrics_df['P8'],metrics_df['P9'],
                    metrics_df['P10'],metrics_df['P11'],metrics_df['P12'],metrics_df['P13'],metrics_df['P14'],metrics_df['P15'],
                    metrics_df['anomaly'])]

        datos_finales_json=[Convert(item) for item in datos_finales]

        for item in datos_finales_json:
            res=es.index(index=index_fp,doc_type='cataloged_footprints',id=ii,body=item)
            ii=ii+1
        print("ii> "+str(ii))
        ####
        #init_notebook_mode(connected=True)
        warnings.filterwarnings('ignore')

        ###
        #columna_indice=[i for i in range(len(metrics_df))]
        #metrics_df['index']=columna_indice
        ###

    if args.opt_onebyone:
        print("One by one ...")
        clf=IsolationForest(n_estimators=n_estimators, max_samples='auto', contamination='auto',
                            max_features=1.0, bootstrap=False, n_jobs=-1, random_state=42, 
                            verbose=0)
        # First column is timestamp
        #index = range(1,len(metrics_df.columns)-1)

        # TODO: Now parameters are save in 15 files, we have to save in one file
        # TODO: Verify if the behaviour is different if the training is done using the 15 paramenters
        #all_df=pd.DataFrame()
        #to_model_columns=metrics_df.columns[3:18]
        #clf.fit(metrics_df[to_model_columns])
        #all_pred = clf.predict(metrics_df[to_model_columns])
        #all_df['score']=clf.decision_function(metrics_df[to_model_columns])
        #all_df['actuals']=metrics_df[to_model_columns]
        #all_df['anomaly']=all_pred
        #breakpoint()
        import numpy as np
        print(metrics_df.columns)
        for i in range(2,len(metrics_df.columns)-1):
            attribute_name=str(metrics_df.columns[i])
            print ("Column: " + attribute_name)
            
            mdf_col = metrics_df.iloc[:,i:i+1]
            
            clf.fit(mdf_col)
            #pred = clf.predict(mdf_col)
            #print(pred)
            test_df=pd.DataFrame()

            #test_df['load_date']=metrics_df['index']
            test_df['load_date']=metrics_df['@timestamp']
            #dates = metrics_df['@timestamp']
            #Find decision function to find the score and classify anomalies
            
            #print(mdf_col)
            test_df['actuals']=mdf_col
            test_df['score']=clf.decision_function(mdf_col)
            test_df['anomaly']=clf.predict(mdf_col)
            
            #Get the indexes of outliers in order to compare the metrics with use case anomalies if required
            ##outliers=test_df.loc[test_df['anomaly']==-1]
            ##outlier_index=list(outliers.index)
            # TODO: At the moment we doesn't use the anomaly classification 
            test_df=ClassifyAnomalies(test_df,attribute_name)
            
            #identify the anomaly points and create a array of its values
            anomaly_points = (abs(test_df['anomaly']) > 0) * (test_df["actuals"])
            anomaly_points[anomaly_points == 0] = np.nan
            r = open('/bndf/adf/anomalies-' + str(metrics_df.columns[i]) + '.csv', 'w')
            writer = csv.writer(r)
            #writer.writerows(np.stack([dates,test_df['actuals'],anomaly_points], axis=1))
            
            # In the next line is generated an array from 1 to the number of records
            index=pd.array(range(1,(len(test_df["load_date"]))+1), dtype=np.dtype("int32"))
            # In the file is writen the index column, the actuals column and the anomalies column
            #    the axis parameter is for write in transpose mode
            writer.writerows(np.stack([index,test_df['actuals'],anomaly_points], axis=1))
            r.close()

if __name__ == "__main__":
    main()
