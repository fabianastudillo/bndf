#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Nov 27 17:36:20 2020

@author: vicente
"""

import glob, os
import numpy as np # linear algebra
import pandas as pd # data processing
import warnings
from argparse import ArgumentParser
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

#################################3
def plot_anomaly(df,metric_name):
    # Description
    descrip=["P1","Number of DNS requests per hour",
            "P2","Number of different DNS requests per hour",
            "P3","Highest number of requests for a single domain per hour",
            "P4","Average number of requests per minute",
            "P5","Most requests per minute",
            "P6","Number of MX record queries per hour",
            "P7","Number of PTR records queries per hour",
            "P8","Number of different DNS servers queried per hour",
            "P9","Number of different TLD domains queried per hour",
            "P10","Number of different SLD domains consulted per hour",
            "P11","Uniqueness ratio per hour",
            "P12","Number of failed / NXDOMAIN queries per hour",
            "P13","Number of different cities of resolved IP addresses",
            "P14","Number of different countries of resolved IP addresse",
            "P15","Hourly flow rate"]
    pio.renderers.default='browser'
    #df.load_date = pd.to_datetime(df['load_date'].astype(str), format="%Y%m%d")
    dates = df.load_date
    #identify the anomaly points and create a array of its values for plot
    bool_array = (abs(df['anomaly']) > 0)
    actuals = df["actuals"][-len(bool_array):]
    anomaly_points = bool_array * actuals
    anomaly_points[anomaly_points == 0] = np.nan
    #A dictionary for conditional format table based on anomaly
    #color_map = {0: "'rgba(228, 222, 249, 0.65)'", 1: "yellow", 2: "red"}
#    color_map = {0: "silver", 1: "yellow", 2: "red"}
#
#    
#    #Table which includes Date,Actuals,Change occured from previous point
#    table = go.Table(
#        domain=dict(x=[0, 1],
#                    y=[0, 0.3]),
#        columnwidth=[1, 2],
#        # columnorder=[0, 1, 2,],
#        header=dict(height=20,
#                    values=[['<b>Date</b>'], ['<b>Actual Values </b>'], ['<b>% Change </b>'],
#                            ],
#                    font=dict(color=['rgb(45, 45, 45)'] * 5, size=14),
#                    fill=dict(color='#d562be')),
#        cells=dict(values=[df.round(3)[k].tolist() for k in ['load_date', 'actuals', 'percentage_change']],
#                   line=dict(color='#506784'),
#                   align=['center'] * 5,
#                   font=dict(color=['rgb(40, 40, 40)'] * 5, size=12),
#                   # format = [None] + [",.4f"] + [',.4f'],
#                   # suffix=[None] * 4,
#                   suffix=[None] + [''] + [''] + ['%'] + [''],
#                   height=27,
#                   fill=dict(color=[test_df['anomaly_class'].map(color_map)],#map based on anomaly level from dictionary
#                   )
#                   ))
    #print(table)
    #Plot the actuals points
    Actuals = go.Scatter(name='Limpio',
                         x=dates,
                         y=df['actuals'],
                         xaxis='x1', yaxis='y1',
                         mode='markers',
                         marker=dict(size=5,
                                     line=dict(width=1),
                                     color="blue"))
#Highlight the anomaly points
    anomalies_map = go.Scatter(name="Bot",
                               showlegend=True,
                               x=dates,
                               y=anomaly_points,
                               mode='markers',
                               xaxis='x1',
                               yaxis='y1',
                               marker=dict(color="red",
                                           size=5,
                                           line=dict(
                                               color="red",
                                               width=1)))
    #print(anomalies_map)
    
    axis = dict(
            showline=True,
            zeroline=False,
            showgrid=True,
            mirror=True,
            ticklen=4,
            gridcolor='#ffffff',
            tickfont=dict(size=10))
    layout = dict(
            width=1000,
            height=865,
            autosize=True,
            #title=metric_name+": "+descrip[descrip.index(metric_name)+1],
            margin=dict(t=75),
            showlegend=True,
            xaxis1=dict(axis, **dict(domain=[0, 1], anchor='y1', showticklabels=True)),
            yaxis1=dict(axis, **dict(domain=[2 * 0.21 + 0.20, 1], anchor='x1', hoverformat='.2f')))
    
    fig = go.Figure(data=[Actuals,anomalies_map], layout=layout)
    fig.update_yaxes(type="log")
    iplot(fig)
    #pyplot.show()

def classify_anomalies(df,metric_name):
    df['metric_name']=metric_name
    df = df.sort_values(by='load_date', ascending=False)
    #Shift actuals by one timestamp to find the percentage chage between current and previous data point
    df['shift'] = df['actuals'].shift(-1)
    df['percentage_change'] = ((df['actuals'] - df['shift']) / df['actuals']) * 100
    #Categorise anomalies as 0-no anomaly, 1- low anomaly , 2 - high anomaly
    df['anomaly'].loc[df['anomaly'] == 1] = 0
    df['anomaly'].loc[df['anomaly'] == -1] = 2
    df['anomaly_class'] = df['anomaly']
    max_anomaly_score = df['score'].loc[df['anomaly_class'] == 2].max()
    medium_percentile = df['score'].quantile(0.24)
    df['anomaly_class'].loc[(df['score'] > max_anomaly_score) & (df['score'] <= medium_percentile)] = 1
    return df

##################################

def Convert(a):
    it = iter(a)
    res_dct = dict(zip(it, it))
    return res_dct

def main():

    parser = ArgumentParser(
            description='Fingerprint generator',
            epilog="This script detects the anomalies from a fingerprint file.")

    # Add the arguments to the parser
    parser.add_argument("-o", "--outliers", dest="opt_outliers", action='store_true', required=False,
    help="This option generates the outliers file")
    parser.add_argument("-3", "--reduce3d", dest="opt_reduce3d", action='store_true', required=False,
    help="Reduce to 3 dimensiones using PCA")
    parser.add_argument("-2", "--reduce2d", dest="opt_reduce2d", action='store_true', required=False,
    help="Reduce to 2 dimensiones using PCA")
    parser.add_argument("-e", "--es", dest="opt_es", action='store_true', required=False,
    help="Upload the anomalies to elasticsearch")

    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    logging.basicConfig(filename='/var/log/bndf.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')
    today = date.today()
    current_date = today.strftime("%Y.%m.%d")

    if args.opt_outliers:
        logging.info("Generate outliers ...")
        warnings.filterwarnings('ignore')

        # Dataframe list of all entries
        df_list = []

        for filename in sorted(glob.glob(os.path.join("/var/log/bndf/","fingerprints-2021-09-13.csv"))):
            df_list.append(pd.read_csv(filename))
            full_df = pd.concat(df_list)
            full_df.to_csv('/var/log/bndf/full-' + current_date + '.csv', index=False)

        df=pd.read_csv("/var/log/bndf/full-" + current_date + ".csv")
        df.head()
        metrics_df=df
        logging.info("Number of hosts: " + str(len(set(metrics_df['ip']))))


        #metrics_df.columns
        # take csv columns from 3 to 18 
        to_model_columns=metrics_df.columns[3:18]

        #clf=IsolationForest(n_estimators=100, max_samples='auto', contamination=float(.12),
                            #max_features=1.0, bootstrap=False, n_jobs=-1, random_state=42, 
                            #verbose=0)
        clf=IsolationForest(n_estimators=110, max_samples='auto', contamination='auto',
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
        metrics_df.to_csv(r'/var/log/bndf/FP_anomalies_target-' + current_date + '.csv',index=False)

    if args.opt_reduce3d:
        # Reduce to k=3 dimensions
        pca = PCA(n_components=3)  
        scaler = StandardScaler()
        # Normalize the metrics
        X = scaler.fit_transform(metrics_df[to_model_columns])
        X_reduce = pca.fit_transform(X)
        fig = plt.figure()
        fig.suptitle('DNS_Fingerprints_3D')
        ax = fig.add_subplot(111, projection='3d')
        # Plot the compressed data points
        ax.scatter(X_reduce[:, 0], X_reduce[:, 1], X_reduce[:, 2], s=4, lw=1, label="normal",c="green")
        # Plot x's for the ground truth outliers
        ax.scatter(X_reduce[outlier_index,0],X_reduce[outlier_index,1], X_reduce[outlier_index,2],
                lw=1, s=4, c="red", label="anormal")
        ax.legend()

        plt.show()
        fig.savefig("dns_fingerprints_3d-1-" + current_date + ".pdf")

        #pca = PCA(n_components=3)  # Reduce to k=3 dimensions
        #scaler = StandardScaler()
        #normalize the metrics
        #X = scaler.fit_transform(metrics_df[to_model_columns])
        #X_reduce = pca.fit_transform(X)
        fig = plt.figure()
        fig.suptitle('DNS_Fingerprints_3D')
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
        fig.savefig("dns_fingerprints_3d-2-" + current_date + ".pdf")

        fig=plt.figure()

    if args.opt_reduce2d:
        pca = PCA(2)
        pca.fit(metrics_df[to_model_columns])
        res=pd.DataFrame(pca.transform(metrics_df[to_model_columns]))
        Z = np.array(res)
        plt.title("DNS_Fingerprints_2D")
        plt.contourf( Z, cmap=plt.cm.Blues_r)
        b1 = plt.scatter(res[0], res[1], c='green',
                        s=20,label="normal")
        b1 =plt.scatter(res.iloc[outlier_index,0],res.iloc[outlier_index,1], c='red',
                        s=20,label="anormal")
        plt.legend(loc="upper right")
        plt.show()
        fig.savefig("dns_fingerprint_2d.pdf")

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
        ####
        #init_notebook_mode(connected=True)
        warnings.filterwarnings('ignore')

        ###
        #columna_indice=[i for i in range(len(metrics_df))]
        #metrics_df['index']=columna_indice
        ###

        for i in range(3,len(metrics_df.columns)-1):
            clf.fit(metrics_df.iloc[:,i:i+1])
            pred = clf.predict(metrics_df.iloc[:,i:i+1])
            test_df=pd.DataFrame()

            test_df['load_date']=metrics_df['index']
            #Find decision function to find the score and classify anomalies
            test_df['score']=clf.decision_function(metrics_df.iloc[:,i:i+1])
            test_df['actuals']=metrics_df.iloc[:,i:i+1]
            test_df['anomaly']=pred
            #Get the indexes of outliers in order to compare the metrics     with use case anomalies if required
            outliers=test_df.loc[test_df['anomaly']==-1]
            outlier_index=list(outliers.index)
            test_df=classify_anomalies(test_df,metrics_df.columns[i])
            plot_anomaly(test_df,metrics_df.columns[i])


if __name__ == "__main__":
    main()