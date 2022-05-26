#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Dec 16 10:10:04 2020

@author: Vicente Quezada
@modified by: Fabian Astudillo <fabian.astudillos@ucuenca.edu.ec>
"""

#Librerías

import pandas as pd
import numpy as np
import matplotlib.pylab as plt
from sklearn.metrics import confusion_matrix
#from sklearn.cross_validation import train_test_split
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report
import sklearn.metrics
from sklearn import datasets
# The Randon Forest algorithm is imported from sklearn.ensamble
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import ExtraTreesClassifier
from datetime import date
import datetime as dt
import os.path
import sys
import joblib
from argparse import ArgumentParser


class RandomForestDetectionModel:
    """This class generates the fingerprints"""

    def __init__(self, filename_base="/bndf/adf/dmrf-", n_estimators=25):
        # dmrf = Detection Model Random Forest
        self.n_estimators = n_estimators
        today = date.today()
        today = today - dt.timedelta(days=1)
        self.current_date = today.strftime("%Y.%m.%d")
        self.filename_anomalies = "/bndf/adf/FP_anomalies_target-last.csv"
        self.filename_fingerprint = "/var/log/bndf/fingerprints-last.csv"
        self.filename_predictions = "/bndf/adf/predictions-" + self.current_date + ".csv"
        self.filename_predictions_last = "/bndf/adf/predictions-last.csv"
        self.filename_confusion_matrix = filename_base + 'conf_matrix-' + self.current_date + '.csv'
        self.filename_trainedmodel = filename_base + 'trained_model-' + self.current_date + '.job'
        self.filename_trainedmodel_last = filename_base + 'trained_model-last.job'
        self.filename_classification_report_csv = filename_base + 'class_report-' + self.current_date + '.csv'
        self.filename_classification_report_json = filename_base + 'class_report-' + self.current_date + '.json'
        self.filename_accuracy = filename_base + 'accuracy-' + self.current_date + '.csv'
        self.filename_iop = filename_base + 'iop-' + self.current_date + '.csv'
        self.parameters = ['P1','P2','P3','P4','P5','P6','P7','P8','P9','P10','P11','P12','P15']
        self.description = ["Number of DNS requests per hour",
                "Number of different DNS requests per hour",
                "Highest number of requests for a single domain per hour",
                "Average number of requests per minute",
                "Most requests per minute",
                "Number of MX record queries per hour",
                "Number of PTR records queries per hour",
                "Number of different DNS servers queried per hour",
                "Number of different TLD domains queried per hour",
                "Number of different SLD domains consulted per hour",
                "Uniqueness ratio per hour",
                "Number of failed / NXDOMAIN queries per hour",
                "Hourly flow rate"]
            
    def __ReadAnomalies(self):

        # Load the anomalies file
        try:
            AH_data = pd.read_csv(self.filename_anomalies)
        except FileNotFoundError as e:
            print(f"File {self.filename_anomalies} not found! You have to run AnomalyDetection.py script", file=sys.stderr)
            exit(-1)

        # Remove the missing values
        data_clean = AH_data.dropna()

        #comprobar si se han leído
        #data_clean.dtypes
        #data_clean.describe()

        #Predictors and target
        # TODO: Add a option to select 13 o 15 attributes
        #predictors = data_clean[['P1','P2','P3','P4','P5',
        #                         'P6','P7','P8','P9','P10',
        #                         'P11','P12','P13','P14','P15']]
        self.predictors = data_clean[['P1','P2','P3','P4','P5',
                                'P6','P7','P8','P9','P10',
                                'P11','P12','P15']]
        self.targets = data_clean.anomaly

    def __Train(self):
        # It is created the training and test sample, the test is 30%
        # pred_train = predictor_train, pred_test = predictor_test
        # tar_train = target_train, tar_test = target_test
        self.pred_train, self.pred_test, self.tar_train, self.tar_test = train_test_split(
                self.predictors, self.targets, test_size=.3, random_state=0)
        
    def __LoadFingerprints(self):
        # Previously, the classifier should be load
        # Load the fingerprint file
        AH_data = pd.read_csv(self.filename_fingerprint)

        # Remove the missing values
        self.__data_clean = AH_data.dropna()

        #comprobar si se han leído
        #data_clean.dtypes
        #data_clean.describe()

        #Predictors and target
        # TODO: Add a option to select 13 o 15 attributes
        #predictors = data_clean[['P1','P2','P3','P4','P5',
        #                         'P6','P7','P8','P9','P10',
        #                         'P11','P12','P13','P14','P15']]
        #self.predictors = data_clean[['P1','P2','P3','P4','P5',
        #                        'P6','P7','P8','P9','P10',
        #                        'P11','P12','P15']]
        self.pred_test = self.__data_clean[['P1','P2','P3','P4','P5',
                                'P6','P7','P8','P9','P10',
                                'P11','P12','P15']]
        #self.targets = data_clean.anomaly


    def __Classify(self):
        # Start Random For`est algorithm with the specific number of trees
        classifier=RandomForestClassifier(n_estimators=self.n_estimators)
        #classifier=RandomForestClassifier(n_estimators=10, max_depth=None, min_samples_split=2, random_state=0)

        # It is build the model on the training data
        self.classifier=classifier.fit(self.pred_train,self.tar_train)

    def __SaveModel(self):
        # The model is saved
        joblib.dump(self.classifier, self.filename_trainedmodel)
        joblib.dump(self.classifier, self.filename_trainedmodel_last)

    def __LoadModel(self):
        # The model is loaded
        self.classifier = joblib.load(self.filename_trainedmodel_last)

    def __Predict(self):
        # The values of the test group is predicted
        self.predictions=self.classifier.predict(self.pred_test)
        self.df = self.__data_clean
        self.df['anomaly'] = self.predictions
    
    def __SavePredictions(self):
        if os.path.exists(self.filename_predictions):
            os.remove(self.filename_predictions)
        self.df.to_csv(self.filename_predictions, index=None)
        self.df.to_csv(self.filename_predictions_last, index=None)
        
    def __SaveConfusionMatrix(self):
        # The confusion matrix of the predictions of the Test group is requested.
        conf_matrix=sklearn.metrics.confusion_matrix(self.tar_test,self.predictions)
        df_confmatrix=pd.DataFrame(conf_matrix)
        df_confmatrix.to_csv(self.filename_confusion_matrix, index=None, mode="w", header=not os.path.isfile(self.filename_confusion_matrix))

    def __SaveClassificationReport(self):
        # The Classification_report is get
        # Save to json
        original_stdout = sys.stdout
        class_report = sklearn.metrics.classification_report(self.tar_test, self.predictions, output_dict=True)
        with open(self.filename_classification_report_json, 'w') as f:
            sys.stdout = f # Change the standard output to the file we created.
            print(class_report)
            sys.stdout = original_stdout
    
        # Save to csv
        class_report = sklearn.metrics.classification_report(self.tar_test, self.predictions)
        with open(self.filename_classification_report_csv, 'w') as f:
            sys.stdout = f # Change the standard output to the file we created.
            print(class_report)
            sys.stdout = original_stdout
        #df_class_report=pd.DataFrame(class_report).transpose()
        #df_class_report.to_csv(path, index=None, mode="w", header=not os.path.isfile(path))

    def __SaveAccuracy(self):
        # The accuracy score index is get, which summarizes the Confusion Matrix and the number of correct answers.
        # fd = filedescriptor
        accuracy_score = sklearn.metrics.accuracy_score(self.tar_test, self.predictions)
        fd_accuracy = open(self.filename_accuracy, "a")
        fd_accuracy.write(str(self.n_estimators) + "," + str(accuracy_score))
        fd_accuracy.close()

#df_accuracy_score=pd.DataFrame(accuracy_score)
#df_accuracy_score.to_csv(path, index=None, mode="w", header=not os.path.isfile(path))

    def __SaveImportanceVariable(self):
        # To obtain the importance of each variable it is initialized the ExtraTreesClassifier
        self.model = ExtraTreesClassifier()
        # The model is fit 
        self.model.fit(self.pred_train,self.tar_train)

        #from sklearn.metrics import plot_confusion_matrix

        #print(classifier)

        #plot_confusion_matrix(classifier)  
        #print(confusion_matrix(tar_test, predictions))
        #plt.show()

        #Pedimos que nos muestre la importancia de cada variable
        #print(model.feature_importances_)

        #Si queremos ver todas las variables en caso de ser muchas, mejor usar el comando «list»
        #list(model.feature_importances_)

        #        "P13","Number of different cities of resolved IP addresses",
        #        "P14","Number of different countries of resolved IP addresse",
            
        #des=["Numero de solicitudes DNS por hora",
        #        "Numero de solicitudes DNS distintas por hora",
        #        "Mayor cantidad de solicitudes para un solo dominio por hora",
        #        "Numero medio de solicitudes por minuto",
        #        "La mayor cantidad de solicitudes por minuto",
        #        "Número de consultas de registros MX por hora",
        #        "Número de consultas de registros PTR por hora",
        #        "Número de servidores DNS distintos consultados por hora",
        #        "Número de dominios de TLD distintos consultados por hora",
        #        "Número de dominios SLD distintos consultados por hora",
        #        "Relación de unicidad por hora",
        #        "Número de consultas fallidas / NXDOMAIN por hora",
        #        "Número de ciudades distintas de direcciones IP resueltas",
        #        "Número de países distintos de direcciones IP resueltas",
        #        "Relación de flujo por hora"]

        # Importance of the parameters
        iop=self.model.feature_importances_
        data={"parameter":self.parameters,"description":self.description,"percentage":np.round(iop,3)}
        df=pd.DataFrame(data,columns=["parameter","description","percentage"])
        df=df.sort_values(by=["percentage"], ascending=False)
        df.to_csv(self.filename_iop, index=None, mode="w", header=not os.path.isfile(self.filename_iop))

        #a=list(iop)
        #b=sorted(a, reverse=True)
        #c=[]
        #for item in b:
        #    c.append((a.index(item))+1)
        #e=[description[item-1] for item in c]
        #d=["P"+str(item) for item in c]

        #from tabulate import tabulate
        #print("\n")
        #l = [[a,b,round(c,3)] for a,b,c in zip(d,e,b)]
        #table = tabulate(l, headers=['Parameter', 'Description', 'Percentage'], tablefmt='orgtbl')
        #print(table)

        #To draw all variables with their importance
        #from matplotlib import pyplot
        #pyplot.figure()
        #pyplot.title("Importance of attributes")
        #pyplot.xlabel("Attribute")
        #pyplot.ylabel("Percentage de importance")
        #pyplot.bar(d, b)
        #pyplot.show()

    def __GetPerformanceEstimators(self):
        #To see how much each new tree we have built has contributed
        accuracy=np.zeros(self.n_estimators)

        from time import time
        time_t=np.zeros(self.n_estimators)
        estimators=np.zeros(self.n_estimators)
        print("getPerformanceEstimators")
        for idx in range(0,self.n_estimators):
            estimators[idx] = idx+1
            classifier=RandomForestClassifier(n_estimators=idx+1)
            start_time = time()
            classifier=classifier.fit(self.pred_train,self.tar_train)
            predictions=classifier.predict(self.pred_test)
            elapsed_time = time() - start_time
            time_t[idx] = round(elapsed_time,3)
            accuracy[idx]=sklearn.metrics.accuracy_score(self.tar_test, predictions)
            print("estimators: " + str(idx+1) + ", time: " + str(time_t[idx]) + ", accuracy: " + str(accuracy[idx]))

        data={"estimators":estimators,"time":time_t,"accuracy":accuracy}
        df=pd.DataFrame(data,columns=["estimators","time","accuracy"])
        df.to_csv(self.filename_accuracy, index=None, mode="w", header=not os.path.isfile(self.filename_iop))

#        plt.figure()
#        plt.title("Precisión vs Número de árboles")
#        plt.xlabel("Numero de Árboles")
#        plt.ylabel("Porcentaje de precisión")
#        plt.plot(trees, accuracy)
#        plt.show()

#        tiempo1=[item*100 for item in time_t]

#        plt.figure()
#        plt.title("Tiempo vs Número de árboles")
#        plt.xlabel("Numero de Árboles")
#        plt.ylabel("Segundos")
#        plt.plot(trees, tiempo1)
#        plt.show()

        sklearn.metrics
        sklearn.metrics.accuracy_score(self.tar_test, predictions)
        
    def GenerateModel(self):
        self.__ReadAnomalies()
        self.__Train()
        self.__Classify()
        self.__SaveModel()
        self.__Predict()
        self.__SaveConfusionMatrix()
        self.__SaveClassificationReport()
        self.__SaveAccuracy()
        self.__SaveImportanceVariable()
        
    def ModelEstimators(self):
        self.__ReadAnomalies()
        self.__Train()
        self.__GetPerformanceEstimators()
        
    def Predict(self):
        self.__LoadFingerprints()
        self.__LoadModel()
        self.__Predict()
        self.__SavePredictions() 
        
def main():
    parser = ArgumentParser(
            description='Detection model using random forest',
            epilog="This script generate the model using random forest")

    # Add the arguments to the parser
    parser.add_argument("-d", "--date", dest="date", required=False,
    help="The date to be processed in ISO format example '2021-08-23T00:00:00Z'")
    parser.add_argument("-g", "--generatemodel", dest="generatemodel", action='store_true', required=False,
    help="This option allows generate the model using Random Forest, the model is saved in a file")
    parser.add_argument("-m", "--modelestimators", dest="modelestimators", action='store_true', required=False,
    help="Generate a csv where is calculated the time and accuracy in function of the number of estimators")
    parser.add_argument("-s", "--estimators", type=int, dest="opt_est", required=False,
    help="Set the number of estimators")
    parser.add_argument("-p", "--predict", dest="predict", action='store_true', required=False,
    help="This option allows predict if the fingerprints generated at the last hour are bots, the model is loaded from a file")

    #args = vars(ap.parse_args())
    args = parser.parse_args()
    n_estimators = 25
    if args.opt_est:
        n_estimators = args.opt_est
    
    rfdm=RandomForestDetectionModel(n_estimators=n_estimators)

    if args.generatemodel:
        rfdm.GenerateModel()
    elif args.modelestimators:
        rfdm.ModelEstimators()
    elif args.predict:
        rfdm.Predict()

if __name__ == "__main__":
    main()
