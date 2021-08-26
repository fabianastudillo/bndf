#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Dec 16 10:10:04 2020

@author: vicente
"""

#Librerías

import pandas as pd
import numpy as np
import matplotlib.pylab as plt
#from sklearn.cross_validation import train_test_split
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report
import sklearn.metrics
from sklearn import datasets
from sklearn.ensemble import ExtraTreesClassifier

#Cargar Fichero
AH_data = pd.read_csv("../Tesis/FP_anomalies_target1.csv")

#Eliminar Valores missing
data_clean = AH_data.dropna()

#comprobar si se han leído
#data_clean.dtypes
#data_clean.describe()

#Predictoras y objetivo
predictors = data_clean[['P1','P2','P3','P4','P5',
                         'P6','P7','P8','P9','P10',
                         'P11','P12','P13','P14','P15']]
targets = data_clean.anomaly

#Creamos la muestra de entrenamiento y de test, 
#siendo test el 30%
pred_train, pred_test, tar_train, tar_test = train_test_split(
        predictors, targets, test_size=.3, random_state=0)

#Importamos desde sklearn.ensamble, el algoritmo de Random Forest
from sklearn.ensemble import RandomForestClassifier

#Iniciar algoritmo Random Forest con numero de arboles=10
classifier=RandomForestClassifier(n_estimators=25)
#classifier=RandomForestClassifier(n_estimators=10, max_depth=None, min_samples_split=2, random_state=0)

#Construimos el modelo sobre los datos de entrenamiento
classifier=classifier.fit(pred_train,tar_train)

#guardamos el modelo
import joblib
joblib.dump(classifier, 'modelo_entrenado.joblib')

#cargar el modelo
classifier = joblib.load('modelo_entrenado.joblib')

#Predecimos para los valores del grupo Test
predictions=classifier.predict(pred_test)


#ver resultados

#Pedimos la matriz de confusión de las predicciones del grupo Test.
print(sklearn.metrics.confusion_matrix(tar_test,predictions)) 

#Sacamos el índice Classification_report,
print(sklearn.metrics.classification_report(tar_test, predictions))

#Sacamos el índice Accuracy Score, que resume la Matriz de Confusión y la cantidad de aciertos.
print(sklearn.metrics.accuracy_score(tar_test, predictions))

#Para obtener la importancia de cada variable inicializamos el  ExtraTreesClassifier
model = ExtraTreesClassifier()

#Ajustamos el modelo
model.fit(pred_train,tar_train)

from sklearn.metrics import plot_confusion_matrix
plot_confusion_matrix(classifier)  
plt.show()

#Pedimos que nos muestre la importancia de cada variable
#print(model.feature_importances_)

#Si queremos ver todas las variables en caso de ser muchas, mejor usar el comando «list»
#list(model.feature_importances_)

des=["Numero de solicitudes DNS por hora",
        "Numero de solicitudes DNS distintas por hora",
        "Mayor cantidad de solicitudes para un solo dominio por hora",
        "Numero medio de solicitudes por minuto",
        "La mayor cantidad de solicitudes por minuto",
        "Número de consultas de registros MX por hora",
        "Número de consultas de registros PTR por hora",
        "Número de servidores DNS distintos consultados por hora",
        "Número de dominios de TLD distintos consultados por hora",
        "Número de dominios SLD distintos consultados por hora",
        "Relación de unicidad por hora",
        "Número de consultas fallidas / NXDOMAIN por hora",
        "Número de ciudades distintas de direcciones IP resueltas",
        "Número de países distintos de direcciones IP resueltas",
        "Relación de flujo por hora"]
a=model.feature_importances_
a=list(a)
b=sorted(a, reverse=True)
c=[]
for item in b:
    c.append((a.index(item))+1)
e=[des[item-1] for item in c]
d=["P"+str(item) for item in c]

from tabulate import tabulate
print("\n")
l = [[a,b,round(c,3)] for a,b,c in zip(d,e,b)]
table = tabulate(l, headers=['Parámetro', 'Descripción', 'Porcentaje'], tablefmt='orgtbl')
print(table)

#Para dibujar todos las variables con su importancia
from matplotlib import pyplot
pyplot.figure()
pyplot.title("Importancia de las Atributos")
pyplot.xlabel("Atributo")
pyplot.ylabel("Porcentaje de Importancia")
pyplot.bar(d, b)
pyplot.show()

#Para ver cuánto ha aportado cada nuevo árbol que hemos construido
"""
trees=range(1,41)
accuracy=np.zeros(40)

from time import time
tiempo=[]

for idx in range(0,len(trees)):
    classifier=RandomForestClassifier(n_estimators=idx+1)
    start_time = time()
    classifier=classifier.fit(pred_train,tar_train)
    predictions=classifier.predict(pred_test)
    elapsed_time = time() - start_time
    tiempo.append(round(elapsed_time,3))
    accuracy[idx]=sklearn.metrics.accuracy_score(tar_test, predictions)

plt.figure()
plt.title("Precisión vs Número de árboles")
plt.xlabel("Numero de Árboles")
plt.ylabel("Porcentaje de precisión")
plt.plot(trees, accuracy)
plt.show()

tiempo1=[item*100 for item in tiempo]

plt.figure()
plt.title("Tiempo vs Número de árboles")
plt.xlabel("Numero de Árboles")
plt.ylabel("Segundos")
plt.plot(trees, tiempo1)
plt.show()

sklearn.metrics
sklearn.metrics.accuracy_score(tar_test, predictions)
"""