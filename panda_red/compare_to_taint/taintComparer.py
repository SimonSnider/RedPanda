from panda_red.models.correlations import *

def convertMatrixToDict(matrix, threshold):
    newModel = {}
    for index1 in range(len(matrix)):
        ls = matrix[index1]
        labelSet = []
        for index2 in range(len(ls)):
            if ls[index2] >= threshold:
                labelSet.append(index2)
        newModel[index1] = labelSet
#        print(str(index1) + " " + str(labelSet))
    return newModel

def extractNewModel(corr: Correlations):
    """
    corr - the Correlations object that describes the new model
    This function formats the data in the correlations model into a dictionary similar to pandaModel in the compare function
    """
    return convertMatrixToDict(corr.regToReg, corr.threshold)

def compare(pandaModel, ourCorr: Correlations):
    """
    pandaModel - the correlation model from PANDA
    corr - the Correlations object that describes the new model
    This function compares the two models and outputs the differences
    """

    newModel = extractNewModel(ourCorr)
    pandaModel = convertMatrixToDict(pandaModel, 0.5)
    pandaTainted = {}
    newTainted = {}
    for reg in pandaModel.keys():
        pTainted = pandaModel[reg]
        nTainted = newModel[reg]
        ls1 = []
        ls2 = []
        for i in pTainted:
            if i not in nTainted:
                ls1.append(i)
        for i in nTainted:
            if i not in pTainted:
                ls2.append(i)
        if ls1 != []:
            pandaTainted[reg] = ls1
        if ls2 != []:
            newTainted[reg] = ls2
    return [pandaTainted, newTainted]
