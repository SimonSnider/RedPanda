from panda_red.models.correlations import *



def extractNewModel(corr: Correlations):
    """
    corr - the Correlations object that describes the new model
    This function formats the data in the correlations model into a dictionary similar to pandaModel in the compare function
    """
    threshold = corr.threshold
    newModel = {}
    for index1 in range(len(corr.regToReg)):
        ls = corr.regToReg[index1]
        labelSet = []
        for index2 in range(len(ls)):
            if ls[index2] >= threshold:
                labelSet.append(index2)
        newModel[index1] = labelSet
    return newModel


def compare(pandaModel, corr: Correlations):
    """
    pandaModel - the correlation model from PANDA
    corr - the Correlations object that describes the new model
    This function compares the two models and outputs the differences
    """
    newModel = extractNewModel(corr)
    pandaTainted = {}
    newTainted = {}
    for (regname, reg) in pandaModel.keys():
        pTainted = pandaModel[(regname, reg)]
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
            pandaTainted[(regname, reg)] = ls1
        if ls2 != []:
            newTainted[reg] = ls2
    return [pandaTainted, newTainted]
