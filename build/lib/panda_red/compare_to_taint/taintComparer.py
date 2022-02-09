from panda_red.models.correlations import *



def extractNewModel(pandaModel, corr: Correlations):
    threshold = corr.threshold
    newModel = {}
    for index1 in range(len(newModel.regToReg)):
        ls = newModel.regToReg[index1]
        labelSet = []
        for index2 in range(len(ls)):
            if  ls[index2] >= threshold:
                labelSet.append(index2)
        newModel[index1] = ls
    return newModel


def compare(pandaModel, corr: Correlations):
    threshold = corr.threshold
    newModel = extractNewModel(pandaModel, corr)
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
        pandaTainted[(regname, reg)] = ls1
        newTainted[reg] = ls2
    return [pandaTainted, newTainted]
