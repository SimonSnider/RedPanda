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

    n = len(pandaModel[0][0])
    pandaRegToWrites = pandaModel[1]
    print(pandaRegToWrites)
    pandaReadToReg = pandaModel[0][n:]
    print(pandaReadToReg)
    pandaModel = pandaModel[0][:n]

    newModel = extractNewModel(ourCorr)
    pandaModel = convertMatrixToDict(pandaModel, 0.5)
    pandaTaintedRegs = {}
    newTaintedRegs = {}
    
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
            pandaTaintedRegs[reg] = ls1
        if ls2 != []:
            newTaintedRegs[reg] = ls2

    newModelReads = convertMatrixToDict(ourCorr.readDataToReg, ourCorr.threshold)
    pandaModelReads = convertMatrixToDict(pandaReadToReg, 0.5)
    pandaTaintedReads = {}
    newTaintedReads = {}

    for read in pandaModelReads.keys():
        pTainted = pandaModel[read]
        nTainted = newModel[read]
        ls1 = []
        ls2 = []
        for i in pTainted:
            if i not in nTainted:
                ls1.append(i)
        for i in nTainted:
            if i not in pTainted:
                ls2.append(i)
        if ls1 != []:
            pandaTaintedReads[read] = ls1
        if ls2 != []:
            newTaintedReads[read] = ls2
            

    pandaTaintedWrites = {}
    newTaintedWrites = {}
            

    pandaTainted = {'reg to reg': pandaTaintedRegs, 'reads to reg': pandaTaintedReads, 'reg to writes': pandaTaintedWrites}
    newTainted = {'reg to reg': newTaintedRegs, 'reads to reg': newTaintedReads, 'reg to writes': newTaintedWrites}
    return [pandaTainted, newTainted]
