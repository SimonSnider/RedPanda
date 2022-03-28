import numpy as np
from panda_red.models.correlations import *

def matrix_multiply(a, b):
    """
    This function carries out matrix multiplication
    inputs:
    a - matrix on the left
    b - matrix on the right
    outputs:
    product - the result of multiplying a*b
    """
    if len(a[0]) != len(b):
        return None
    product = np.zeros((len(a), len(b[0])))
    for x in range(len(a)):
        for y in range(len(b[0])):
            sum = 0
            for i in range(len(b)):
                sum += (a[x][i])*(b[i][y])
            product[x][y] = sum
    return product


def transpose(matr):
    output = np.zeros((len(matr[0]), len(matr)))
    for i in range(len(matr)):
        for j in range(len(matr[0])):
            output[j][i] = matr[i][j]
    return output


def propagate(corr):
    numInstructions = len(corr)
    triangle = np.zeros((numInstructions, numInstructions, 3))
    finalRegToReg = corr[0].regToReg
    for i in range(len(corr) - 1):
        finalRegToReg = matrix_multiply(finalRegToReg, corr[i+1].regToReg)
    # finalRegToReg represents the correlations between registers over the course of the entire instruction sequence

    for i in range(numInstructions):
        for j in range(i+1, numInstructions):
            t = TriangleEntry()
            t.readDataToReadAddress = matrix_multiply(corr[i].readDataToReg, transpose(corr[j].regToReadAddress))
            t.readDataToWriteData = matrix_multiply(corr[i].readDataToReg, transpose(corr[j].regToWriteData))
            t.readDataToWriteAddress = matrix_multiply(corr[i].readDataToReg, transpose(corr[j].regToWriteAddress))
            triangle[i][j] = t
    readDataToReg = []
    regToReadAddress = []
    regToWriteData = []
    regToWriteAddress = []
    for i in range(len(corr)):
        readDataToReg.append(corr[i].readDataToReg)
        regToReadAddress.append(corr[i].regToReadAddress)
        regToWriteData.append(corr[i].regToWriteData)
        regToWriteAddress.append(corr[i].regToWriteAddress)
    output = NonRectangularPseudoMatrix()
    output.regToReg = finalRegToReg
    output.triangle = triangle
    output.readDataToReg = readDataToReg
    output.regToReadAddress = regToReadAddress
    output.regToWriteData = regToWriteData
    output.regToWriteAddress = regToWriteAddress

    return output
