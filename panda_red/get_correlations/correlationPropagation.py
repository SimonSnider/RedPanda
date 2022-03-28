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
            t.readValToReadAddress = matrix_multiply(corr[i].readDataToReg, corr[j].regToReadAddress)
            t.readValToWriteVal = matrix_multiply(corr[i].readDataToReg, corr[j].regToWriteData)
            t.readValToWriteAddress = matrix_multiply(corr[i].readDataToReg, corr[j].regToWriteAddress)
            triangle[i][j] = t

    output = NonRectangularPseudoMatrix()
    output.regToReg = finalRegToReg
    output.triangle = triangle
