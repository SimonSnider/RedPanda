import numpy as np
from panda_red.models.correlations import *

def matrix_multiply(a: Matrix, b: Matrix):
    """
    This function carries out matrix multiplication
    inputs:
    a - matrix on the left
    b - matrix on the right
    outputs:
    product - the result of multiplying a*b
    """
    if a.numCols != b.numRows:
        return None
    if a.numRows == 0 or b.numCols == 0:
        ret = Matrix()
        ret.numRows = a.numRows
        ret.numCols = b.numCols
        ret.matrix = None
    product = [[0]*a.numRows for _ in range(b.numCols)]
    for x in range(a.numRows):
        for y in range(b.numCols):
            sum = 0
            for i in range(b.numRows):
                sum += (a.matrix[x][i])*(b.matrix[i][y])
            product[x][y] = sum
    output = toMatrix(product)
    return output


def transpose(matr: Matrix):
    if matr.numRows == 0 or matr.numCols == 0:
        ret = Matrix()
        ret.numRows = matr.numCols
        ret.numCols = matr.numRows
        ret.matrix = None
    output = [[0]*matr.numCols for _ in range(matr.numRows)]
    for i in range(matr.numRows):
        for j in range(matr.numCols):
            output[j][i] = matr[i][j]
    trans = toMatrix(output)
    return trans

def toMatrix(matr):
    if type(matr) is Matrix:
        return matr

    m = Matrix()
    m.numRows = len(matr)
    if type(matr[0]) is Matrix:
        m.numCols = matr[0].numRows
    else:
        m.numCols = len(matr[0])
    m.matrix = matr
    return m


def propagate(corr):
    numInstructions = len(corr)
    triangleMatr = [[None]*numInstructions for _ in range(numInstructions)]
    finalRegToReg = corr[0].regToReg
    for i in range(len(corr) - 1):
        finalRegToReg = matrix_multiply(toMatrix(finalRegToReg), toMatrix(corr[i+1].regToReg))
    # finalRegToReg represents the correlations between registers over the course of the entire instruction sequence

    for i in range(numInstructions):
        for j in range(i+1, numInstructions):
            t = TriangleEntry()
            t.readDataToReadAddress = matrix_multiply(toMatrix(corr[i].readDataToReg), transpose(toMatrix(corr[j].regToReadAddress)))
            t.readDataToWriteData = matrix_multiply(toMatrix(corr[i].readDataToReg), transpose(toMatrix(corr[j].regToWriteData)))
            t.readDataToWriteAddress = matrix_multiply(toMatrix(corr[i].readDataToReg), transpose(toMatrix(corr[j].regToWriteAddress)))
            triangleMatr[i][j] = t
    readDataToReg = []
    regToReadAddress = []
    regToWriteData = []
    regToWriteAddress = []
    for i in range(len(corr)):
        readDataToReg.append(toMatrix(corr[i].readDataToReg))
        regToReadAddress.append(toMatrix(corr[i].regToReadAddress))
        regToWriteData.append(toMatrix(corr[i].regToWriteData))
        regToWriteAddress.append(toMatrix(corr[i].regToWriteAddress))
    output = NonRectangularPseudoMatrix()
    output.regToReg = finalRegToReg
    output.triangle = toMatrix(triangleMatr)
    output.readDataToReg = toMatrix(readDataToReg)
    output.regToReadAddress = toMatrix(regToReadAddress)
    output.regToWriteData = toMatrix(regToWriteData)
    output.regToWriteAddress = toMatrix(regToWriteAddress)

    return output
