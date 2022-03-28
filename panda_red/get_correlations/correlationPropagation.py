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
    if a.numCols != b.numColumns:
        return None
    product = [[0]*a.numRows for _ in range(b.numCols)]
    for x in range(a.numRows):
        for y in range(b.numCols):
            sum = 0
            for i in range(b.numRows):
                sum += (a[x][i])*(b[i][y])
            product[x][y] = sum
    output = toMatrix(product)
    return output


def transpose(matr):
    if matr.numRows == 0:
        return []
    output = [[0]*matr.numCols for _ in range(matr.numRows)]
    for i in range(matr.numRows):
        for j in range(matr.numCols)):
            output[j][i] = matr[i][j]
    trans = toMatrix(output)
    return trans
    

def toMatrix(matr):
    m = Matrix()
    m.numRows = len(matr)
    m.numCols = len(matr[0])
    m.matrix = matr
    return m


def propagate(corr):
    numInstructions = len(corr)
    triangleMatr = [[None]*numInstructions for _ in range(numInstructions)]
    finalRegToReg = corr[0].regToReg
    for i in range(len(corr) - 1):
        finalRegToReg = matrix_multiply(finalRegToReg, corr[i+1].regToReg)
    # finalRegToReg represents the correlations between registers over the course of the entire instruction sequence

    for i in range(numInstructions):
        for j in range(i+1, numInstructions):
            t = TriangleEntry()
            t.readDataToReadAddress = matrix_multiply(toMatrix(corr[i].readDataToReg), toMatrix(transpose(corr[j].regToReadAddress)))
            t.readDataToWriteData = matrix_multiply(toMatrix(corr[i].readDataToReg), toMatrix(transpose(corr[j].regToWriteData)))
            t.readDataToWriteAddress = matrix_multiply(toMatrix(corr[i].readDataToReg), toMatrix(transpose(corr[j].regToWriteAddress)))
            triangle[i][j] = t
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
    output.triangle = triangle
    output.readDataToReg = readDataToReg
    output.regToReadAddress = regToReadAddress
    output.regToWriteData = regToWriteData
    output.regToWriteAddress = regToWriteAddress

    return output
