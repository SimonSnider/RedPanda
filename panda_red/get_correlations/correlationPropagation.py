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
    if a.numRows == 1:
        product = [product]
    output = toMatrix(product)
    return output


def transpose(matr: Matrix):
    if matr.numRows == 0 or matr.numCols == 0:
        ret = Matrix()
        ret.numRows = matr.numCols
        ret.numCols = matr.numRows
        ret.matrix = None
    output = [[0]*matr.numRows for _ in range(matr.numCols)]
    for i in range(matr.numRows):
        for j in range(matr.numCols):
            output[j][i] = matr.matrix[i][j]
    trans = toMatrix(output)
    return trans

def toMatrix(matr):
    if type(matr) is Matrix: return matr
    m = Matrix()
    m.numRows = len(matr)
    if m.numRows == 0:
        m.numCols = 0
        m.matrix = None
        return m
    if type(matr[0]) is Matrix:
        m.numCols = matr[0].numRows
    else:
        if matr[0] == None:
            print(matr)
            raise ImportError
        m.numCols = len(matr[0])
    m.matrix = matr
    if m.numCols == 0: m.matrix = None
    return m


def propagate(corr):
    numInstructions = len(corr)
    triangleMatr = [[None]*numInstructions for _ in range(numInstructions)]
    regToRegs = [0]*numInstructions
    regToRegs[0] = toMatrix(corr[0].regToReg)
    for i in range(len(corr) - 1):
        regToRegs[i+1] = matrix_multiply(regToRegs[i], toMatrix(corr[i+1].regToReg))

    for i in range(numInstructions):
        for j in range(i+1, numInstructions):
            t = TriangleEntry()
            readTranspose = transpose(toMatrix(corr[i].readDataToReg))
            t.readDataToReadAddress = matrix_multiply(readTranspose, toMatrix(corr[j].regToReadAddress))
            t.readDataToWriteData = matrix_multiply(readTranspose, toMatrix(corr[j].regToWriteData))
            t.readDataToWriteAddress = matrix_multiply(readTranspose, toMatrix(corr[j].regToWriteAddress))
            triangleMatr[i][j] = t
    readDataToReg = []
    regToReadAddress = []
    regToWriteData = []
    regToWriteAddress = []
    for i in range(len(corr)):
        if i==9:
            print(toMatrix(corr[i].readDataToReg))
            print(regToRegs[i])
        readDataToReg.append(matrix_multiply(toMatrix(corr[i].readDataToReg), regToRegs[i]))
        regToReadAddress.append(matrix_multiply(regToRegs[i], transpose(toMatrix(corr[i].regToReadAddress))))
        regToWriteData.append(matrix_multiply(regToRegs[i], transpose(toMatrix(corr[i].regToWriteData))))
        regToWriteAddress.append(matrix_multiply(regToRegs[i], transpose(toMatrix(corr[i].regToWriteAddress))))
    readDataToReg = [readDataToReg]
    regToReadAddress = [regToReadAddress]
    regToWriteData = [regToWriteData]
    regToWriteAddress = [regToWriteAddress]
    output = NonRectangularPseudoMatrix()
    output.regToReg = regToRegs[-1]
    output.triangle = toMatrix(triangleMatr)
    output.readDataToReg = toMatrix(readDataToReg)
    output.regToReadAddress = toMatrix(regToReadAddress)
    output.regToWriteData = toMatrix(regToWriteData)
    output.regToWriteAddress = toMatrix(regToWriteAddress)

    return output
