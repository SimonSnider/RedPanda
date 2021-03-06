import unittest
from red_panda.get_correlations import correlationPropagation as prop
from red_panda.models.correlations import *

class TestPropagation(unittest.TestCase):
    def testNoMem(self):
        #1 R1 = R2 + R3
        #2 R4 = R1 + (-1)
    
        inst1 = Correlations()
        inst1.regToReg = [[1,0,0,0,0],[0,0,0,0,0],[0,1,1,0,0],[0,1,0,1,0],[0,0,0,0,1]]
        inst1.regToReadAddress = [[],[],[],[],[]]
        inst1.readDataToReg = [[],[],[],[],[]]
        inst1.regToWriteAddress = [[],[],[],[],[]]
        inst1.regToWriteData = [[],[],[],[],[]]
    
        inst2 = Correlations()
        inst2.regToReg = [[1,0,0,0,0],[0,1,0,0,1],[0,0,1,0,0],[0,0,0,1,0],[0,0,0,0,0]]
        inst2.regToReadAddress = [[],[],[],[],[]]
        inst2.readDataToReg = [[],[],[],[],[]]
        inst2.regToWriteAddress = [[],[],[],[],[]]
        inst2.regToWriteData = [[],[],[],[],[]]
    
        actual = prop.propagate([inst1, inst2])
        correctRegToReg = [[1,0,0,0,0], [0,0,0,0,0], [0,1,1,0,1], [0,1,0,1,1], [0,0,0,0,0]]
        assert actual.regToReg.matrix == correctRegToReg

    def testSmallScale(self):
        #1 R1 = R2 + R3
        #2 R2 = M(R3)
        #3 M(R2) = r1
        #4 R4 = R2 + 4
    
        inst1 = Correlations()
        inst1.regToReg = [[1,0,0,0,0],[0,0,0,0,0],[0,1,1,0,0],[0,1,0,1,0],[0,0,0,0,1]]
        inst1.regToReadAddress = [[],[],[],[],[]]
        inst1.readDataToReg = [[],[],[],[],[]]
        inst1.regToWriteAddress = [[],[],[],[],[]]
        inst1.regToWriteData = [[],[],[],[],[]]
    
        inst2 = Correlations()
        inst2.regToReg = [[1,0,0,0,0],[0,1,0,0,0],[0,0,0,0,0],[0,0,0,1,0],[0,0,0,0,1]]
        inst2.regToReadAddress = [[0],[0],[0],[1],[0]]
        inst2.readDataToReg = [[0],[0],[1],[0],[0]]
        inst2.regToWriteAddress = [[],[],[],[],[]]
        inst2.regToWriteData = [[],[],[],[],[]]
    
        inst3 = Correlations()
        inst3.regToReg = [[1,0,0,0,0],[0,1,0,0,0],[0,0,1,0,0],[0,0,0,1,0],[0,0,0,0,1]]
        inst3.regToReadAddress = [[],[],[],[],[]]
        inst3.readDataToReg = [[],[],[],[],[]]
        inst3.regToWriteAddress = [[0],[0],[1],[0],[0]]
        inst3.regToWriteData = [[0],[1],[0],[0],[0]]
    
        inst4 = Correlations()
        inst4.regToReg = [[1,0,0,0,0],[0,1,0,0,0],[0,0,1,0,1],[0,0,0,1,0],[0,0,0,0,0]]
        inst4.regToReadAddress = [[],[],[],[],[]]
        inst4.readDataToReg = [[],[],[],[],[]]
        inst4.regToWriteAddress = [[],[],[],[],[]]
        inst4.regToWriteData = [[],[],[],[],[]]
    
        actual = prop.propagate([inst1, inst2, inst3, inst4])
        correct = NonRectangularPseudoMatrix(regToReg=Matrix(numRows=5, numCols=5, matrix=[[1, 0, 0, 0, 0], [0, 0, 0, 0, 0], [0, 1, 0, 0, 0], [0, 1, 0, 1, 0], [0, 0, 0, 0, 0]]), readDataToReg=Matrix(numRows=1, numCols=4, matrix=[[None, Matrix(numRows=1, numCols=5, matrix=[[0, 0, 1, 0, 1]]), None, None]]), regToReadAddress=Matrix(numRows=1, numCols=4, matrix=[[None, Matrix(numRows=5, numCols=1, matrix=[[0], [0], [0], [1], [0]]), None, None]]), regToWriteData=Matrix(numRows=1, numCols=4, matrix=[[None, None, Matrix(numRows=5, numCols=1, matrix=[[0], [0], [1], [1], [0]]), None]]), regToWriteAddress=Matrix(numRows=1, numCols=4, matrix=[[None, None, Matrix(numRows=5, numCols=1, matrix=[[0], [0], [0], [0], [0]]), None]]), triangle=Matrix(numRows=4, numCols=4, matrix=[[None, TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None)], [None, None, TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=Matrix(numRows=1, numCols=1, matrix=[[1]]), readDataToWriteData=Matrix(numRows=1, numCols=1, matrix=[[0]])), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None)], [None, None, None, TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None)], [None, None, None, None]]))
        assert equalsNonRectangularPseudoMatrix(actual, correct)

    def testLargeScale(self):
        #1  R1 = M(R2)
        #2  M(R3) = R1
        #3  R4 = M(R1)
        #4  M(R0) = R1
        #5  M(R2) = R4
        #6  R2 = M(R0)
        #7  M(R1) = R3
        #8  R1 = 0
        #9  R1 = M(R1)
        #10 M(R2) = R1
    
        inst1 = Correlations()
        inst1.regToReg = [[1,0,0,0,0],[0,0,0,0,0],[0,0,1,0,0],[0,0,0,1,0],[0,0,0,0,1]]
        inst1.regToReadAddress = [[0],[0],[1],[0],[0]]
        inst1.readDataToReg = [[0],[1],[0],[0],[0]]
        inst1.regToWriteAddress = [[],[],[],[],[]]
        inst1.regToWriteData = [[],[],[],[],[]]
    
        inst2 = Correlations()
        inst2.regToReg = [[1,0,0,0,0],[0,1,0,0,0],[0,0,1,0,0],[0,0,0,1,0],[0,0,0,0,1]]
        inst2.regToReadAddress = [[],[],[],[],[]]
        inst2.readDataToReg = [[],[],[],[],[]]
        inst2.regToWriteAddress = [[0],[0],[0],[1],[0]]
        inst2.regToWriteData = [[0],[1],[0],[0],[0]]
    
        inst3 = Correlations()
        inst3.regToReg = [[1,0,0,0,0],[0,1,0,0,0],[0,0,1,0,0],[0,0,0,1,0],[0,0,0,0,0]]
        inst3.regToReadAddress = [[0],[1],[0],[0],[0]]
        inst3.readDataToReg = [[0],[0],[0],[0],[1]]
        inst3.regToWriteAddress = [[],[],[],[],[]]
        inst3.regToWriteData = [[],[],[],[],[]]
    
        inst4 = Correlations()
        inst4.regToReg = [[1,0,0,0,0],[0,1,0,0,0],[0,0,1,0,0],[0,0,0,1,0],[0,0,0,0,1]]
        inst4.regToReadAddress = [[],[],[],[],[]]
        inst4.readDataToReg = [[],[],[],[],[]]
        inst4.regToWriteAddress = [[1],[0],[0],[0],[0]]
        inst4.regToWriteData = [[0],[1],[0],[0],[0]]
    
        inst5 = Correlations()
        inst5.regToReg = [[1,0,0,0,0],[0,1,0,0,0],[0,0,1,0,0],[0,0,0,1,0],[0,0,0,0,1]]
        inst5.regToReadAddress = [[],[],[],[],[]]
        inst5.readDataToReg = [[],[],[],[],[]]
        inst5.regToWriteAddress = [[0],[0],[1],[0],[0]]
        inst5.regToWriteData = [[0],[0],[0],[0],[1]]
    
        inst6 = Correlations()
        inst6.regToReg = [[1,0,0,0,0],[0,1,0,0,0],[0,0,0,0,0],[0,0,0,1,0],[0,0,0,0,1]]
        inst6.regToReadAddress = [[1],[0],[0],[0],[0]]
        inst6.readDataToReg = [[0],[0],[1],[0],[0]]
        inst6.regToWriteAddress = [[],[],[],[],[]]
        inst6.regToWriteData = [[],[],[],[],[]]
    
        inst7 = Correlations()
        inst7.regToReg = [[1,0,0,0,0],[0,1,0,0,0],[0,0,1,0,0],[0,0,0,1,0],[0,0,0,0,1]]
        inst7.regToReadAddress = [[],[],[],[],[]]
        inst7.readDataToReg = [[],[],[],[],[]]
        inst7.regToWriteAddress = [[0],[1],[0],[0],[0]]
        inst7.regToWriteData = [[0],[0],[0],[1],[0]]
    
        inst8 = Correlations()
        inst8.regToReg = [[1,0,0,0,0],[0,0,0,0,0],[0,0,1,0,0],[0,0,0,1,0],[0,0,0,0,1]]
        inst8.regToReadAddress = [[],[],[],[],[]]
        inst8.readDataToReg = [[],[],[],[],[]]
        inst8.regToWriteAddress = [[],[],[],[],[]]
        inst8.regToWriteData = [[],[],[],[],[]]
        
        inst9 = Correlations()
        inst9.regToReg = [[1,0,0,0,0],[0,0,0,0,0],[0,0,1,0,0],[0,0,0,1,0],[0,0,0,0,1]]
        inst9.regToReadAddress = [[0],[1],[0],[0],[0]]
        inst9.readDataToReg = [[0],[1],[0],[0],[0]]
        inst9.regToWriteAddress = [[],[],[],[],[]]
        inst9.regToWriteData = [[],[],[],[],[]]
        
        inst10 = Correlations()
        inst10.regToReg = [[1,0,0,0,0],[0,1,0,0,0],[0,0,1,0,0],[0,0,0,1,0],[0,0,0,0,1]]
        inst10.regToReadAddress = [[],[],[],[],[]]
        inst10.readDataToReg = [[],[],[],[],[]]
        inst10.regToWriteAddress = [[0],[0],[1],[0],[0]]
        inst10.regToWriteData = [[0],[1],[0],[0],[0]]
    
        expected = NonRectangularPseudoMatrix()
        expected.regToReg = [[1,0,0,0,0],[0,0,0,0,0],[0,0,0,0,0],[0,0,0,1,0],[0,0,0,0,0]]
        # expected.readDataToReg = []
    
        actual = prop.propagate([inst1,inst2,inst3,inst4,inst5,inst6,inst7,inst8,inst9,inst10])
        correct = NonRectangularPseudoMatrix(regToReg=Matrix(numRows=5, numCols=5, matrix=[[1, 0, 0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 1, 0], [0, 0, 0, 0, 0]]), readDataToReg=Matrix(numRows=1, numCols=10, matrix=[[Matrix(numRows=1, numCols=5, matrix=[[0, 0, 0, 0, 0]]), None, Matrix(numRows=1, numCols=5, matrix=[[0, 0, 0, 0, 1]]), None, None, Matrix(numRows=1, numCols=5, matrix=[[0, 0, 1, 0, 0]]), None, None, Matrix(numRows=1, numCols=5, matrix=[[0, 1, 0, 0, 0]]), None]]), regToReadAddress=Matrix(numRows=1, numCols=10, matrix=[[Matrix(numRows=5, numCols=1, matrix=[[0], [0], [1], [0], [0]]), None, Matrix(numRows=5, numCols=1, matrix=[[0], [0], [0], [0], [0]]), None, None, Matrix(numRows=5, numCols=1, matrix=[[1], [0], [0], [0], [0]]), None, None, Matrix(numRows=5, numCols=1, matrix=[[0], [0], [0], [0], [0]]), None]]), regToWriteData=Matrix(numRows=1, numCols=10, matrix=[[None, Matrix(numRows=5, numCols=1, matrix=[[0], [0], [0], [0], [0]]), None, Matrix(numRows=5, numCols=1, matrix=[[0], [0], [0], [0], [0]]), Matrix(numRows=5, numCols=1, matrix=[[0], [0], [0], [0], [0]]), None, Matrix(numRows=5, numCols=1, matrix=[[0], [0], [0], [1], [0]]), None, None, Matrix(numRows=5, numCols=1, matrix=[[0], [0], [0], [0], [0]])]]), regToWriteAddress=Matrix(numRows=1, numCols=10, matrix=[[None, Matrix(numRows=5, numCols=1, matrix=[[0], [0], [0], [1], [0]]), None, Matrix(numRows=5, numCols=1, matrix=[[1], [0], [0], [0], [0]]), Matrix(numRows=5, numCols=1, matrix=[[0], [0], [1], [0], [0]]), None, Matrix(numRows=5, numCols=1, matrix=[[0], [0], [0], [0], [0]]), None, None, Matrix(numRows=5, numCols=1, matrix=[[0], [0], [0], [0], [0]])]]), triangle=Matrix(numRows=10, numCols=10, matrix=[[None, TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=Matrix(numRows=1, numCols=1, matrix=[[0]]), readDataToWriteData=Matrix(numRows=1, numCols=1, matrix=[[1]])), TriangleEntry(readDataToReadAddress=Matrix(numRows=1, numCols=1, matrix=[[1]]), readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=Matrix(numRows=1, numCols=1, matrix=[[0]]), readDataToWriteData=Matrix(numRows=1, numCols=1, matrix=[[1]])), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=Matrix(numRows=1, numCols=1, matrix=[[0]]), readDataToWriteData=Matrix(numRows=1, numCols=1, matrix=[[0]])), TriangleEntry(readDataToReadAddress=Matrix(numRows=1, numCols=1, matrix=[[0]]), readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=Matrix(numRows=1, numCols=1, matrix=[[1]]), readDataToWriteData=Matrix(numRows=1, numCols=1, matrix=[[0]])), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=Matrix(numRows=1, numCols=1, matrix=[[1]]), readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=Matrix(numRows=1, numCols=1, matrix=[[0]]), readDataToWriteData=Matrix(numRows=1, numCols=1, matrix=[[1]]))], [None, None, TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None)], [None, None, None, TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=Matrix(numRows=1, numCols=1, matrix=[[0]]), readDataToWriteData=Matrix(numRows=1, numCols=1, matrix=[[0]])), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=Matrix(numRows=1, numCols=1, matrix=[[0]]), readDataToWriteData=Matrix(numRows=1, numCols=1, matrix=[[1]])), TriangleEntry(readDataToReadAddress=Matrix(numRows=1, numCols=1, matrix=[[0]]), readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=Matrix(numRows=1, numCols=1, matrix=[[0]]), readDataToWriteData=Matrix(numRows=1, numCols=1, matrix=[[0]])), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=Matrix(numRows=1, numCols=1, matrix=[[0]]), readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=Matrix(numRows=1, numCols=1, matrix=[[0]]), readDataToWriteData=Matrix(numRows=1, numCols=1, matrix=[[0]]))], [None, None, None, None, TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None)], [None, None, None, None, None, TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None)], [None, None, None, None, None, None, TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=Matrix(numRows=1, numCols=1, matrix=[[0]]), readDataToWriteData=Matrix(numRows=1, numCols=1, matrix=[[0]])), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=Matrix(numRows=1, numCols=1, matrix=[[0]]), readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=Matrix(numRows=1, numCols=1, matrix=[[1]]), readDataToWriteData=Matrix(numRows=1, numCols=1, matrix=[[0]]))], [None, None, None, None, None, None, None, TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None)], [None, None, None, None, None, None, None, None, TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None), TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=None, readDataToWriteData=None)], [None, None, None, None, None, None, None, None, None, TriangleEntry(readDataToReadAddress=None, readDataToWriteAddress=Matrix(numRows=1, numCols=1, matrix=[[0]]), readDataToWriteData=Matrix(numRows=1, numCols=1, matrix=[[1]]))], [None, None, None, None, None, None, None, None, None, None]]))
        assert equalsNonRectangularPseudoMatrix(actual, correct)
