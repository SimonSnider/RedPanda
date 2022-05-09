from dataclasses import dataclass, field

@dataclass
class Correlations:
	regToReg: "list[list[float]]" = field(default_factory=list)
	regToReadAddress: "list[list[float]]" = field(default_factory=list)
	regToWriteAddress: "list[list[float]]" = field(default_factory=list)
	regToWriteData: "list[list[float]]" = field(default_factory=list)
	readDataToReg: "list[list[float]]" = field(default_factory=list)
	threshold: float = 0

@dataclass
class TriangleEntry:
	readDataToReadAddress: "Matrix" = field(default_factory=object)
	readDataToWriteAddress: "Matrix" = field(default_factory=object)
	readDataToWriteData: "Matrix" = field(default_factory=object)
	
@dataclass
class Matrix:
	numRows: "int" = field(default_factory=int)
	numCols: "int" = field(default_factory=int)
	matrix: "list[list[float]]" = field(default_factory=list)

@dataclass
class NonRectangularPseudoMatrix:
	regToReg: "Matrix" = field(default_factory=Matrix)
	readDataToReg: "Matrix" = field(default_factory=Matrix)
	regToReadAddress: "Matrix" = field(default_factory=Matrix)
	regToWriteData: "Matrix" = field(default_factory=Matrix)
	regToWriteAddress: "Matrix" = field(default_factory=Matrix)
	triangle: "Matrix" = field(default_factory=Matrix)

@dataclass
class IntermediateData:
	initialInput: "dict[str, int]" = field(default_factory=list)
	initialOutput: "dict[str, int]" = field(default_factory=list)
	inputs: "list[dict[str, int]]" = field(default_factory=list)
	outputs: "list[dict[str, int]]" = field(default_factory=list)
	ps: "list[int]" = field(default_factory=list)
	
def equalsCorrelations(c1: Correlations, c2: Correlations):
	r1 = c1.regToReg == c2.regToReg
	r2 = c1.regToReadAddress == c2.regToReadAddress
	r3 = c1.regToWriteAddress == c2.regToWriteAddress
	r4 = c1.regToWriteData == c2.regToWriteData
	r5 = c1.readDataToReg == c2.readDataToReg
	return r1 and r2 and r3 and r4 and r5

def equalsNonRectangularPseudoMatrix(m1: NonRectangularPseudoMatrix, m2: NonRectangularPseudoMatrix):
	r1 = equalsMatrix(m1.regToReg, m2.regToReg)
	r2 = equalsMatrix(m1.regToReadAddress, m2.regToReadAddress)
	r3 = equalsMatrix(m1.regToWriteAddress, m2.regToWriteAddress)
	r4 = equalsMatrix(m1.regToWriteData, m2.regToWriteData)
	r5 = equalsMatrix(m1.readDataToReg, c2.readDataToReg)
	return r1 and r2 and r3 and r4 and r5

def equalsMatrix(m1: Matrix, m2: Matrix):
	return m1.matrix == m2.matrix