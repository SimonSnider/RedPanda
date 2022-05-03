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
