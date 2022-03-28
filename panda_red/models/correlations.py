from dataclasses import dataclass, field

@dataclass
class Correlations:
	regToReg: "list[list[float]]" = field(default_factory=list)
	regToReadAddress: "list[list[float]]" = field(default_factory=list)
	# regToReadAddress: "list[float]" = field(default_factory=list)
	regToWriteAddress: "list[list[float]]" = field(default_factory=list)
	regToWriteData: "list[list[float]]" = field(default_factory=list)
	readDataToReg: "list[list[float]]" = field(default_factory=list)
	# readDataToReg: "list[float]" = field(default_factor=list)
	threshold: float = 0

@dataclass
class TriangleEntry:
	readValToReadAddress: "list[list[float]]" = field(default_factory=float)
	readValToWriteAddress: "list[list[float]]" = field(default_factory=float)
	readValToWriteVal: "list[list[float]]" = field(default_factory=float)

@dataclass
class NonRectangularPseudoMatrix:
	regToReg: "list[list[float]]" = field(default_factory=list)
	readValToReg: "list[list[float]]" = field(default_factory=list)
	regToReadVal: "list[list[float]]" = field(default_factory=list)
	regToWriteVal: "list[list[float]]" = field(default_factory=list)
	regToWriteAddress: "list[list[float]]" = field(default_factory=list)
	triangle: "list[list[TriangleEntry]]" = field(default_factory=list)

@dataclass
class IntermediateData:
	initialInput: "dict[str, int]" = field(default_factory=list)
	initialOutput: "dict[str, int]" = field(default_factory=list)
	inputs: "list[dict[str, int]]" = field(default_factory=list)
	outputs: "list[dict[str, int]]" = field(default_factory=list)
	ps: "list[int]" = field(default_factory=list)
