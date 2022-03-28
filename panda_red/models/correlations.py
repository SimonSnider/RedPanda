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
	readDataToReadAddress: "list[list[float]]" = field(default_factory=float)
	readDataToWriteAddress: "list[list[float]]" = field(default_factory=float)
	readDataToWriteData: "list[list[float]]" = field(default_factory=float)

@dataclass
class NonRectangularPseudoMatrix:
	regToReg: "list[list[float]]" = field(default_factory=list)
	readDataToReg: "list[list[float]]" = field(default_factory=list)
	regToReadAddress: "list[list[float]]" = field(default_factory=list)
	regToWriteData: "list[list[float]]" = field(default_factory=list)
	regToWriteAddress: "list[list[float]]" = field(default_factory=list)
	triangle: "list[list[TriangleEntry]]" = field(default_factory=list)

@dataclass
class IntermediateData:
	initialInput: "dict[str, int]" = field(default_factory=list)
	initialOutput: "dict[str, int]" = field(default_factory=list)
	inputs: "list[dict[str, int]]" = field(default_factory=list)
	outputs: "list[dict[str, int]]" = field(default_factory=list)
	ps: "list[int]" = field(default_factory=list)
