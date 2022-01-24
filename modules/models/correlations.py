from dataclasses import dataclass, field

@dataclass
class Correlations:
	regToReg: "list[list[float]]" = field(default_factory=list)
	regToReadAddress: "list[list[float]]" = field(default_factory=list)
	regToWriteAddress: "list[list[float]]" = field(default_factory=list)
	regToWriteData: "list[list[float]]" = field(default_factory=list)
	readDataToReg: "list[list[float]]" = field(default_factory=list)

@dataclass
class IntermediateData:
	initialInput: "list[int]" = field(default_factory=list)
	initialOutput: "list[int]" = field(default_factory=list)
	inputs: "list[int]" = field(default_factory=list)
	outputs:"list[int]" = field(default_factory=list)
	ps: "list[list[int]]" = field(default_factory=list)
