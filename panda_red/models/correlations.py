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
class IntermediateData:
	initialInput: "dict[str, int]" = field(default_factory=list)
	initialOutput: "dict[str, int]" = field(default_factory=list)
	inputs: "list[dict[str, int]]" = field(default_factory=list)
	outputs:"list[dict[str, int]]" = field(default_factory=list)
	ps: "list[int]" = field(default_factory=list)
