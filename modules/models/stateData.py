from dataclasses import dataclass, field

@dataclass
class StateData:
    instructions: "list[bytes]" = field(default_factory=list)
    registerStates: "list[RegisterStates]" = field(default_factory=list)

@dataclass
class RegisterStates:
    bitmasks: "list[bytes]" = field(default_factory=list)
    beforeStates: "list[dict[str,int]]" = field(default_factory=list)
    afterStates: "list[dict[str,int]]" = field(default_factory=list)
    memoryReads: "list[list[MemoryTransaction]]" = field(default_factory=list)
    memoryWrites: "list[list[MemoryTransaction]]" = field(default_factory=list)

@dataclass
class MemoryTransaction:
    type: str
    value: int
    address: int
    size: int
