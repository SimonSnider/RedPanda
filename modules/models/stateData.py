from dataclasses import dataclass

@dataclass
class StateData:
    instructions: "list[bytes]" = []
    registerStates: "list[RegisterStates]" = []

@dataclass
class RegisterStates:
    bitmasks: "list[bytes]" = []
    beforeStates: "list[dict[str,int]]" = []
    afterStates: "list[dict[str,int]]" = []
    memoryReads: "list[list[int]]" = []
    memoryWrites: "list[list[int]]" = []