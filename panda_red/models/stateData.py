from dataclasses import dataclass, field, asdict
import json

@dataclass
class StateData:
    instructions: "list[bytes]" = field(default_factory=list)
    instructionNames: "list[str]" = field(default_factory=list)
    registerStateLists: "list[RegisterStateList]" = field(default_factory=list)

@dataclass
class RegisterStateList:
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

def stateDataToJson(data: StateData):
    class MyEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, bytes):
                return ("0x" + obj.hex())
            return json.JSONEncoder.default(self, obj)
    return json.dumps(asdict(data), cls=MyEncoder)