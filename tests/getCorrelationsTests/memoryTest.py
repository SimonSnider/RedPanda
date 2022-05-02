from panda_red.models.stateData import *
from panda_red.get_correlations import correlationCalculatorMemory as mem
from panda_red.models import *

n = 3
iterPerReg = 3
data = -1  # RegisterStates


def testMemRead():
    global data
    bitmasks: "list[bytes]" = []
    beforeStates: "list[dict[str, int]]" = []
    afterStates: "list[dict[str, int]]" = []
    memoryReads: "list[list[int]]" = []
    memoryWrites: "list[list[int]]" = []
    bitmasks.append(b"\x00\x00\x00")
    beforeStates.append({"r1": 1, "r2": 2, "r3": 3})
    afterStates.append({"r1": 1, "r2": 2, "r3": 3})
    memoryReads.append([1])
    # memoryWrites.append([0])

    bitmasks.append(b"\x01\x00\x00")
    beforeStates.append({"r1": 4, "r2": 2, "r3": 3})
    afterStates.append({"r1": 4, "r2": 2, "r3": 3})
    memoryReads.append([4])
    # memoryWrites.append([0])

    bitmasks.append(b"\x00\x01\x00")
    beforeStates.append({"r1": 1, "r2": 4, "r3": 3})
    afterStates.append({"r1": 1, "r2": 4, "r3": 3})
    memoryReads.append([1])
    # memoryWrites.append([0])

    bitmasks.append(b"\x00\x00\x01")
    beforeStates.append({"r1": 1, "r2": 2, "r3": 4})
    afterStates.append({"r1": 1, "r2": 2, "r3": 4})
    memoryReads.append([1])
    # memoryWrites.append([0])

    data = RegisterStateList()
    data.beforeStates = beforeStates
    data.afterStates = afterStates
    data.memoryReads = memoryReads
    data.memoryWrites = memoryWrites
    data.bitmasks = bitmasks

    mem.setArch("test", 3)
    mem.initialize(data, 3)
    M = mem.computeCorrelations()
    print(M)


def testMemWrite():
    """
    This function tests the correctness of the new memory model using the pseudo-instruction:
         sw $r2 0($r1)
    or:  mem[$r1] = $r2
    """
    size = 1
    global data
    bitmasks: "list[bytes]" = []
    beforeStates: "list[dict[str, int]]" = []
    afterStates: "list[dict[str, int]]" = []
    memoryReads: "list[list[int]]" = []
    memoryWrites: "list[list[int]]" = []
    memoryWriteVals: "list[list[int]]" = []

    bitmasks.append(b"\x00\x00\x00")
    beforeStates.append({"r1": 1, "r2": 2, "r3": 3})
    afterStates.append({"r1": 1, "r2": 2, "r3": 3})
    memoryReads.append([])
    # MemoryTransaction(type, value, address, size)
    curWrite = MemoryTransaction("write", 2, 1, size)
    memoryWrites.append([curWrite])

    bitmasks.append(b"\x01\x00\x00")
    beforeStates.append({"r1": 4, "r2": 2, "r3": 3})
    afterStates.append({"r1": 4, "r2": 2, "r3": 3})
    memoryReads.append([])
    curWrite = MemoryTransaction("write", 2, 4, size)
    memoryWrites.append([curWrite])
    
    bitmasks.append(b"\x00\x01\x00")
    beforeStates.append({"r1": 1, "r2": 4, "r3": 3})
    afterStates.append({"r1": 1, "r2": 4, "r3": 3})
    memoryReads.append([])
    curWrite = MemoryTransaction("write", 4, 1, size)
    memoryWrites.append([curWrite])

    bitmasks.append(b"\x00\x00\x01")
    beforeStates.append({"r1": 1, "r2": 2, "r3": 4})
    afterStates.append({"r1": 1, "r2": 2, "r3": 4})
    memoryReads.append([])
    curWrite = MemoryTransaction("write", 2, 1, size)
    memoryWrites.append([curWrite])

    data = RegisterStateList()
    data.beforeStates = beforeStates
    data.afterStates = afterStates
    data.memoryReads = memoryReads
    data.memoryWrites = memoryWrites
    data.bitmasks = bitmasks

    mem.setArch("test", 3)
    mem.initialize(data, 3)
    print(data)
    M = mem.computeCorrelations()
    print(M)


# testMemRead()
testMemWrite()
