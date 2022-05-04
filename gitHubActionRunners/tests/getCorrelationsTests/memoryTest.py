from modules.models.stateData import *
from modules.getCorrelations import correlationCalculatorMemory as mem

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
    memoryReads.append([0])
    memoryWrites.append([1])
    memoryWriteVals.append([2])

    bitmasks.append(b"\x01\x00\x00")
    beforeStates.append({"r1": 4, "r2": 2, "r3": 3})
    afterStates.append({"r1": 4, "r2": 2, "r3": 3})
    memoryReads.append([0])
    memoryWrites.append([4])
    memoryWriteVals.append([2])

    bitmasks.append(b"\x00\x01\x00")
    beforeStates.append({"r1": 1, "r2": 4, "r3": 3})
    afterStates.append({"r1": 1, "r2": 4, "r3": 3})
    memoryReads.append([0])
    memoryWrites.append([1])
    memoryWriteVals.append([4])


    bitmasks.append(b"\x00\x00\x01")
    beforeStates.append({"r1": 1, "r2": 2, "r3": 4})
    afterStates.append({"r1": 1, "r2": 2, "r3": 4})
    memoryReads.append([0])
    memoryWrites.append([1])
    memoryWriteVals.append([2])

    data = RegisterStateList()
    data.beforeStates = beforeStates
    data.afterStates = afterStates
    data.memoryReads = memoryReads
    data.memoryWrites = memoryWrites
    data.memoryWriteValues = memoryWriteVals
    data.bitmasks = bitmasks

    mem.setArch("test", 3)
    mem.initialize(data, 3)
    M = mem.computeCorrelations()
    print(M)


# testMemRead()
testMemWrite()
