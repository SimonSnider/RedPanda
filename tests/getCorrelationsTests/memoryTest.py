from red_panda.models.correlations import *
from red_panda.models.stateData import *
from red_panda.get_correlations import correlationCalculatorMemory as mem
from red_panda.models import *

n = 3
iterPerReg = 3
data = -1  # RegisterStates
size = 1


def testMemRead():
    """
    Here, we test the performance of the memory portion of the correlation module using the instruction
    lw $r2, 0($r1)
    """
    global data, size
    bitmasks: "list[bytes]" = []
    beforeStates: "list[dict[str, int]]" = []
    afterStates: "list[dict[str, int]]" = []
    memoryReads: "list[list[int]]" = []
    memoryWrites: "list[list[int]]" = []
    bitmasks.append(b"\x00\x00\x00")
    beforeStates.append({"r1": 1, "r2": 2, "r3": 3})
    afterStates.append({"r1": 1, "r2": 2, "r3": 3})
    # MemoryTransaction(type, value, address, size
    curRead = MemoryTransaction("read", 2, 1, size)
    memoryReads.append([curRead])

    bitmasks.append(b"\x01")
    beforeStates.append({"r1": 4, "r2": 2, "r3": 3})
    afterStates.append({"r1": 4, "r2": 2, "r3": 3})
    curRead = MemoryTransaction("read", 2, 4, size)
    memoryReads.append([curRead])

    bitmasks.append(b"\x02")
    beforeStates.append({"r1": 1, "r2": 4, "r3": 3})
    afterStates.append({"r1": 1, "r2": 4, "r3": 3})
    curRead = MemoryTransaction("read", 4, 1, size)
    memoryReads.append([curRead])

    bitmasks.append(b"\x04")
    beforeStates.append({"r1": 1, "r2": 2, "r3": 4})
    afterStates.append({"r1": 1, "r2": 2, "r3": 4})
    curRead = MemoryTransaction("read", 2, 1, size)
    memoryReads.append([curRead])

    data = RegisterStateList()
    data.beforeStates = beforeStates
    data.afterStates = afterStates
    data.memoryReads = memoryReads
    data.memoryWrites = memoryWrites
    data.bitmasks = bitmasks

    mem.setArch("test", 3)
    mem.initialize(data, 3)
    M = mem.computeCorrelations()
    correct = Correlations(regToReg=[[1, 0, 0], [0, 1, 0], [0, 0, 1]], regToReadAddress=[[1], [0], [0]], regToWriteAddress=[[], [], []], regToWriteData = [[], [], []], readDataToReg=[[0], [1], [0]], threshold=1)
    assert equalsCorrelations(M, correct)



def testMemWrite():
    """
    This function tests the correctness of the new memory model using the pseudo-instruction:
         sw $r2 0($r1)
    or:  mem[$r1] = $r2
    """
    global data, size
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

    bitmasks.append(b"\x01")
    beforeStates.append({"r1": 4, "r2": 2, "r3": 3})
    afterStates.append({"r1": 4, "r2": 2, "r3": 3})
    memoryReads.append([])
    curWrite = MemoryTransaction("write", 2, 4, size)
    memoryWrites.append([curWrite])
    
    bitmasks.append(b"\x02")
    beforeStates.append({"r1": 1, "r2": 4, "r3": 3})
    afterStates.append({"r1": 1, "r2": 4, "r3": 3})
    memoryReads.append([])
    curWrite = MemoryTransaction("write", 4, 1, size)
    memoryWrites.append([curWrite])

    bitmasks.append(b"\x04")
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
    M = mem.computeCorrelations()
    correct = Correlations(regToReg=[[1,0,0],[0,1,0],[0,0,1]],regToReadAddress=[[], [], []], regToWriteAddress=[[1], [0], [0]], regToWriteData=[[0], [1], [0]], readDataToReg=[[], [], []], threshold=1.0)
    assert equalsCorrelations(correct, M)
    

