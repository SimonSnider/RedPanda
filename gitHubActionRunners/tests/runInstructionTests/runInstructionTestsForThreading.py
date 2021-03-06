import unittest

from capstone import *
from red_panda.models import stateData
from red_panda.run_instruction import runInstruction
from red_panda.run_instruction.stateManager import *
from keystone import *
from red_panda.generate_instruction import instructionGenerator
import math
from red_panda.models.stateData import *
from red_panda.generate_instruction.filterer import filtererBasicMIPS as mipsFilter
from red_panda.generate_instruction.filterer import filtererBasicX86 as x86Filter

instGen = instructionGenerator.initialize()


def Log2(x):
    if (x == 0):
        return True
    return (math.log10(x)/math.log10(2))

# Function to check
# if x is power of 2


def isPowerOfTwo(n):
    return (math.ceil(Log2(n)) == math.floor(Log2(n)))


def testRunMipsInstructionOnce():
    """
    This test runs a single mips instruction with one randomization per register.
    
    Asserts that using the run_instruction module on a mips instruction returns the correct
    number of outputs, that the instruction information is of the correct type and length,
    and that the instruction executed properly
    """
    # initialize an instance of panda with the mips32 architecture
    panda = initializePanda("mips")
    # create the instruction we want to run
    instruction = "andi $t0, $t1, 0"
    print(instruction)
    CODE = instruction.encode('UTF-8')
    # assemble the instruction
    ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)
    ADDRESS = 0x0000
    encoding, count = ks.asm(CODE, ADDRESS)

    # gather the instruction data by executing it in panda
    data: StateData = None
    data, model, _ = runInstruction.runInstructions(
        panda, [encoding], 1)

    # make sure the data contains the correct information
    assert len(data.registerStateLists) == 1
    regStateList = data.registerStateLists[0]
    assert isinstance(regStateList, RegisterStateList)
    # check that the correct number of randomized bitmasks were executed
    assert len(regStateList.beforeStates) == 1 * 24 + 1
    assert len(regStateList.afterStates) == 1 * 24 + 1
    # Check that the 'and' instruction executed properly.
    assert regStateList.beforeStates[0].get("T0") != 0
    assert regStateList.afterStates[0].get("T0") == 0

def testRunX86InstructionOnce():
    """
    This test runs a single x86_64 instruction with one randomization per register.
    
    Asserts that using the run_instruction module on an x86_64 instruction returns the correct
    number of outputs, that the instruction information is of the correct type and length,
    and that the instruction executed properly
    """
    panda = initializePanda("x86_64")
    instruction = "AND RAX, 0"
    print(instruction)
    CODE = instruction.encode('UTF-8')
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)

    ADDRESS = 0x0000
    encoding, count = ks.asm(CODE, ADDRESS)
    print(encoding)
    data: StateData = None
    data, model, _ = runInstruction.runInstructions(
        panda, [encoding], 1)
    # assert that the register state list is of the correct length (1) and type (class RegisterStateList)
    assert len(data.registerStateLists) == 1
    regStateList = data.registerStateLists[0]
    assert isinstance(regStateList, RegisterStateList)
    # assert that the correct number of randomizations (15) were performed
    assert len(regStateList.beforeStates) == 1 * 14 + 1
    assert len(regStateList.afterStates) == 1 * 14 + 1
    print(regStateList.beforeStates[0])
    # assert that the AND instruction executed properly (the RAX register should be 0 after execution)
    assert regStateList.beforeStates[0].get("RAX") != 0
    assert regStateList.afterStates[0].get("RAX") == 0


def testRunTwoMipsInstructions():
    """
    This test uses the run_instruction module to gather data on two mips instructions in sequence

    Asserts that the run_instruction module will properly switch between instructions, that the information
    gathered for each instruction is of the correct length, and the correct information was gathere for each instruction
    """
    panda = initializePanda("mips")
    instruction = "andi $t0, $t1, 0"
    instruction2 = "andi $t5, $t6, 0"
    CODE = instruction.encode('UTF-8')
    CODE2 = instruction2.encode('UTF-8')
    ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)

    ADDRESS = 0x0000
    encoding, count = ks.asm(CODE, ADDRESS)
    encoding2, count = ks.asm(CODE2, ADDRESS)
    data, model, _ = runInstruction.runInstructions(
        panda, [encoding, encoding2], 1)
    # assert the correct number of instructions (2) were collected
    assert len(data.registerStateLists) == 2
    # determine the first regStateList contains data for the first instruction and not the second
    states = data.registerStateLists[0]
    assert isinstance(states, RegisterStateList)
    assert len(states.beforeStates) == 1 * 24 + 1
    assert len(states.afterStates) == 1 * 24 + 1
    # assert that for each randomization, the And instruction executed properly
    for i in range(len(states.beforeStates)):
        assert states.beforeStates[i].get("T0") != 0
        assert states.afterStates[i].get(
            "T5") == states.beforeStates[i].get("T5")
        assert states.afterStates[i].get("T0") == 0

    # determine the second regStateList contains data for the second instruction and not the first
    states = data.registerStateLists[1]
    assert isinstance(states, RegisterStateList)
    assert len(states.beforeStates) == 1 * 24 + 1
    assert len(states.afterStates) == 1 * 24 + 1
    # assert that for each randomization, the correct instruction was executed
    for i in range(len(states.beforeStates)):
        assert states.beforeStates[i].get("T5") != 0
        assert states.beforeStates[i].get(
            "T0") == states.afterStates[i].get("T0")
        assert states.afterStates[i].get("T5") == 0
    # assert that the panda model gathered for each instruction are not identical
    assert model[0] != model[1], "model 0 and model 1 are identical"


def testRunTwoX86Instructions():
    """
    This test uses the run_instruction module to gather data on two x86_64 instructions in sequence

    Asserts that the run_instruction module will properly switch between instructions, that the information
    gathered for each instruction is of the correct length, and the correct information was gathere for each instruction
    """
    panda = initializePanda("x86_64")
    instruction = "INC RAX"
    instruction2 = "INC RBX"
    CODE = instruction.encode('UTF-8')
    CODE2 = instruction2.encode('UTF-8')
    ks = Ks(KS_ARCH_X86, KS_MODE_64)

    ADDRESS = 0x0000
    encoding, count = ks.asm(CODE, ADDRESS)
    encoding2, count = ks.asm(CODE2, ADDRESS)
    data: StateData = None
    data, model, _ = runInstruction.runInstructions(
        panda, [encoding, encoding2], 1)
    assert len(data.registerStateLists) == 2
    # determine the first regStateList contains data for the first instruction and not the second
    states = data.registerStateLists[0]
    assert isinstance(states, RegisterStateList)
    # assert that the correct number of randomizations were performed for instruction 1
    assert len(states.beforeStates) == 1 * 14 + 1
    assert len(states.afterStates) == 1 * 14 + 1
    # assert that, for each randomization, RAX was incremented and RBX was not
    for i in range(len(states.beforeStates)):
        assert states.afterStates[i].get(
            "RAX") == states.beforeStates[i].get("RAX") + 1
        assert states.afterStates[i].get(
            "RBX") == states.beforeStates[i].get("RBX")

    # determine the second regStateList contains data for the second instruction and not the first
    states = data.registerStateLists[1]
    assert isinstance(states, RegisterStateList)
    # assert that the correct number of randomizations were performed for the second instruction
    assert len(states.beforeStates) == 1 * 14 + 1
    assert len(states.afterStates) == 1 * 14 + 1
    # assert that, for each randomization, RBX was incremented and RAX was not
    for i in range(len(states.beforeStates)):
        assert states.beforeStates[i].get("RBX") == states.afterStates[i].get("RBX") - 1
        assert states.afterStates[i].get("RAX") == states.beforeStates[i].get("RAX")
    #assert that the Panda model gathered for each instruction are note equivalent
    assert model[0] != model[1], "model 0 and model 1 are identical"


def testRunInstructionsMips():
    """
    This test checks whether the generation and execution of 10 random instructions works for mips

    Asserts that the run_instruction module will properly switch between instructions, that the information
    gathered for each instruction is of the correct length and type
    """
    panda = initializePanda("mips")
    print("num_regs: " + str(len(panda.arch.registers)))
    instructions = []
    instGen = instructionGenerator.initialize("mips32")
    inst = 10
    n = 10
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)  # misp32
    for i in range(inst):
        instruction = instructionGenerator.generateInstruction(
            instGen, mipsFilter)
        instructions.append(instruction)
        for insn in md.disasm(instruction, 0x1000):
            print("%s\t%s" % (insn.mnemonic, insn.op_str))

    data: StateData = None
    data, model, _ = runInstruction.runInstructions(
        panda, instructions, n)
    # assert that the correct number of instructions were collected
    assert len(data.registerStateLists) == inst
    for regStateList in data.registerStateLists:
        if regStateList is None:
            continue
        # assert that the correct number of randomizations were performed
        assert len(regStateList.bitmasks) == n*24 + 1
        assert len(regStateList.afterStates) == n*24 + 1
        assert len(regStateList.beforeStates) == n*24 + 1
        # assert that the first execution of each instruction was with an initial state
        assert regStateList.bitmasks[0], b'\x00\x00\x00\x00'
        # assert that each register state contains the correct datatypes
        for i in range(len(regStateList.bitmasks)):
            assert isinstance(regStateList.bitmasks[i], bytes)
            assert isinstance(regStateList.beforeStates[i], dict)
            assert isinstance(regStateList.afterStates[i], dict)
            assert isPowerOfTwo(int.from_bytes(
                regStateList.bitmasks[i], 'big', signed=False))



def testRunInstructionsX86():
    panda = initializePanda("x86_64")
    instructions = []
    instGen = instructionGenerator.initialize("x86_64")
#    inst = 1
    n = 100
    md = Cs(CS_ARCH_X86, CS_MODE_64)
#    for i in range(inst):
#        instruction = instructionGenerator.generateInstruction(
#            instGen, x86Filter)
#        instructions.append(instruction)
#        for insn in md.disasm(instruction, 0x1000):
#            print("%s\t%s" % (insn.mnemonic, insn.op_str))
    insn1 = "add rax, rbx"
    CODE = insn1.encode('UTF-8')
    ks = Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    encoding, count = ks.asm(CODE, 0x1000)
    instructions.append(encoding)
    print("add rax, rbx")
    

    data: StateData = None
    data, model, _ = runInstruction.runInstructions(
        panda, instructions, n)
    assert len(data.registerStateLists) == 1
    for regStateList in data.registerStateLists:
        assert len(regStateList.bitmasks) == n*14 + 1
        assert len(regStateList.afterStates) == n*14 + 1
        assert len(regStateList.beforeStates) == n*14 + 1
        assert regStateList.bitmasks[0] == b'\x00\x00'
        for i in range(len(regStateList.bitmasks)):
            assert isinstance(regStateList.bitmasks[i], bytes)
            assert isinstance(regStateList.beforeStates[i], dict)
            assert isinstance(regStateList.afterStates[i], dict)
            assert isPowerOfTwo(int.from_bytes(
                regStateList.bitmasks[i], 'big', signed=False))


def testRunInstructionsMemoryMips():
    """
    Tests that memory instructions can be run in mips

    asserts that the correct number of instructions is run, that the memory accesses were recorded properly,
    and that each memory transaction is of the correct type
    """
    panda = initializePanda("mips")
    instruction = "lw $t2, 0($t4)"
    instruction2 = "sw $t2, 0($t4)"
    CODE = instruction.encode('UTF-8')
    CODE2 = instruction2.encode('UTF-8')
    ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)

    ADDRESS = 0x0000
    encoding, count = ks.asm(CODE, ADDRESS)
    encoding2, count = ks.asm(CODE2, ADDRESS)
    instructions = [encoding, encoding2]
    inst = 2
    n = 5

    data, model, _ = runInstruction.runInstructions(panda, instructions, n, True)
    assert isinstance(data, StateData)
    assert len(data.instructions) == inst
    assert len(data.registerStateLists) == inst
    lwStates = data.registerStateLists[0]
    swStates = data.registerStateLists[1]
    assert len(lwStates.memoryReads) == n*24 + 1
    assert len(swStates.memoryWrites) == n*24 + 1
    for read in lwStates.memoryReads[0]:
        assert isinstance(read, MemoryTransaction)
    for write in lwStates.memoryWrites[0]:
        assert isinstance(write, MemoryTransaction)
