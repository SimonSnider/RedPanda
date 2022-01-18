from pandare import Panda
from modules.runInstruction.stateManager import *
from capstone import *
from capstone.mips import *
import math
from modules.generateInstruction.bitGenerator import *
from modules.models.stateData import *
import copy


def loadInstruction(panda: Panda, cpu, instruction, address=0):
    """
    Arguments:
        panda -- the instance of panda the instruction will be loaded into
        cpu -- the cpu instance obtained from a panda callback
        instruction -- the instruction in byte form
        address -- the address location to load the instruction into
    Output:
        loads the instruction into panda's memory at the specified address,
        then loads a jump instruction immediately after it to loop through that instruction.
        Sets the program counter to address
    """
    panda.physical_memory_write(address, bytes(instruction))
    panda.physical_memory_write(address + len(instruction), bytes(b"\x00\x00\x00\x00"))
    # create a jump instruction
    jump = b"\x08\x00\x00\x00"
    panda.physical_memory_write(address + 2*len(instruction), bytes(jump))
    
    cpu.env_ptr.active_tc.PC = address
    return

def getNextValidBit(panda: Panda, regNum):
    # 
    regs = list(panda.arch.registers.keys())
    count = 0
    for i in range(len(regs)):
        if (regs[i] not in skippedMipsRegs):
            if (count >= regNum):
                return i
            else:
                count += 1
    return -1

def runInstructionLoop(panda: Panda, instruction, n, verbose=False):
    """
    Arguments:
        panda -- the istance of panda that will be executed
        instruction -- the instruction you want to run in byte form
        n -- how many times you want the instruction to run for each bitmask
        verbose -- turns on printing of step completions and instructions being run
    Outputs:
        returns an n x 3 array of bitmasks, beforeregister states, and after register states.
        bitmask0 is always all zeroes
        output format: [[bitmask0: bytes, beforeState0: dict, afterState0: dict], [bitmask1, beforeState1, afterState1], ...]
    """
    print("initializing panda")
    ADDRESS = 0
    stateData = []
    index = 0
    regBoundsCount = 0
    upperBound = 2**(31) - 1
    lowerBound = -(2**31)
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32+ CS_MODE_BIG_ENDIAN)
    initialState = {}
    latch = 1
    bitmask = b'\x00\x00\x00\x00'

    @panda.cb_after_machine_init
    def setup(cpu):
        initializeMemory(panda, "mymem", address=ADDRESS)
        loadInstruction(panda, cpu, instruction, ADDRESS)
        randomizeRegisters(panda, cpu)
        nonlocal initialState
        initialState = getRegisterState(panda, cpu)
        if (verbose): print("setup done")


    @panda.cb_insn_exec
    def randomRegState(cpu, pc):
        nonlocal latch
        if (pc == ADDRESS):
            if (verbose): print("randomizing registers")
            nonlocal index, bitmask, regBoundsCount
            setRegisters(panda, cpu, initialState)
            randomizeRegisters(panda, cpu, bitmask, lowerBound, upperBound)
            stateData.append([bitmask, getRegisterState(panda, cpu)])
        if (verbose):
            code = panda.virtual_memory_read(cpu, pc, 4)
            for i in md.disasm(code, pc):
                print("0x%x:\t%s\t%s" % (pc, i.mnemonic, i.op_str))
                break
        return 0

    @panda.cb_after_insn_translate
    def translateAll(env, pc):
        return True

    @panda.cb_after_insn_exec
    def getInstValues(cpu, pc):
        nonlocal latch
        if (pc == 4):
            if (verbose): print("saving after reg state")
            nonlocal index, bitmask, regBoundsCount
            stateData[index].append(getRegisterState(panda, cpu))
            
            if (index % n == 0):
                nextReg = getNextValidBit(panda, math.floor(index / n))
                if (nextReg == -1):
                    if (verbose): print("end analysis")
                    panda.end_analysis()
                    return 0
                bitmask = int.to_bytes(1<<(31-nextReg), 4, 'big')
                regBoundsCount = 0
            index += 1
        return 0

    @panda.cb_before_handle_exception
    def bhe(cpu, errorIndex):
        nonlocal regBoundsCount, bitmask, stateData, upperBound, lowerBound, initialState, index
        pc = cpu.panda_guest_pc
        if (verbose): print(f"handled exception index {errorIndex:#x} at pc: {pc:#x}")
        regBoundsCount += 1
        if (regBoundsCount >= 31): 
            print("cannot run instruction")
            print(getRegisterState(panda, cpu))
            panda.end_analysis()
            return 0
        if (index == 0):
            if (verbose): print(f"re-randomizing initial state")
            upperBound = 2**(31 - math.floor(regBoundsCount / 6)) - 1
            lowerBound = -(2**(31 - math.floor(regBoundsCount/6)))
            randomizeRegisters(panda, cpu, minValue=lowerBound, maxValue=upperBound)
            initialState = getRegisterState(panda, cpu)
            stateData = []
            return -1
        if (verbose): print(f"re-randomizing register ${list(panda.arch.registers)[31 - getNextValidBit(panda, math.floor(index / n))]} with reduced range")
        upperBound = 2**(31 - regBoundsCount) - 1
        lowerBound = -(2**(31 - regBoundsCount))
        stateData.pop()
        return -1

    panda.enable_precise_pc()
    panda.cb_insn_translate(lambda x, y: True)
    panda.run()
    return stateData

def runInstructions(panda: Panda, instructions, n, verbose=False):
    """
    Arguments:
        panda -- The instance of panda the instructions will be run on
        instructions -- the list of instructions in byte form that will be run on the panda instance
        n -- the number of times each instruction will be run on each bitmask
        verbose -- enables printing of step completions and instructions being run
    Outputs:
        returns a dictionary of instruction byte to an n by 3 array containing the 
        bitmask, before register state, and after register state of running that instruction. bitmask0 is always all zeroes
        Output format: {inst1: [[bitmask0: bytes, beforeState0: dict, afterState0: dict], [bitmask1, beforeState1, afterState1], ...], inst2: [[bitmask0, beforeState0, afterState0]...], ...}
    """
    ADDRESS = 0
    stateData = StateData()
    registerStates = RegisterStates()
    regStateIndex = 0
    instIndex = 0
    regBoundsCount = 0
    upperBound = 2**(31) - 1
    lowerBound = -(2**31)
    bitmask = b'\x00\x00\x00\x00'
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32+ CS_MODE_BIG_ENDIAN)
    initialState = {}
    memoryStructure = dict()


    @panda.cb_after_machine_init
    def setup(cpu):
        initializeMemory(panda, "mymem", address=ADDRESS)
        nonlocal instIndex, initialState, stateData
        loadInstruction(panda, cpu, instructions[instIndex], ADDRESS)
        stateData.instructions.append(instructions[instIndex])
        randomizeRegisters(panda, cpu)
        initialState = getRegisterState(panda, cpu)
        if (verbose): print("setup done")

    @panda.cb_insn_exec
    def randomRegState(cpu, pc):
        nonlocal bitmask, stateData, registerStates
        if (verbose): print("randomRegState")
        if (pc == ADDRESS):
            if (verbose): print("randomizing registers")
            setRegisters(panda, cpu, initialState)
            randomizeRegisters(panda, cpu, bitmask)
            if (verbose): print("saving before reg state")
            registerStates.bitmasks.append(bitmask)
            registerStates.beforeStates.append(getRegisterState(panda, cpu))
        if (verbose):
            code = panda.virtual_memory_read(cpu, pc, 4)
            for i in md.disasm(code, pc):
                print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
                break
        return 0

    @panda.cb_after_insn_translate
    def translateAll(env, pc):
        return True

    @panda.cb_after_insn_exec 
    def getInstValues(cpu, pc):
        if (verbose): print("getInstValues")
        nonlocal regStateIndex, instIndex, bitmask, registerStates
        if (pc == 4):
            if (verbose): print("saving reg state after run", regStateIndex)
            registerStates.afterStates.append(getRegisterState(panda, cpu))
            
            if (regStateIndex % n == 0):
                nextReg = getNextValidBit(panda, math.floor(regStateIndex / n))
                if (nextReg == -1):
                    if (instIndex < len(instructions)-1):
                        if (verbose): print("switching instructions")
                        instIndex += 1
                        stateData.registerStates.append(copy.copy(registerStates))
                        loadInstruction(panda, cpu, instructions[instIndex], ADDRESS)
                        stateData.instructions.append(instructions[instIndex])
                        registerStates = RegisterStates()
                        regStateIndex = 0
                        bitmask = b'\x00\x00\x00\x00'
                        return 0
                    else:
                        if (verbose): print("end analysis")
                        stateData.registerStates.append(copy.copy(registerStates))
                        panda.end_analysis()
                        return 0
            
                bitmask = int.to_bytes(1<<(31-nextReg), 4, 'big')
            regStateIndex += 1
        return 0

    @panda.cb_before_handle_exception
    def bhe(cpu, index):
        nonlocal regBoundsCount, bitmask, stateData, regStateIndex, initialState, registerStates
        pc = cpu.panda_guest_pc
        if (verbose): print(f"handled exception index {index:#x} at pc: {pc:#x}")
        regBoundsCount += 1
        if (regBoundsCount >= 31):
            print("Cannot run instruction")
            panda.end_analysis()
            return 0
        if (regStateIndex == 0):
            if (verbose): print(f"re-randomizing initial state")
            upperBound = 2**(31 - math.floor(regBoundsCount / 6)) - 1
            lowerBound = -(2**(31 - math.floor(regBoundsCount/6)))
            randomizeRegisters(panda, cpu, minValue=lowerBound, maxValue=upperBound)
            initialState = getRegisterState(panda, cpu)
            # stateData[instructions[instIndex]] = []
            registerStates.beforeStates = []
            registerStates.bitmasks = []
            registerStates.afterStates = []
            registerStates.memoryWrites = []
            registerStates.memoryReads = []
            return -1
        if (verbose): print(f"re-randomizing register with reduced range")
        upperBound = 2**(31 - regBoundsCount) - 1
        lowerBound = -(2**(31 - regBoundsCount))
        registerStates.beforeStates.pop()
        registerStates.bitmasks.pop()
        return -1

    panda.enable_memcb()

    @panda.cb_virt_mem_before_read
    def manageread(cpu, pc, addr, size):
        nonlocal memoryStructure, stateData, lowerBound, upperBound

        if not (addr in memoryStructure):
            memoryStructure[addr] = generateRandomMemoryValues(lowerBound, upperBound)

        valueRead = memoryStructure[addr]

        memoryTransaction = MemoryTransaction("read", valueRead, addr, size)
        registerStates.memoryReads.append(memoryTransaction)

        if(verbose):
            print("pc of read:", pc)
            print("value read:", valueRead)
            print("addr of read:", addr)
            print("size of read:", size)

    @panda.cb_virt_mem_before_write
    def managewrite(cpu, pc, addr, size, data):
        nonlocal memoryStructure, stateData, registerStates

        memoryStructure[addr] = data

        memoryTransaction = MemoryTransaction("write", data, addr, size)
        registerStates.memoryWrites.append(memoryTransaction)

        if(verbose):        
            print("pc of write:", pc)
            print("addr of write:", addr)
            print("size of write:", size)
            print("data of write:", data)
    
    panda.enable_precise_pc()
    panda.cb_insn_translate(lambda x, y: True)
    panda.run()
    return stateData