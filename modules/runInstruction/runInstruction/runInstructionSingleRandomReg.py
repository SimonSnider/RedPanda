from pandare import Panda
from modules.runInstruction.stateManager import *
from capstone import *
from capstone.mips import *
from modules.generateInstruction.bitGenerator import *


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
    # create a jump instruction
    jump = b"\x08\x00\x00\x00"
    panda.physical_memory_write(address + len(instruction), bytes(jump))
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
    regCount = 0
    loopCount = 0
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32+ CS_MODE_BIG_ENDIAN)
    initialState = {}
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
        if (pc == ADDRESS):
            if (verbose): print("randomizing registers")
            nonlocal index, bitmask, loopCount ,regCount
            if (index > 0):
                nextReg = getNextValidBit(panda, regCount)
                if (nextReg == -1):
                    if (verbose): print("end analysis")
                    panda.end_analysis()
                    return 0
                bitmask = int.to_bytes(1<<(31-nextReg), 4, 'big')
                loopCount += 1
                if (loopCount >= n):
                    loopCount = 0
                    regCount += 1
            setRegisters(panda, cpu, initialState)
            randomizeRegisters(panda, cpu, bitmask)
            stateData.append([bitmask, getRegisterState(panda, cpu)])
        code = panda.virtual_memory_read(cpu, pc, 4)
        if (verbose):
            for i in md.disasm(code, pc):
                print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
                break
        return 0

    @panda.cb_after_insn_translate
    def translateAll(env, pc):
        return True

    @panda.cb_after_insn_exec
    def getInstValues(cpu, pc):
        if (pc == 4):
            if (verbose): print("saving after reg state")
            nonlocal index
            stateData[index].append(getRegisterState(panda, cpu))
            index += 1
        return 0

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
    stateData = {}
    regStateIndex = 0
    instIndex = 0
    regCount = 0
    loopCount = 0
    bitmask = b'\x00\x00\x00\x00'
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32+ CS_MODE_BIG_ENDIAN)
    initialState = {}


    @panda.cb_after_machine_init
    def setup(cpu):
        initializeMemory(panda, "mymem", address=ADDRESS)
        nonlocal instIndex, initialState, stateData
        loadInstruction(panda, cpu, instructions[instIndex], ADDRESS)
        randomizeRegisters(panda, cpu)
        initialState = getRegisterState(panda, cpu)
        stateData[instructions[instIndex]] = []
        if (verbose): print("setup done")

    @panda.cb_insn_exec
    def randomRegState(cpu, pc):
        nonlocal regCount, loopCount, bitmask, stateData
        if (verbose): print("randomRegState")
        if (pc == ADDRESS):
            if (verbose): print("randomizing registers")
            setRegisters(panda, cpu, initialState)
            randomizeRegisters(panda, cpu, bitmask)
            if (verbose): print("saving before reg state")
            stateData[instructions[instIndex]].append([bitmask, getRegisterState(panda, cpu)])
        code = panda.virtual_memory_read(cpu, pc, 4)
        if (verbose):
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
        nonlocal regStateIndex, instIndex, regCount, loopCount, bitmask
        if (pc == 4):
            if (verbose): print("saving reg state after run", regStateIndex)
            stateData[instructions[instIndex]][regStateIndex].append(getRegisterState(panda, cpu))
            regStateIndex += 1
            nextReg = getNextValidBit(panda, regCount)
            if (nextReg == -1):
                if (instIndex < len(instructions)-1):
                    if (verbose): print("switching instructions")
                    instIndex += 1
                    loadInstruction(panda, cpu, instructions[instIndex], ADDRESS)
                    stateData[instructions[instIndex]] = []
                    regStateIndex = 0
                    loopCount = 0
                    regCount = 0
                    bitmask = b'\x00\x00\x00\x00'
                    return 0
                else:
                    if (verbose): print("end analysis")
                    panda.end_analysis()
                    return 0
            bitmask = int.to_bytes(1<<(31-nextReg), 4, 'big')
            loopCount += 1
            if (loopCount >= n):
                loopCount = 0
                regCount += 1
            
        return 0

    @panda.cb_before_handle_exception
    def bhe(cpu, index):
        pc = cpu.panda_guest_pc
        print(f"handled exception index {index:#x} at pc: {pc:#x}")
        panda.arch.set_pc(cpu, pc+4)
        return -1

    panda.enable_precise_pc()
    panda.cb_insn_translate(lambda x, y: True)
    panda.run()
    return stateData