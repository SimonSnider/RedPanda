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


def runInstructionLoop(panda: Panda, instruction, n, verbose=False):
    """
    Arguments:
        panda -- the istance of panda that will be executed
        instruction -- the instruction you want to run in byte form
        n -- how many times you want to run the instruction
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
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32+ CS_MODE_BIG_ENDIAN)
    initialState = {}
    

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
            nonlocal index
            bitmask = b'\x00\x00\x00\x00'
            if (index > 0):
                bitmask = generateRandomBits(32)
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
        if (index >= n):
            if (verbose): print("end analysis")
            panda.end_analysis()
        return 0

    panda.cb_insn_translate(lambda x, y: True)

    panda.run()
    return stateData

def runInstructions(panda: Panda, instructions, n, verbose=False):
    """
    Arguments:
        panda -- The instance of panda the instructions will be run on
        instructions -- the list of instructions in byte form that will be run on the panda instance
        n -- the number of times each instruction will be run
        verbose -- enables printing of step completions and instructions being run
    Outputs:
        returns a dictionary of instruction byte to an n by 3 array containing the 
        bitmask, before register state, and after register state of running that instruction. bitmask0 is always all zeroes
        Output format: {inst1: [[bitmask0: bytes, beforeState0: dict, afterState0: dict], [bitmask1, beforeState1, afterState1], ...], inst2: [[bitmask0, beforeState0, afterState0]...], ...}
    """
    ADDRESS = 0
    stateData = dict()
    regStateIndex = 0
    instIndex = 0
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32+ CS_MODE_BIG_ENDIAN)
    initialState = {}


    @panda.cb_after_machine_init
    def setup(cpu):
        initializeMemory(panda, "mymem", address=ADDRESS)
        nonlocal instIndex, initialState
        loadInstruction(panda, cpu, instructions[instIndex], ADDRESS)
        randomizeRegisters(panda, cpu)
        initialState = getRegisterState(panda, cpu)
        stateData[instructions[instIndex]] = []
        print("setup done")

    @panda.cb_insn_exec
    def randomRegState(cpu, pc):
        if (pc == ADDRESS):
            if (verbose): print("randomizing registers")
            bitmask = b'\x00\x00\x00\x00'
            if (regStateIndex > 0):
                bitmask = generateRandomBits(32)
            randomizeRegisters(panda, cpu, bitmask)
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
        nonlocal regStateIndex, instIndex
        if (pc == 4):
            if (verbose): print("saving reg state after run", regStateIndex)
            stateData[instructions[instIndex]][regStateIndex].append(getRegisterState(panda, cpu))
            regStateIndex += 1
        if (regStateIndex >= n):
            if (instIndex < len(instructions)-1):
                instIndex += 1
                loadInstruction(panda, cpu, instructions[instIndex], ADDRESS)
                stateData[instructions[instIndex]] = []
                regStateIndex = 0
            else:
                if (verbose): print("end analysis")
                panda.end_analysis()
        return 0

    panda.cb_insn_translate(lambda x, y: True)
    panda.run()

    return stateData
    