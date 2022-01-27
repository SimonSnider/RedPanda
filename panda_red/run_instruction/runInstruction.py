from pandare import Panda
from panda_red.run_instruction.stateManager import *
from capstone import *
from capstone.mips import *
import math
from panda_red.generate_instruction.bitGenerator import *
from panda_red.models.stateData import *
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

def runInstructions(panda: Panda, instructions, n, verbose=False):
    """
    Arguments:
        panda -- The instance of panda the instructions will be run on
        instructions -- the list of instructions in byte form that will be run on the panda instance
        n -- the number of times each instruction will be run on each bitmask
        verbose -- enables printing of step completions and instructions being run
    Outputs:
        returns a StateData object containing the instructions run and the program state data for each
    """
    ADDRESS = 0
    stateData = StateData()
    registerStateList = RegisterStateList()
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
        code = panda.virtual_memory_read(cpu, ADDRESS, 4)
        for i in md.disasm(code, 0):
            instr = i.mnemonic + " " + i.op_str
            stateData.instructionNames.append(instr)
            break
        randomizeRegisters(panda, cpu)
        initialState = getRegisterState(panda, cpu)
        if (verbose): print("setup done")

    @panda.cb_insn_exec
    def randomRegState(cpu, pc):
        nonlocal bitmask, stateData, registerStateList
        if (verbose): print("randomRegState")
        if (pc == ADDRESS):
            if (verbose): print("randomizing registers")
            setRegisters(panda, cpu, initialState)
            randomizeRegisters(panda, cpu, bitmask, lowerBound, upperBound)
            if (verbose): print("saving before reg state")
            registerStateList.bitmasks.append(bitmask)
            registerStateList.beforeStates.append(getRegisterState(panda, cpu))
            registerStateList.memoryReads.append([])
            registerStateList.memoryWrites.append([])
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
        nonlocal regStateIndex, instIndex, bitmask, registerStateList, regBoundsCount
        if (pc == 4):
            regBoundsCount = 0
            if (verbose): print("saving reg state after run", regStateIndex)
            registerStateList.afterStates.append(getRegisterState(panda, cpu))
            
            if (regStateIndex % n == 0):
                nextReg = getNextValidBit(panda, math.floor(regStateIndex / n))
                if (nextReg == -1):
                    if (instIndex < len(instructions)-1):
                        if (verbose): print("switching instructions")
                        instIndex += 1
                        stateData.registerStateLists.append(copy.copy(registerStateList))
                        loadInstruction(panda, cpu, instructions[instIndex], ADDRESS)
                        stateData.instructions.append(instructions[instIndex])
                        code = panda.virtual_memory_read(cpu, ADDRESS, 4)
                        for i in md.disasm(code, ADDRESS):
                            instr = i.mnemonic + " " + i.op_str
                            stateData.instructionNames.append(instr)
                            break
                        registerStateList = RegisterStateList()
                        regStateIndex = 0
                        bitmask = b'\x00\x00\x00\x00'
                        return 0
                    else:
                        if (verbose): print("end analysis")
                        stateData.registerStateLists.append(copy.copy(registerStateList))
                        panda.end_analysis()
                        return 0
            
                bitmask = int.to_bytes(1<<(31-nextReg), 4, 'big')
            regStateIndex += 1
        return 0

    @panda.cb_before_handle_exception
    def bhe(cpu, index):
        nonlocal regBoundsCount, bitmask, stateData, regStateIndex, initialState, registerStateList, upperBound, lowerBound
        pc = cpu.panda_guest_pc
        if (verbose): print(f"handled exception index {index:#x} at pc: {pc:#x}")
        regBoundsCount += 1
        if (regStateIndex == 0):
            if (verbose): print(f"re-randomizing initial state")
            upperBound = 2**(31 - math.floor(regBoundsCount / 6)) - 1
            lowerBound = -(2**(31 - math.floor(regBoundsCount/6)))
            randomizeRegisters(panda, cpu, minValue=lowerBound, maxValue=upperBound)
            initialState = getRegisterState(panda, cpu)
            registerStateList.beforeStates = []
            registerStateList.bitmasks = []
            registerStateList.afterStates = []
            registerStateList.memoryWrites = []
            registerStateList.memoryReads = []
            return -1
        if (regBoundsCount >= 31):
            print("Cannot run instruction")
            panda.end_analysis()
            return 0
        if (verbose): print(f"re-randomizing register with reduced range")
        upperBound = 2**(31 - regBoundsCount) - 1
        lowerBound = -(2**(31 - regBoundsCount))
        registerStateList.beforeStates.pop()
        registerStateList.bitmasks.pop()
        registerStateList.memoryReads.pop()
        registerStateList.memoryWrites.pop()
        return -1

    panda.enable_memcb()

    @panda.cb_virt_mem_before_read
    def manageread(cpu, pc, addr, size):
        nonlocal memoryStructure, stateData, lowerBound, upperBound

        if not (addr in memoryStructure):
            memoryStructure[addr] = generateRandomMemoryValues(lowerBound, upperBound)

        valueRead = memoryStructure[addr]

        memoryTransaction = MemoryTransaction("read", valueRead, addr, size)
        registerStateList.memoryReads[-1].append(memoryTransaction)

        if(verbose):
            print("pc of read:", pc)
            print("value read:", valueRead)
            print("addr of read:", addr)
            print("size of read:", size)

    @panda.cb_virt_mem_before_write
    def managewrite(cpu, pc, addr, size, data):
        nonlocal memoryStructure, stateData, registerStateList

        memoryStructure[addr] = data

        memoryTransaction = MemoryTransaction("write", data, addr, size)
        registerStateList.memoryWrites[-1].append(memoryTransaction)

        if(verbose):        
            print("pc of write:", pc)
            print("addr of write:", addr)
            print("size of write:", size)
            print("data of write:", data)
    
    panda.enable_precise_pc()
    panda.cb_insn_translate(lambda x, y: True)
    panda.run()
    return stateData