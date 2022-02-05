from pandare import Panda
from pytest import skip
from capstone import *
from capstone.mips import *
import math
import copy
from panda_red.run_instruction.stateManager import *


# TODO: change to load all instructions at once
def loadInstructions(panda: Panda, cpu, instructions, address=0):
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

    # get the appropriate jump instruction encoding for the architecture
    jump_instr = b""
    if (panda.arch_name == "mips"):
        jump_instr = b"\x08\x00\x00\x00"
    
    adr = address
    for instruction in instructions:
        panda.physical_memory_write(adr, bytes(instruction))
        adr += len(bytes(instruction))
    
    panda.physical_memory_write(adr, bytes(jump_instr))
    cpu.env_ptr.active_tc.PC = address
    return adr

def getNextValidReg(panda: Panda, regNum):
    """
    Arguments:
        panda -- the instance of panda the next valid register will be found in
        startIndex -- the start index for the search
    Output:
        returns the index of next register in the architecture that is allowed to be modified, using
        the "skipped regs" specifications from the stateManager module. returns -1 if there are no more
        valid registers
    """
    skippedRegs = []
    if (panda.arch_name == "mips"):
        skippedRegs = skippedMipsRegs
    regs = list(panda.arch.registers.keys())
    count = 0
    for i in range(len(regs)):
        if (regs[i] not in skippedRegs):
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
    iters = 0
    regBoundsCount = 0
    upperBound = 2**(31) - 1
    lowerBound = -(2**31)
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32+ CS_MODE_BIG_ENDIAN)

    STOPADDRESS = loadInstructions(panda, panda.get_cpu(), instructions, ADDRESS)

    # This callback executes before each instruction is executed, it handles randomizing the registers and saving the before states
    @panda.cb_insn_exec
    def randomRegState(cpu, pc):

        # Check if the panda is about to execute the instruction that is being tested. 
        # The register state only needs randomized before that instruction
        if (pc == ADDRESS):
            if (verbose): print("tainting registers before execution")
            
            # Randomize the registers specified by the bitmask to be a value between lowerBound and upperBound
            randomizeRegisters(panda, cpu, minValue=lowerBound, maxValue=upperBound, taintRegs=True)

        if (verbose):
            # Display the instruction that is about to be executed
            code = panda.virtual_memory_read(cpu, pc, 4)
            for i in md.disasm(code, pc):
                print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
                break
        return 0

    # Tell panda to translate every instruction
    @panda.cb_after_insn_translate
    def translateAll(env, pc):
        return True

    # This callback executes after each instruction execution. It handles saving the after register state and 
    # handles instruction switching, bitmask updating, and emulation termination
    @panda.cb_after_insn_exec 
    def getInstValues(cpu, pc):
        nonlocal regBoundsCount, iters

        if (pc >= STOPADDRESS):
            
            if (iters >= n-1):
                panda.end_analysis()
            iters += 1
        return 0

    # This callback is executed when an instruction throws an exception. It handles finding a valid initial state,
    # modifying the randomized register ranges, rolling back saved data, and terminating if an instruction cannot be executed
    @panda.cb_before_handle_exception
    def bhe(cpu, index):
        nonlocal regBoundsCount, upperBound, lowerBound
        pc = cpu.panda_guest_pc
        if (verbose): print(f"handled exception index {index:#x} at pc: {pc:#x}")
        regBoundsCount += 1
        if (regBoundsCount >= 32):
            print("can't find valid register state")
            panda.end_analysis()
            return 0
        # TODO: double check regBounds reduction rate
        upperBound = 2**(31 - math.floor(regBoundsCount/6)) - 1
        lowerBound = -(2**(31 - math.floor(regBoundsCount/6)))
        randomizeRegisters(panda, cpu, minValue=lowerBound, maxValue=upperBound)
        panda.arch.set_pc(cpu, ADDRESS)
        return -1

    
    panda.enable_precise_pc()
    panda.cb_insn_translate(lambda x, y: True)
    panda.run()
    return
