# State Manager Module. Handles randomizing register and memory state and viewing them
# Since there can only be one instance of panda, procedures will have to take in an instance of panda to manipulate
# This means that these procedures will likely need to be called in @panda.cb_after_machine_init or the like
from random import randint, seed
from pandare.arch import PandaArch
from pandare.panda import Panda
from panda_red.generate_instruction.bitGenerator import *
import math

skippedMipsRegs = ['ZERO', 'SP', 'K0', 'K1', 'AT', 'GP', 'FP', 'RA']
skippedX86Regs = ['RSP', 'RBP']

def initializePanda(architecture="mips"):
    """
    Arguments:
        architecture -- the architecture that panda will be set up to emulate. Supported architectures: "mips", "x86_84"
    Outputs: 
        Returns an instance of panda with the specified architecture
    """


    
    # TODO: Change "mips32" in the rest of the code to "mips"
    arch = architecture
    if (arch == "mips32"):
        arch = "mips"
    panda = Panda(arch,
        extra_args=["-M", "configurable", "-nographic"],
        raw_monitor=True)
    # panda.taint_enable()
    return panda

def setRandomSeed(random_seed):
    """
    Arguments:
        random_seed -- an int to set as the random seed
    Outputs
        sets the seed for randint calls
    """
    seed(random_seed)

def initializeMemory(panda: Panda, memName, memSize=2 * 1024 * 1024, address=0):
    """
    Arguments:
        panda -- the instance of panda that will have its memory initialized
        memName -- the name of the memory region that will be mapped
        memSize -- the size of the memory region
        address -- the start address of the memory region
    Ouputs:
        maps a section of memory in panda
    """
    panda.map_memory(memName, memSize, address)
    
def generateRandomMemoryValues(minValue = -(2**(31)), maxValue = (2**31) - 1):
    """
    Arguments: 
        minValue -- the minimum value for the randomized value (inclusive)
        maxValue -- the maximum value for the randomized value (inclusive)
    Outputs: 
        returns a random 4-byte value between minValue and maxValue
    """
    return generateRandomBytes(4, minValue=minValue, maxValue=maxValue)

def randomizeRegisters(panda: Panda, cpu, regBitMask: bytes = b'\xff\xff\xff\xff',
                       minValue = -(2**(31)), maxValue = (2**31) - 1, taintRegs: bool = False):
    """
    Arguments:
        panda -- the instance of panda that will have its registers randomized
        cpu -- the cpu given by a panda callback
        regBitMask -- a byte bitmask the length of the number of registers in the panda architecture that determines which registers are randomized
    Outputs:
        for registers 1 through n, if the nth bit in the regBitMask is 1, sets the nth register to a random value.
        Will not randomize register necessary for hardware execution, such as ZERO, Stack Pointers, Kernel registers, Return Addresses, Etc.
    """
    
    if (panda.arch_name == "mips"):
        regSize = 4
        skippedRegs = skippedMipsRegs
    elif (panda.arch_name == "x86_64"):
        regSize = 8
        skippedRegs = skippedX86Regs
    else:
        regSize = 4
        skippedRegs = []


    for (regname, reg) in panda.arch.registers.items():
        if (regname in skippedRegs or not getBit(regBitMask, reg)): continue
        num = generateRandomBytes(regSize, minValue=minValue, maxValue=maxValue)
        panda.arch.set_reg(cpu, regname, int.from_bytes(num, 'big', signed=False))
        if (taintRegs): panda.taint_label_reg(reg, reg)
    return

def setRegisters(panda: Panda, cpu, registerSate: dict):
    """
    Arguments:
        panda -- the instance of panda that will have its register set
        cpu -- an instance of the cpu given by a panda callback
        registerState -- a dictionary of register names to register values
    Outputs:
        for every item in registerState, set the corresponding panda register to that item's value
    """
    for (regname, reg) in registerSate.items():
        panda.arch.set_reg(cpu, regname, registerSate[regname])
    return

def randomizeMemory(panda):
    """
    Arguments:
        panda -- the instance of panda that will have its register state randomized
    Outputs:
        randomizes the memory of panda
    """
    # TODO: why is this here. I was gonna remove this but Jake wants it, so here it remains
    return

def getRegisterState(panda: Panda, cpu):
    """
    Arguments:
        panda -- the panda instance the register instance will be gotten from
        cpu -- the cpu instance returned from a panda callback
    Outputs:
        a dictionary of register names to register values
    """
    regs = {}
    for (regname, reg) in panda.arch.registers.items():
        val = panda.arch.get_reg(cpu, reg)
        regs[regname] = val
    return regs

def compareRegStates(state1, state2):
    """
    Arguments:
        state1, state2 -- a dictionary of register names to values
    Outputs:
        returns true if the register states are different
    """
    for key in state1:
        if (state1[key] != state2[key]): return True
    return False

def getBit(byteData, bit):
    """
    Arguments:
        byteData -- a byte literal
        bit -- which bit will be returned
    Outputs:
        Returns true if the <bit> bit of byteData is set to 1, false otherwise
    """
    if (bit < 0): return False
    
    return int.from_bytes(byteData, 'big')&(1<<(bit)) != 0
