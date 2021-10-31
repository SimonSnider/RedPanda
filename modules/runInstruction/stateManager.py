# State Manager Module. Handles randomizing register and memory state and viewing them
# Since there can only be one instance of panda, procedures will have to take in an instance of panda to manipulate
# This means that these procedures will likely need to be called in @panda.cb_after_machine_init or the like

from random import randint, seed
from pandare.arch import PandaArch
from pandare.panda import Panda

skippedMipsRegs = ['ZERO', 'SP', 'K0', 'K1', 'AT', 'GP', 'FP', 'RA']

def initializePanda(architecture="mips"):
    panda = Panda("mips",
        extra_args=["-M", "configurable", "-nographic"],
        raw_monitor=True)
    return panda

def setRandomSeed(random_seed):
    """Sets the random seed used in this module"""
    seed(random_seed)

def initializeMemory(panda: Panda, memName, memSize=2 * 1024 * 1024, address=0):
    panda.map_memory(memName, memSize, address)

def randomizeRegisters(panda: Panda, cpu, regBitMask: bytes = b'\xff\xff\xff\xff'):
    """
    randomize the registers of the panda instance
    panda is the instance of panda to randomize the registers in
    cpu is the cpu from the callback function
    regKeys is a list of register keys that are to be randomized. If left blank if will randomize all registers
    random_seed will set the seed of the random number generator. if left as -1 it will use the default
    """
    if (panda.arch_name == "mips"):
        # skippedRegs = ['ZERO', 'SP', 'K0', 'K1', 'AT', 'GP', 'FP', 'RA']
        for (regname, reg) in panda.arch.registers.items():
            if (regname in skippedMipsRegs or not getBit(regBitMask, reg)): continue
            num = randint(0, 2**(32) - 1)
            panda.arch.set_reg(cpu, regname, num)
    return

def randomizeMemory(panda):
    """
    randomize all of memory
    """
    return

def getRegisterState(panda: Panda, cpu):
    """
    return a structure containing the registers and their values
    """
    regs = {}
    for (regname, reg) in panda.arch.registers.items():
        val = panda.arch.get_reg(cpu, reg)
        regs[regname] = val
    return regs

def compareRegStates(state1, state2):
    """
    compare two states and return true if they are different
    """
    for key in state1:
        if (state1[key] != state2[key]): return True
    return False

def getBit(byteData, bit):
    """
    returns true if the <bit> bit of <byteData> is set to 1, 0 indexed
    """
    if (bit < 0): return False
    
    return int.from_bytes(byteData, 'big')&(1<<(bit)) != 0