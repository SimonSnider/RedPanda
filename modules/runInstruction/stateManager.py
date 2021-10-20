# State Manager Module. Handles randomizing register and memory state and viewing them
# Since there can only be one instance of panda, procedures will have to take in an instance of panda to manipulate
# This means that these procedures will likely need to be called in @panda.cb_after_machine_init or the like

from random import randint, seed
from pandare.arch import PandaArch
from pandare.panda import Panda

def setRandomSeed(random_seed):
    seed(random_seed)

def randomizeRegisters(panda: Panda, cpu, regKeys=[]):
    """
    randomize the registers of the panda instance
    panda is the instance of panda to randomize the registers in
    cpu is the cpu from the callback function
    regKeys is a list of register keys that are to be randomized. If left blank if will randomize all registers
    random_seed will set the seed of the random number generator. if left as -1 it will use the default
    """
    if (panda.arch_name == "mips"):
        skippedRegs = ['ZERO', 'SP', 'K0', 'K1', 'AT', 'GP', 'FP', 'RA']
        keys = regKeys
        if (len(keys) == 0): keys = panda.arch.registers.keys()
        for key in keys:
            if key in skippedRegs: continue
            num = randint(0, 2**(32) - 1)
            panda.arch.set_reg(cpu, key, num)
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