from pandare import Panda
from stateManager import *

def loadInstruction(panda: Panda, cpu, instruction, address=0):
    """
    Takes an instance of panda, a cpu from the setup callback, an instruction, and an address.
    loads the instruction into phyiscal memory at the address and sets the program counter to the address
    """
    panda.physical_memory_write(address, instruction)
    cpu.env_ptr.active_tc.PC = address
    return

def runInstructionLoop(instruction, n):
    """
    runs the instruction n times and returns the register states
    [[before, after], [before, after], ...]
    """
    panda = initializePanda()

    panda.register_cal
    ADDRESS = 0
    stateData = []
    index = -1

    @panda.cb_after_machine_init
    def setup(cpu):
        initializeMemory(panda, "mymem", address=ADDRESS)
        loadInstruction(panda, cpu, instruction, ADDRESS)
        # Set starting_pc
        cpu.env_ptr.active_tc.PC = ADDRESS

    @panda.cb_insn_exec
    def randomRegState(cpu, pc):
        randomizeRegisters(panda, cpu)
        stateData.append([getRegisterState(panda, cpu)])
        nonlocal index
        index += 1

    @panda.cb_after_insn_exec
    def getInstValues(cpu, pc):
        stateData[index].append(getRegisterState(panda, cpu))
        if (index < n):
            cpu.env_ptr.active_tc.PC = ADDRESS
        else:
            panda.end_analysis()
    
    panda.run()
    return stateData

