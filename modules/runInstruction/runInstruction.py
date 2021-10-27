from pandare import Panda
from modules.runInstruction.stateManager import *

def loadInstruction(panda: Panda, cpu, instruction, address=0):
    """
    Takes an instance of panda, a cpu from the setup callback, an instruction, and an address.
    loads the instruction into phyiscal memory at the address and sets the program counter to the address
    """
    panda.physical_memory_write(address, bytes(instruction))
    cpu.env_ptr.active_tc.PC = address
    return

def runInstructionLoop(instruction, n):
    """
    runs the instruction n times and returns the register states
    [[before, after], [before, after], ...]
    """
    print("initializing panda")
    panda = initializePanda()
    ADDRESS = 0
    stateData = []
    index = -1


    @panda.cb_after_machine_init
    def setup(cpu):
        initializeMemory(panda, "mymem", address=ADDRESS)
        loadInstruction(panda, cpu, instruction, ADDRESS)
        panda.enable_precise_pc()
        print("setup done")


    @panda.cb_insn_exec
    def randomRegState(cpu, pc):
        print("randomizing registers", pc)
        randomizeRegisters(panda, cpu)
        stateData.append([getRegisterState(panda, cpu)])
        nonlocal index
        index += 1
        return 0

    @panda.cb_after_insn_translate
    def translateAll(env, pc):
        return True

    @panda.cb_after_insn_exec
    def getInstValues(cpu, pc):
        print("saving after reg state")
        stateData[index].append(getRegisterState(panda, cpu))
        if (index < n-1):
            print("looping backwards")
            panda.arch.set_pc(cpu, 0)
            print(panda.arch.get_pc(cpu))
        else:
            print("end analysis")
            panda.end_analysis()
        return 0

    panda.cb_insn_translate(lambda x,y: True)
    
    panda.run()
    return stateData

