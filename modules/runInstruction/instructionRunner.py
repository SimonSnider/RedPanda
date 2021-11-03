from modules.generateInstruction import instructionGenerator as instructionGen
from modules.runInstruction.stateManager import initializePanda

def generateInstructionData(arch="mips", instructionTotal=1, instructionIterations=10, verbose=False):
    """Generates a structure of data pertaining to randomly generated instructions in a set ISA.

    Arguments:
        arch -- specifies the architecture to generate instruction data for (default = mips32)
        Valid Arguments:
            mips32 -- Use the MIPS architecture

        instructionTotal -- specifies the total number of random instructions to generate data for (default = 1)

        instructionIterations -- specifies the number times an instruction is run and data is generated (default = 10)

    Output:
        Returns a dictionary of <instruction bytecode> -> <result array> pairings where the result array is an <instructionIterations x 2> array 
        with the first column specifying the register state before instruction execution and the second column specifying the register state afterwards.

        Register state is stored as a dictionary of <register name> -> <register value> pairings. 
    """
    pandaInstance = initializePanda(arch)
    instructionGen.initialize(arch)

    instructionList = [b"\x01\x4b\x48\x20"]

    # for _ in range(instructionTotal):
    #     instructionList.append(instructionGen.generateInstruction())

    return runInstructions(pandaInstance, instructionList, instructionIterations, verbose) 