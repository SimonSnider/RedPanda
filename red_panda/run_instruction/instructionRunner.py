from red_panda.run_instruction.stateManager import initializePanda
from red_panda.run_instruction import runInstruction as S

def generateInstructionData(arch, instructionList, instructionIterations=10, verbose=False):
    """Generates a structure of data pertaining to randomly generated instructions in a set ISA.

    Arguments:
        arch -- specifies the architecture to generate instruction data for (default = mips32)
        Valid Arguments:
            mips32 -- Use the MIPS architecture

        instructionIterations -- specifies the number times an instruction is run and data is generated (default = 10)

    Output:
        Returns a dictionary of <instruction bytecode> -> <result array> pairings where the result array is an <instructionIterations x 2> array 
        with the first column specifying the register state before instruction execution and the second column specifying the register state afterwards.

        Register state is stored as a dictionary of <register name> -> <register value> pairings. 
    """
    pandaInstance = initializePanda(arch)

    return S.runInstructions(pandaInstance, instructionList, instructionIterations, verbose) 
