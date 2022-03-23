from panda_red.utilities.printOptions import printStandard, printSubsystemFunction
from panda_red.generate_instruction import verifierAdapter as verAdapt
from panda_red.generate_instruction import bitGenerator as bitGen
from panda_red.generate_instruction.filterer import filtererBasicMIPS as fBMIPS



def initialize(arch="mips32", littleEndian=False):
    """Initializes an architecture to generate instructions

    Arguments:
        arch -- specifies the architecture for which instructions are generated (default = mips32)
        littleEndian -- specifies the instructions to be verified in little endian mode (default = False)

    Valid Arguments:
        mips32 -- Use the MIPS architecture
        x86_64 -- Use the x86_64 architecture
    """
    return verAdapt.initialize(arch, littleEndian)

def generateInstruction(instructionGenerator, filterer, verbose=False):
    """Generates a single instruction in the currently selected ISA
    Instructions generated in this way are valid instructions for the current ISA 
    and are runnable on the currently tested Taint-Tracker system.

    Arguments:
        verbose -- turns on printing of generated instruction bytes (default = False)

    Output:
        One instruction specified in byte format machine code
    """

    # Continually generate random bytes until a valid instruction is generated
    while True:
        randomInstructionBytes = bitGen.generateRandomBytes(4)
        if(verbose):
            printStandard("Proposing instruction bytes:" + bitGen.byteBinaryString(randomInstructionBytes))

        # Check if the instruction is a valid instruction in the ISA
        if(not verAdapt.isValidInstruction(instructionGenerator, randomInstructionBytes)):
            if(verbose): printStandard("Byte string not valid for given ISA, throwing out bytes")
            continue

        # Check if the instruction should be filtered out for the current implementation selection
        if(not filterer.filterInstruction(randomInstructionBytes)):
            if(verbose): printStandard("Byte string does not pass filter, throwing out bytes")
            continue

        break;

    if(verbose): printStandard("Bytes accepted")
    else: printSubsystemFunction("Intruction bytes generated: " + bitGen.byteBinaryString(randomInstructionBytes))
    return randomInstructionBytes