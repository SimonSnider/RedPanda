from modules.generateInstruction import verifierAdapter as verAdapt
from modules.generateInstruction import bitGenerator as bitGen
from modules.generateInstruction.filterer import filtererBasicMIPS as fBMIPS

def initialize(arch="mips32"):
    """Initializes an architecture to generate instructions

    Arguments:
        arch -- specifies the architecture for which instructions are generated (default = mips32)

    Valid Arguments:
        mips32 -- Use the MIPS architecture
    """
    verAdapt.setISA(arch)
    verAdapt.initialize()

def setISA(arch):
    """Changes the current architecture to a newly specified one
    
    Arguments:
        arch -- specifies the architecture for which instructions are generated

    Valid Arguments:
        mips32 -- Use the MIPS architecture
    """
    verAdapt.setISA(arch)

def generateInstruction(verbose=False):
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
            print(bitGen.byteBinaryString(randomInstructionBytes))

        if(verAdapt.isValidInstruction(randomInstructionBytes)):
            continue

        if(fBMIPS.filterInstruction(randomInstructionBytes)):
            continue

        break;

    return randomInstructionBytes