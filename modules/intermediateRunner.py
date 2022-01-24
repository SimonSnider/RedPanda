"""Intermediary Component which may be used as a standalone executable or as a callable module from other scripts

Execution
Arguments:
        arg1 -- output file

        arg2 -- arch -- specifies the architecture for which the system is run (default = MIPS32)
        Valid Arguments:
            mips32 -- Use the MIPS architecture

        arg3 -- instructionTotal -- specifies the total number of random instructions to generate data for (default = 1)

        arg4 -- instructionIterations -- specifies the number times an instruction is run and data is generated (default = 10)

        arg5 -- analysis model -- specifies the type of analysis to be run on the data
        Valid Arguments:
            reg-coorelational -- calculate coorelation between register values before and after an instruction is run
"""

import os
from modules.runInstruction.instructionRunner import generateInstructionData
from modules.getCorrelations import correlationCalculator as CC 
from modules.generateInstruction import instructionGenerator as instructionGen
from modules.createOutput import matrixOutput as output
import keystone as k
import sys

module_location = os.path.abspath(__file__)
module_dir = os.path.dirname(module_location)

def runInputAndModel():
    #
    # Take user input and specify run modes.
    #

    # File Name
    print("Specify an output file name (default = data)")
    outputFileName = input() or "data"

    # Architecture
    print("Specify an architecture (default = 0)")
    print("Supported Architectures")
    print("    0 - mips32")
    try:
        arch = int(input() or 0)
    except ValueError:
        print("Value supplied not numerical. Please supply a numeric value corresponding to a supported architecture.")
        return

    if arch == 0:
        arch = 'mips32'
    else:
        print("Architecture not within supported range. Please enter a supported architecture value.")
        return

    # Instruction Mode
    print("Specify a mode (default = 0)")
    print("Supported Modes")
    print("    0 - random")
    print("    1 - byte-specified")
    print("    2 - text-specified")
    try:
        mode = int(input() or 0)
    except ValueError:
        print("Value supplied not numerical. Please supply a numeric value corresponding to a supported mode.")
        return

    numInstructions = 0
    instructionsFile = ""

    if mode == 0:
        print("Specify the number of instructions to generate data for (default = 1)")
        try:
            numInstructions = int(input() or 1)
        except ValueError:
            print("Value supplied not numerical. Please supply a numeric value.")
            return
    elif mode == 1:
        print("Specify the file containing the instructions (default = byte_specifications.txt)")
        instructionsFile = input() or os.path.join(module_dir, "byte_specifications.txt")
    elif mode == 2:
        print("Specify the file containing the instructions (default = instruction_specifications.txt)")
        instructionsFile = input() or os.path.join(module_dir, "instruction_specifications.txt")
    else:
        print("Mode not within supported range. Please enter a supported mode value.")
        return

    # Instruction Iterations
    print("Specify the number of times an instruction is run (default = 10)")
    try:
        instructionIterations = int(input() or 10)
    except ValueError:
        print("Value supplied not numerical. Please supply a numeric value.")
        return

    # Analysis Model
    print("Specify the analysis model (default = 0)")
    print("Supported Models")
    print("    0 - reg-coorelational")
    print("    1 - mem-reg-coorelational")
    try:
        model = int(input() or 0)
    except ValueError:
        print("Value supplied not numerical. Please supply a numeric value corresponding to a supported model.")
        return

    if model < 0 or model > 1:
        print("Model not within supported range. Please enter a supported model value.")
        return

    # Output Form
    print("Specify the output form (default = 0)")
    print("Supported Forms")
    print("    0 - coorelation matrix")
    try:
        form = int(input() or 0)
    except ValueError:
        print("Value supplied not numerical. Please supply a numeric value corresponding to a supported output form.")
        return

    if form < 0 or form > 1:
        print("Output not within supported range. Please enter a supported output form value.")
        return

    # Verbosity
    print("Verbose? (default = 0)")
    try:
        verbose = int(input() or 0)
    except ValueError:
        print("Value supplied not numerical. Please supply a numeric value.")
        return
    
    if(verbose < 0 or verbose > 1):
        print("Value supplied is not either 0 or 1. Please supply a valid value.")
        return

    runModel(arch, mode, instructionIterations, outputFileName, instructionsFile, numInstructions, form, verbose)



def runModel(arch, mode, instructionIterations, outputFileName, instructionsFile = "", numInstructions = 1, form = 0, verbose = 0):
    #
    # Generate instructions or load them from a file
    # 
    if mode == 0:
        # Instructions are generated randomly using the generateInstruction module
        instructionList = []
        instructionGenerator = instructionGen.initialize(arch)

        for _ in range(numInstructions):
            instructionList.append(instructionGen.generateInstruction(instructionGenerator))
    elif mode == 1:
        # Instructions are given in byte format in a text file
        instructionList = []

        # Read file
        with open(instructionsFile) as f:
            lines = f.readlines()

        # Parse file
        for line in lines:
            # Ignore comments and blank lines
            if (line[0] == '#') or (len(line) < 2):
                continue;

            instructionList.append(bytes(line, encoding="raw_unicode_escape"))
    elif mode == 2:
        # Instructions are given in an unassembled format in a text file
        instructionList = []
        
        # Instantiate the Keystone assembler to assemble instructions
        KS = k.Ks(k.KS_ARCH_MIPS,k.KS_MODE_MIPS32 + k.KS_MODE_BIG_ENDIAN)
        ADDRESS = 0x0000

        # Read file
        with open(instructionsFile) as f:
            lines = f.readlines()

        # Parse file
        for line in lines:
            #Ignore comments and blank lines
            if (line[0] == '#') or (len(line) < 2):
                continue;

            code = line.encode('UTF-8')
            encoding, count = KS.asm(code, ADDRESS)

            instructionList.append(encoding)
    else:
        print("Mode supplied invalid. Must be 0, 1, or 2")
        return

    #
    # Run the instructions through the Panda.re engine
    #
    instructionData = generateInstructionData(arch, instructionList, instructionIterations, verbose)

    #
    # Generate coorelation data from the instruction results
    #
    CC.setArch("mips32")
    analyzedData = []
    
    instructionKeys = list(instructionData.keys())
    for i in range(1):
        dat = instructionData[instructionKeys[i]]
        CC.initialize(dat, 1)
        print(CC.computeCorrelations())
        analyzedData.append(CC.computeCorrelations())

    # fields = ['InstructionName', 'Coorelation'] 

    output.generateOutput(analyzedData, outputFileName)

if len(sys.argv) > 1:
    if sys.argv[1] == "-c":
        # arguments list
        arguments = []

        # Read file
        fname = "debug.cfg"
        debug_file = os.path.join(module_dir, fname)
        with open(debug_file) as f:
            lines = f.readlines()

        # Parse file
        for line in lines:
            # Ignore comments and blank lines
            if (line[0] == '#') or (len(line.rstrip('\n')) < 1):
                continue;

            arguments.append(line.rstrip('\n'))
        print(len(arguments))
        print("Read instruction arguments: \nArchitecture:", arguments[0], 
            "\nInstruction Mode:", arguments[1], 
            "\nInstruction Iterations:", arguments[2], 
            "\nOutput File Name:", arguments[3], 
            "\nInstructions File:", arguments[4], 
            "\nNumber of Instructions to Generate:", arguments[5],
            "\nVerbose:", arguments[6]
            )

        runModel(arguments[0], int(arguments[1]), int(arguments[2]), arguments[3], arguments[4], int(arguments[5]), int(arguments[6]))
    else:
        runInputAndModel()
else:
    runInputAndModel()