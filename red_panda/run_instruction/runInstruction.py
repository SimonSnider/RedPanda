from time import sleep
from pandare import Panda
from pytest import skip
from red_panda.run_instruction.stateManager import *
from red_panda.run_instruction.runInstruction import *
from capstone import *
from capstone.mips import *
import math
from red_panda.generate_instruction.bitGenerator import *
from red_panda.utilities.printOptions import *
from red_panda.models.stateData import *
import keystone.keystone
import copy
from red_panda.create_output.intermediateJsonOutput import *

def loadInstruction(panda: Panda, cpu, instruction, address=0, md=None):

    """
    Arguments:
        panda -- the instance of panda the instruction will be loaded into
        cpu -- the cpu instance obtained from a panda callback
        instruction -- the instruction in byte form
        address -- the address location to load the instruction into
        md -- a dissasembler used to print the isntruction mnemonic
    Output:
        loads the instruction into panda's memory at the specified address,
        then loads a jump instruction immediately after it to loop through that instruction.
        Sets the program counter to address
        returns the stop address
    """

    # get the appropriate jump instruction encoding for the architecture
    jump_instr = b""

    # Display the instruction that is about to be executed
    for i in md.disasm(bytes(instruction), 0):
        printSubsystemFunction("Loading instruction: \t%s\t%s" % (i.mnemonic, i.op_str))
        break

    #load the instruction into memory
    panda.physical_memory_write(address + len(instruction), bytes(instruction))

    #determine what kind of jump instruction we need
    if (panda.arch_name == "mips"):
        jump_instr = b"\x08\x00\x00\x00"
    elif (panda.arch_name == "x86_64"):
        ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        jmpInstr = "JMP -" + str(address)
        jump_instr, count = ks.asm(jmpInstr.encode("UTF-8"), address)
    
    #load jump instruction into memory, initialize the pc value, and return the finish address
    panda.physical_memory_write(address + len(instruction), bytes(jump_instr))
    panda.arch.set_pc(cpu, address)
    return address + len(instruction)

def getNextValidReg(panda: Panda, regNum):
    """
    Arguments:
        panda -- the instance of panda the next valid register will be found in
        startIndex -- the start index for the search
    Output:
        returns the index of next register in the architecture that is allowed to be modified, using
        the "skipped regs" specifications from the stateManager module. returns -1 if there are no more
        valid registers
    """
    skippedRegs = []
    if (panda.arch_name == "mips"):
        skippedRegs = skippedMipsRegs
    if (panda.arch_name == "x86_64"):
        skippedRegs = skippedX86Regs
    regs = list(panda.arch.registers.keys())
    count = 0
    for i in range(len(regs)):
        if (regs[i] not in skippedRegs):
            if (count >= regNum):
                return i
            else:
                count += 1
    return -1

def runInstructions(panda: Panda, instructions, n, verbose=False):
    """
    Arguments:
        panda -- The instance of panda the instructions will be run on
        instructions -- the list of instructions in byte form that will be run on the panda instance
        n -- the number of times each instruction will be run on each bitmask
        verbose -- enables printing of step completions and instructions being run
    Outputs:
        stateData -- a StateData object containing the instructions run and the program state data for each
        modelList -- A list of matrix representations of panda's correlational models for each instruction
    """
    ADDRESS = 0
    stateData = StateData()
    registerStateList = RegisterStateList()
    regStateIndex = 0
    instIndex = 0
    regBoundsCount = 0
    upperBound = 2**(31) - 1
    lowerBound = -(2**31)
    numRegs = len(panda.arch.registers)
    bitmask = b'\0'*(math.ceil(numRegs/8))
    initialState = {}
    memoryStructure = dict()
    stopaddress = 0
    iters = 0
    size = len(panda.arch.registers.items())
    modelList = []
    model = [[0] * size for _ in range(size)]

    #initialize capstone for the architecture
    if (panda.arch_name == "mips"):
        md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32+ CS_MODE_BIG_ENDIAN)
    elif (panda.arch_name == "x86_64"):
        md = Cs(CS_ARCH_X86, CS_MODE_64)

     # This callback handles all of the initial setup of panda before it begins executing instructions
    @panda.cb_after_machine_init
    def setup(cpu):
        nonlocal instIndex, initialState, stateData, stopaddress, model, size
       
        # Initialize memory and load the first instruction in to initialize the emulation loop
        initializeMemory(panda, "mymem", address=ADDRESS)
        stopaddress = loadInstruction(panda, cpu, instructions[instIndex], ADDRESS, md=md)

        panda.taint_enable()

        # Load the first instruction byte encoding and mnemonic into the stateData object
        stateData.instructions.append(instructions[instIndex])
        code = panda.virtual_memory_read(cpu, ADDRESS, 4)
        for i in md.disasm(code, 0):
            instr = i.mnemonic + " " + i.op_str
            stateData.instructionNames.append(instr)
            break

        # Generate the initial state before instruction execution
        randomizeRegisters(panda, cpu)
        initialState = getRegisterState(panda, cpu)

        # disable taint data gathering callbacks
        panda.disable_callback("randomRegStateTaint")
        panda.disable_callback("getInstValuesTaint")
        panda.disable_callback("bheTaint")

        # initialize the model with zeros
        for (regname, reg) in panda.arch.registers.items():
            model[reg] = [0]*size #len(panda.arch.registers.items())

        printSubsystemFunction("Random instruction setup complete")

    # gather instruction data
    ###########################################################################################################################################

    # This callback executes before each instruction is executed, it handles randomizing the registers and saving the before states
    @panda.cb_insn_exec
    def randomRegState(cpu, pc):
        nonlocal bitmask, stateData, registerStateList

        # Check if the panda is about to execute the instruction that is being tested. 
        # The register state only needs randomized before that instruction
        if (pc == ADDRESS):
            if (verbose): printStandard("---\nRandomizing registers before execution #" + str(regStateIndex))
            
            # Reset the registers to the initial state so that only the register specified by the bitmask are different
            setRegisters(panda, cpu, initialState)
            
            # Randomize the registers specified by the bitmask to be a value between lowerBound and upperBound
            randomizeRegisters(panda, cpu, bitmask, lowerBound, upperBound)

            # Save the bitmask and beforeState before execution and initialize the memory reads and writes arrays to be
            # modified by their respective callbacks.
            if (verbose): printStandard("Saving before state of registers")
            registerStateList.bitmasks.append(bitmask)
            registerStateList.beforeStates.append(getRegisterState(panda, cpu))
            registerStateList.memoryReads.append([])
            registerStateList.memoryWrites.append([])

        # if (False):
        #     # Display the instruction that is about to be executed
        #     code = panda.virtual_memory_read(cpu, pc, 4)
        #     for i in md.disasm(code, pc):
        #         printStandard("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        #         break
        return 0

    # Tell panda to translate every instruction
    @panda.cb_after_insn_translate
    def translateAll(env, pc):
        return True

    # This callback executes after each instruction execution. It handles saving the after register state and 
    # handles instruction switching, bitmask updating, and switching to taint model gathering
    @panda.cb_after_insn_exec 
    def getInstValues(cpu, pc):
        nonlocal regStateIndex, instIndex, bitmask, registerStateList, regBoundsCount
        if (pc == stopaddress):

            # Save the register state after executing the instruction
            if (verbose): printStandard("Saving register state after run")
            registerStateList.afterStates.append(getRegisterState(panda, cpu))

            # If this is true before incrementing regStateIndex, then the instruction has been run n times and 
            # the bitmask or instruction must change
            if (regStateIndex % n == 0):
                
                # Reset the register bounds since a different register will be randomized, or a differnet instruction will be run
                regBoundsCount = 0
 
                # Find the next valid register to randomize. If nextReg = -1, then it's time to switch the instruction or terminate
                nextReg = getNextValidReg(panda, math.floor(regStateIndex / n))
#                printComment(nextReg, ": Next register ------------------------------------------------------------")
                if (nextReg == -1):
                    
                    # If there are remaining instructions, save the current register state list to the state data and 
                    # switch to the next instruction.
#                    printComment(str(instIndex) + ": instIndex --------------------------------------------------------------")
                    if (instIndex < len(instructions)-1):
                        if (verbose): printStandard("Switching instructions")
                        instIndex += 1
                        stateData.registerStateLists.append(copy.copy(registerStateList))

                        #flush the translation block cache to ensure retranslation of new instruction
                        panda.flush_tb()
                        loadInstruction(panda, cpu, instructions[instIndex], ADDRESS, md=md)
                
                        stateData.instructions.append(instructions[instIndex])

                        #add the instruction mnemonic to stateData
                        code = panda.virtual_memory_read(cpu, ADDRESS, 4)
                        for i in md.disasm(code, ADDRESS):
                            instr = i.mnemonic + " " + i.op_str
                            stateData.instructionNames.append(instr)
                            break

                        # Reset nonlocal variables for beginning of next instruction emulation
                        registerStateList = RegisterStateList()
                        regStateIndex = 0
                        bitmask = b'\0'*(math.ceil(numRegs/8))
                        return 0
                    else:

                        # If there are no more instructions to run, switch to gathering taint data
                        if(verbose): printStandard("---");
                        printSubsystemFunction("Random data gathered, switching to taint gathering")
                        stateData.registerStateLists.append(copy.copy(registerStateList))
                       
                        # enable taint model gathering callbacks
                        panda.enable_callback("randomRegStateTaint")
                        panda.enable_callback("getInstValuesTaint")
                        panda.enable_callback("bheTaint")
                        
                        #remove stateData gathering callbacks
                        panda.disable_callback("randomRegState")
                        panda.disable_callback("getInstValues")
                        panda.disable_callback("bhe")
                        panda.disable_callback("manageread")
                        panda.disable_callback("managewrite")

                        instIndex = 0
                        
                        #flush the translation block cache and load in the first instruction
                        panda.flush_tb()
                        loadInstruction(panda, cpu, instructions[instIndex], ADDRESS, md=md)

                        # after this, the instruction data gathering should be finished and the system
                        # should begin gathering panda's taint models
                        return 0
            
                # Update the bitmask to randomize the next valid register
                bitmask = int.to_bytes(1<<(nextReg), (math.ceil(numRegs/8)), 'big')
            regStateIndex += 1
        return 0

    # This callback is executed when an instruction throws an exception. It handles finding a valid initial state,
    # modifying the randomized register ranges, rolling back saved data, and terminating if an instruction cannot be executed
    @panda.cb_before_handle_exception
    def bhe(cpu, index):
        nonlocal regBoundsCount, bitmask, stateData, regStateIndex, initialState, registerStateList, upperBound, lowerBound
        pc = cpu.panda_guest_pc
        if (verbose): printStandard(f"handled exception index {index:#x} at pc: {pc:#x}")
        regBoundsCount += 1

        # If regBoundsCount >= 31, then the instruction presumably cannot execute with any possible range of inputs that 
        # doesn't require fine tuning. switch to the next instruction, if there are none left, set up the taint model gathering system
        if (regBoundsCount >= 31):
            printError("cannot execute instruction, switching to next instruction")
            if (instIndex < len(instructions)-1):
                if (verbose): printStandard("Switching instructions")
                instIndex += 1
                stateData.registerStateLists.append(copy.copy(registerStateList))

                #flush the translation block cache to ensure retranslation of new instruction
                panda.flush_tb()
                loadInstruction(panda, cpu, instructions[instIndex], ADDRESS, md=md)
        
                stateData.instructions.append(instructions[instIndex])

                # add the instruction mnemonic to the stateData
                code = panda.virtual_memory_read(cpu, ADDRESS, 4)
                for i in md.disasm(code, ADDRESS):
                    instr = i.mnemonic + " " + i.op_str
                    stateData.instructionNames.append(instr)
                    break

                # Reset nonlocal variables for beginning of next instruction emulation
                registerStateList = RegisterStateList()
                regStateIndex = 0
                bitmask = b'\0'*(math.ceil(numRegs/8))
            else:

                # If there are no more instructions to run, switch to gathering taint data
                if(verbose): printStandard("---");
                printSubsystemFunction("Random data gathered, switching to taint gathering")
                stateData.registerStateLists.append(copy.copy(registerStateList))
                
                # enable taint model gathering callbacks
                panda.enable_callback("randomRegStateTaint")
                panda.enable_callback("getInstValuesTaint")
                panda.enable_callback("bheTaint")
                
                #remove stateData gathering callbacks
                panda.disable_callback("randomRegState")
                panda.disable_callback("getInstValues")
                panda.disable_callback("bhe")
                panda.disable_callback("manageread")
                panda.disable_callback("managewrite")

                instIndex = 0
                
                #flush the translation block cache and load in the first instruction
                panda.flush_tb()
                loadInstruction(panda, cpu, instructions[instIndex], ADDRESS, md=md)

                # after this, the instruction data gathering should be finished and the system
                # should begin gathering panda's taint models
            return 0

        # If regStateIndex == 0, The initial state is invalid and needs updated.
        if (regStateIndex == 0):
            if (verbose): printStandard("Re-randomizing initial state")
            
            # Reduces the upper and lower bounds by a factor of 2 every 6 exceptions until a valid initial state is found
            upperBound = 2**(31 - math.floor(regBoundsCount / 6)) - 1
            lowerBound = -(2**(31 - math.floor(regBoundsCount/6)))
            randomizeRegisters(panda, cpu, minValue=lowerBound, maxValue=upperBound)
            initialState = getRegisterState(panda, cpu)
            registerStateList.beforeStates = []
            registerStateList.bitmasks = []
            registerStateList.afterStates = []
            registerStateList.memoryWrites = []
            registerStateList.memoryReads = []
            return -1

        if (verbose): printStandard(f"re-randomizing register with reduced range")
        
        # If regStateIndex > 0, then a valid initial state has been found. Now the upper and lower bound are reduced by
        # a factor of 2 every exception and the data saved before the exception occured (before state, bitmask, and mem 
        # reads and writes) is removed
        upperBound = 2**(31 - regBoundsCount) - 1
        lowerBound = -(2**(31 - regBoundsCount))
        registerStateList.beforeStates.pop()
        registerStateList.bitmasks.pop()
        registerStateList.memoryReads.pop()
        registerStateList.memoryWrites.pop()
        return -1

    # Tell panda to cal memory callbacks
    panda.enable_memcb()

    # This callback executes before panda tries to read from memory. It handles intercepting the read
    # address and saving that information in the registerStateList object.
    @panda.cb_virt_mem_before_read
    def manageread(cpu, pc, addr, size):
        nonlocal memoryStructure, stateData, lowerBound, upperBound
    
        # if the memory location has never been accessed then randomly generate a value and store it in the fake memory structure
        if not (addr in memoryStructure):
            memoryStructure[addr] = generateRandomMemoryValues(lowerBound, upperBound)

        # read the value Read from the memory structure
        valueRead = memoryStructure[addr]

        # create and store a new memory transaction for the read
        memoryTransaction = MemoryTransaction("read", valueRead, addr, size)
        registerStateList.memoryReads[-1].append(memoryTransaction)

        if(verbose):
            printStandard("pc of read:" + str(pc))
            printStandard("value read:" + str(valueRead))
            printStandard("addr of read:" + str(addr))
            printStandard("size of read:" + str(size))

    @panda.cb_virt_mem_before_write
    def managewrite(cpu, pc, addr, size, data):
        nonlocal memoryStructure, stateData, registerStateList

        # set the fake memory structure to hold the newly written data
        memoryStructure[addr] = data

        # create and store a new memory transaction for the write
        memoryTransaction = MemoryTransaction("write", data, addr, size)
        registerStateList.memoryWrites[-1].append(memoryTransaction)

        if(verbose):        
            printStandard("pc of write:", str(pc))
            printStandard("addr of write:", str(addr))
            printStandard("size of write:", str(size))
            printStandard("data of write:", str(data))
    
    #Gather Taint Data
    #####################################################################################################################

    # this callback is called before panda executes an instruction, it handles randomizing 
    # the register state with tainting of registers enabled
    @panda.cb_insn_exec
    def randomRegStateTaint(cpu, pc):
        if(verbose): printStandard("Randomize register state")
        # Check if the panda is about to execute the instruction that is being tested. 
        # The register state only needs randomized before that instruction
        if (pc == ADDRESS):
            if (verbose): printStandard("Tainting registers before execution")
            # Randomize the registers to a value between lowerBound and upperBound
            randomizeRegisters(panda, cpu, minValue=lowerBound, maxValue=upperBound, taintRegs=True)

        if (verbose):
            # Display the instruction that is about to be executed
            code = panda.virtual_memory_read(cpu, pc, 4)
            for i in md.disasm(code, pc):
                printStandard("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
                break
        return 0

    # This callback executes after each instruction execution. It handles collecting taint information,
    # switching instructions, and ending analysis
    @panda.cb_after_insn_exec 
    def getInstValuesTaint(cpu, pc):
        nonlocal regBoundsCount, iters, model, instIndex, modelList
        printComment(iters)
        if (pc == stopaddress):
            for (regname, reg) in panda.arch.registers.items():
                result = panda.taint_get_reg(reg)[0]
                if(result is not None):
                    labels = panda.taint_get_reg(reg)[0].get_labels()
                    for label in labels:
                        model[label][reg] += 1

            if (iters >= n):
                if(instIndex < len(instructions) - 1):
                    # Instruction Finished collecting iterations
                    # Switching to next instruction
                    instIndex += 1
                    iters = 0
                    modelList.append(model)
                    model = [[0] * size for _ in range(size)]
                    panda.flush_tb()
                    printComment(instIndex)
                    loadInstruction(panda, cpu, instructions[instIndex], ADDRESS, md=md)
                else:
                    #no more instructions to run, end analysis
                    modelList.append(model)
                    panda.end_analysis()
            iters += 1
        return 0

    # This callback is executed when an instruction throws an exception. It handles finding a valid initial state,
    # modifying the randomized register ranges, and rolling back saved data.
    @panda.cb_before_handle_exception
    def bheTaint(cpu, index):
        nonlocal regBoundsCount, upperBound, lowerBound, iters, instIndex
        pc = cpu.panda_guest_pc
        if (verbose): printStandard(f"handled exception index {index:#x} at pc: {pc:#x}")
        regBoundsCount += 1
        if (regBoundsCount >= 32):
            if(instIndex < len(instructions) - 1):
                # Instruction Finished collecting iterations
                # Switching to next instruction
                instIndex += 1
                iters = 0
                modelList.append(model)
                model = [[0] * size for _ in range(size)]
                panda.flush_tb()
                printComment(instIndex)
                loadInstruction(panda, cpu, instructions[instIndex], ADDRESS, md=md)
            else:
                #no more instructions left to run, end analysis
                modelList.append(model)
                panda.end_analysis()
            return 0
        # update the register bounds and rerandomize the register state
        upperBound = 2**(31 - math.floor(regBoundsCount/6)) - 1
        lowerBound = -(2**(31 - math.floor(regBoundsCount/6)))
        randomizeRegisters(panda, cpu, minValue=lowerBound, maxValue=upperBound) # retaint registers???
        panda.arch.set_pc(cpu, ADDRESS)
        return -1

    panda.enable_precise_pc()
    panda.cb_insn_translate(lambda x, y: True)
    panda.run()
    return [stateData, modelList]
