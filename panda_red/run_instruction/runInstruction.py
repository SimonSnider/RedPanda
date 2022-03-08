from pandare import Panda
from pytest import skip
from panda_red.run_instruction.stateManager import *
from capstone import *
from capstone.mips import *
import math
from panda_red.generate_instruction.bitGenerator import *
from panda_red.models.stateData import *
import keystone
import copy


def loadInstruction(panda: Panda, cpu, instruction, address=0):
    """
    Arguments:
        panda -- the instance of panda the instruction will be loaded into
        cpu -- the cpu instance obtained from a panda callback
        instruction -- the instruction in byte form
        address -- the address location to load the instruction into
    Output:
        loads the instruction into panda's memory at the specified address,
        then loads a jump instruction immediately after it to loop through that instruction.
        Sets the program counter to address
    """

    # get the appropriate jump instruction encoding for the architecture

    jump_instr = b""
    if (panda.arch_name == "mips"):
        jump_instr = b"\x08\x00\x00\x00"
        panda.physical_memory_write(address, bytes(instruction))
        panda.physical_memory_write(address + len(instruction), bytes(jump_instr))
    elif (panda.arch_name == "x86_64"):
        ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        jmpInstr = "JMP -" + str(len(instruction))
        jump_instr, count = ks.asm(jmpInstr.encode("UTF-8"), address)
        panda.physical_memory_write(address, bytes(instruction))
        panda.physical_memory_write(address + len(instruction), bytes(jump_instr))
    
    
    panda.arch.set_pc(cpu, address)
    return

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
    elif (panda.arch_name == "x86_64"):
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
        returns a StateData object containing the instructions run and the program state data for each
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

    if (panda.arch_name == "mips"):
        md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32+ CS_MODE_BIG_ENDIAN)
    elif (panda.arch_name == "x86_64"):
        md = Cs(CS_ARCH_X86, CS_MODE_64)

     # This callback handles all of the initial setup of panda before it begins executing instructions
    @panda.cb_after_machine_init
    def setup(cpu):
        nonlocal instIndex, initialState, stateData

        # Initialize memory and load the first instruction in to initialize the emulation loop
        initializeMemory(panda, "mymem", address=ADDRESS)
        loadInstruction(panda, cpu, instructions[instIndex], ADDRESS)

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
        if (verbose): print("setup done")

    # This callback executes before each instruction is executed, it handles randomizing the registers and saving the before states
    @panda.cb_insn_exec
    def randomRegState(cpu, pc):
        nonlocal bitmask, stateData, registerStateList

        # Check if the panda is about to execute the instruction that is being tested. 
        # The register state only needs randomized before that instruction
        if (pc == ADDRESS):
            if (verbose): print("randomizing registers before execution")
            
            # Reset the registers to the initial state so that only the register specified by the bitmask are different
            setRegisters(panda, cpu, initialState)
            
            # Randomize the registers specified by the bitmask to be a value between lowerBound and upperBound
            randomizeRegisters(panda, cpu, bitmask, lowerBound, upperBound)

            # Save the bitmask and beforeState before execution and initialize the memory reads and writes arrays to be
            # modified by their respective callbacks.
            if (verbose): print("saving before reg state")
            registerStateList.bitmasks.append(bitmask)
            registerStateList.beforeStates.append(getRegisterState(panda, cpu))
            registerStateList.memoryReads.append([])
            registerStateList.memoryWrites.append([])

        if (verbose):
            # Display the instruction that is about to be executed
            code = panda.virtual_memory_read(cpu, pc, 4)
            for i in md.disasm(code, pc):
                print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
                break
        return 0

    # Tell panda to translate every instruction
    @panda.cb_after_insn_translate
    def translateAll(env, pc):
        return True

    # This callback executes after each instruction execution. It handles saving the after register state and 
    # handles instruction switching, bitmask updating, and emulation termination
    @panda.cb_after_insn_exec 
    def getInstValues(cpu, pc):
        nonlocal regStateIndex, instIndex, bitmask, registerStateList, regBoundsCount
        if (pc == ADDRESS + len(instructions[instIndex])):

            # Save the register state after executing the instruction
            if (verbose): print("saving reg state after run", regStateIndex)
            registerStateList.afterStates.append(getRegisterState(panda, cpu))
            
            # If this is true before incrementing regStateIndex, then the instruction has been run n times and 
            # the bitmask or instruction must change
            if (regStateIndex % n == 0):
                
                # Reset the register bounds since a different register will be randomized, or a differnet instruction will be run
                regBoundsCount = 0
 
                # Find the next valid register to randomize. If nextReg = -1, then it's time to switch the instruction or terminate
                nextReg = getNextValidReg(panda, math.floor(regStateIndex / n))
                if (nextReg == -1):
                    
                    # If there are remaining instructions, save the current register state list to the state data and 
                    # switch to the next instruction.
                    if (instIndex < len(instructions)-1):
                        if (verbose): print("switching instructions")
                        instIndex += 1
                        stateData.registerStateLists.append(copy.copy(registerStateList))
                        loadInstruction(panda, cpu, instructions[instIndex], ADDRESS)
                        stateData.instructions.append(instructions[instIndex])
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

                        # If there are no more instructions to run, save any remaining data and end analysis
                        if (verbose): print("end analysis")
                        stateData.registerStateLists.append(copy.copy(registerStateList))
                        panda.end_analysis()
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
        if (verbose): print(f"handled exception index {index:#x} at pc: {pc:#x}")
        regBoundsCount += 1

        # If regStateIndex == 0, The initial state is invalid and needs updated.
        if (regStateIndex == 0):
            if (verbose): print(f"re-randomizing initial state")
            
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

        # If regBoundsCount >= 31, then the instruction presumably cannot execute with any possible range of inputs that 
        # doesn't require fine tuning. End the analysis. TODO: update to switch to the next instruction instead of terminating
        if (regBoundsCount >= 31):
            print("Cannot run instruction")
            panda.end_analysis()
            return 0
        if (verbose): print(f"re-randomizing register with reduced range")
        
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
            print("pc of read:", pc)
            print("value read:", valueRead)
            print("addr of read:", addr)
            print("size of read:", size)

    @panda.cb_virt_mem_before_write
    def managewrite(cpu, pc, addr, size, data):
        nonlocal memoryStructure, stateData, registerStateList

        # set the fake memory structure to hold the newly written data
        memoryStructure[addr] = data

        # create and store a new memory transaction for the write
        memoryTransaction = MemoryTransaction("write", data, addr, size)
        registerStateList.memoryWrites[-1].append(memoryTransaction)

        if(verbose):        
            print("pc of write:", pc)
            print("addr of write:", addr)
            print("size of write:", size)
            print("data of write:", data)
    
    panda.enable_precise_pc()
    panda.cb_insn_translate(lambda x, y: True)
    panda.run()
    return stateData
