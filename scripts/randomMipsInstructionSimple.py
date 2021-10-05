from pandare import Panda
from capstone import *
from capstone.mips import *
from keystone import *
from enum import Enum
from random import choice, randint
import os


#This code is attempting to run a random mips command with random inputs
Itypes = Enum('Itypes', 'R I J')

instructions = [
    ['add', Itypes.R],
    ['addu', Itypes.R],
    ['addiu', Itypes.I],
    ['addi', Itypes.I],
    ['sub', Itypes.R],
    ['subu', Itypes.R],
    ['and', Itypes.R],
    ['andi', Itypes.I],
    # ['lw', Itypes.I],
    ['lui', Itypes.I],
    # ['lbu', Itypes.I],
    # ['lhu', Itypes.I],
    # ['ll', Itypes.I], this one uses arrays
    ['nor', Itypes.R],
    ['or', Itypes.R],
    ['ori', Itypes.I],
    ['slt', Itypes.R],
    ['slti', Itypes.I],
    ['sltiu', Itypes.I],
    ['sltu', Itypes.I],
]

registers = ['$t0', '$t1', '$t2', '$t3', '$t4', '$t5', '$t6', '$t7', '$t8', '$t9']

def getRandomInstruction():
    instruction = ""
    rando = choice(instructions)
    instruction += rando[0] + " "
    if (rando[1] == Itypes.R):
        instruction += choice(registers) + ", " + choice(registers) + ", " + choice(registers)
    elif (rando[1] == Itypes.I):
        instruction += choice(registers) + ", " + str(randint(0, 100))
    elif (rando[1] == Itypes.J):
        instruction += ""
    return instruction

instruction = getRandomInstruction()
print(instruction)
CODE = instruction.encode('UTF-8')

ks = Ks(KS_ARCH_MIPS,KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)

ADDRESS = 0x1000
encoding, count = ks.asm(CODE, ADDRESS)
stop_addr = ADDRESS + len(encoding)

panda = Panda("mips",
        extra_args=["-M", "configurable", "-nographic"],
        raw_monitor=True) # Allows for a user to ctrl-a + c then type quit if things go wrong

@panda.cb_after_machine_init
def setup(cpu):
    '''
    After our CPU has been created, allocate memory and set starting state
    '''
    # map 2MB memory for this emulation
    panda.map_memory("mymem", 2 * 1024 * 1024, ADDRESS)

    # Write code into memory
    panda.physical_memory_write(ADDRESS, bytes(encoding))

    # Set up registers
    #cpu.env_ptr.active_tc.gpr[panda.arch.registers['t0']] = 0x10
    panda.arch.set_reg(cpu, 't0', 0x00)
    panda.arch.set_reg(cpu, 't1', 0x01)
    panda.arch.set_reg(cpu, 't2', 0x02)
    panda.arch.set_reg(cpu, 't3', 0x03)
    panda.arch.set_reg(cpu, 't4', 0x04)
    panda.arch.set_reg(cpu, 't5', 0x05)
    panda.arch.set_reg(cpu, 't6', 0x06)
    panda.arch.set_reg(cpu, 't7', 0x07)
    panda.arch.set_reg(cpu, 't8', 0x08)
    panda.arch.set_reg(cpu, 't9', 0x09)

    # Set starting_pc
    cpu.env_ptr.active_tc.PC = ADDRESS

# Always run insn_exec
panda.cb_insn_translate(lambda x,y: True)

md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32+ CS_MODE_BIG_ENDIAN) # misp32
@panda.cb_insn_exec
def on_insn(cpu, pc):
    '''
    At each instruction, print capstone disassembly.
    '''
    if pc >= stop_addr:
        print("Finished execution")
        #dump_regs(panda, cpu)
        print("Register t0 contains:", hex(panda.arch.get_reg(cpu, 't0')))
        print("Register t1 contains:", hex(panda.arch.get_reg(cpu,'t1')))
        print("Register t2 contains:", hex(panda.arch.get_reg(cpu,'t2')))
        print("Register t3 contains:", hex(panda.arch.get_reg(cpu,'t3')))
        print("Register t4 contains:", hex(panda.arch.get_reg(cpu,'t4')))
        print("Register t5 contains:", hex(panda.arch.get_reg(cpu,'t5')))
        print("Register t6 contains:", hex(panda.arch.get_reg(cpu,'t6')))
        print("Register t7 contains:", hex(panda.arch.get_reg(cpu,'t7')))
        print("Register t8 contains:", hex(panda.arch.get_reg(cpu,'t8')))
        print("Register t9 contains:", hex(panda.arch.get_reg(cpu,'t9')))
        os._exit(0) # TODO: we need a better way to stop here

    code = panda.virtual_memory_read(cpu, pc, 4)
    for i in md.disasm(code, pc):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        break
    return 0

# Start PANDA running. Callback functions will be called as necessary
panda.run()