from pandare import Panda
from capstone import *
from capstone.mips import *
from keystone import *
from enum import Enum
from random import choice, randint
import os




instruction = "sub $t1, $t2, $t3"
print(instruction)
CODE = b"""
sub $t1, $t2, $t3


"""

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
    panda.arch.set_reg(cpu, 't2', 0xFEEEEEEE)
    panda.arch.set_reg(cpu, 't3', 0x8BBBBBBB)
    panda.arch.set_reg(cpu, 't4', 0x00)
    panda.arch.set_reg(cpu, 't5', 0x00)
    panda.arch.set_reg(cpu, 't6', 0x00)
    panda.arch.set_reg(cpu, 't7', 0x00)
    panda.arch.set_reg(cpu, 't8', 0x00)
    panda.arch.set_reg(cpu, 't9', 0x00)

    # Set starting_pc
    cpu.env_ptr.active_tc.PC = ADDRESS


@panda.cb_before_handle_exception
def bhe(cpu, index):
    pc = cpu.panda_guest_pc
    print(f"handled exception index {index:#x} at pc: {pc:#x}")
    panda.arch.set_pc(cpu, pc+4)
    from time import sleep
    sleep(1)
    return -1


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
        panda.end_analysis() # TODO: we need a better way to stop here

    code = panda.virtual_memory_read(cpu, pc, 4)
    for i in md.disasm(code, pc):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        break
    return 0

# Start PANDA running. Callback functions will be called as necessary
panda.enable_precise_pc()
panda.run()