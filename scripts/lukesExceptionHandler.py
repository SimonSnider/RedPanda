#!/usr/bin/env python3

from pandare import Panda
from capstone import *
from capstone.mips import *
from keystone import *
import os

CODE = b"""
syscall

break


li $1, 0x0
sw $0, 0($1)


li $1, 0x1
li $2, 0x1
sub $2, $2, $1
divu $1, $2

li $1, 1

.loop: 
    j .loop
"""

ks = Ks(KS_ARCH_MIPS,KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)

ADDRESS = 0x1000
encoding, count = ks.asm(CODE, ADDRESS)
stop_addr = ADDRESS + len(encoding)


md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32+ CS_MODE_BIG_ENDIAN) # misp32

print("capstone output:")
for i in md.disasm(bytes(encoding), ADDRESS):
    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

panda = Panda("mips",
        extra_args=["-M", "configurable", "-nographic", '-d', 'in_asm'],
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
    panda.arch.set_reg(cpu, 't0', 0x10)

    # Set starting_pc
    cpu.env_ptr.active_tc.PC = ADDRESS


@panda.cb_before_handle_exception
def bhe(cpu, index):
    pc = cpu.panda_guest_pc
    print(f"handle exception pc: {pc:#x}")
    panda.arch.set_pc(cpu, pc+4)
    from time import sleep
    sleep(1)
    return -1

# Start PANDA running. Callback functions will be called as necessary
panda.enable_precise_pc()
panda.run()
