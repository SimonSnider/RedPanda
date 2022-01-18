#!/usr/bin/env python3
import os
import time
import keystone
import capstone

from pandare import Panda
CODE = b"""
INC EAX
ADD EAX, 1
"""

ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
ADDRESS = 0x1000
encoding, count = ks.asm(CODE, ADDRESS)
stop_addr = ADDRESS + len(encoding)
print(encoding)

# Create a machine of type 'configurable' but with just a CPU specified (no peripherals or memory maps)
panda = Panda("x86_64", extra_args=["-M", "configurable", "-nographic", "-d", "in_asm"])


@panda.cb_after_machine_init
def setup(cpu):
    # After our CPU has been created, allocate memory and set starting state

    # Setup a region of memory
    panda.map_memory("mymem", 2 * 1024 * 1024, ADDRESS)

    # Write code into memory
    panda.physical_memory_write(ADDRESS, bytes(encoding))

    # Set starting pc
    panda.arch.set_pc(cpu, ADDRESS)


# Before every instruction, disassemble it with capstone
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

panda.cb_insn_translate(lambda x,y: True)

@panda.cb_after_insn_translate
def translateAll(env, pc):
    return True

@panda.cb_insn_exec
def on_insn(cpu, pc):
    print(pc)
    code = panda.virtual_memory_read(cpu, pc, 12)
    
    for i in md.disasm(code, pc):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        break
    return 0

@panda.cb_after_insn_exec
def getInstValues(cpu, pc):
    print("I AM HERE")
    if pc >= stop_addr:
        print("\nSTOP", hex(stop_addr), "\n")
        panda.arch.dump_regs(cpu)
        panda.end_analysis()
        return 0
    return 0

panda.enable_precise_pc()
# Start PANDA running. Callback functions will be called as necessary
panda.run()