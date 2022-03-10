
from time import sleep
from pandare import Panda
from capstone import *
from capstone.mips import *
from keystone import *
import os

CODE = b"""
addu $t1, $t2, $t3
j 0
"""

ks = Ks(KS_ARCH_MIPS,KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)

ADDRESS = 0x0000
encoding, count = ks.asm(CODE, ADDRESS)
stop_addr = ADDRESS + len(encoding)

count = 0

md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32+ CS_MODE_BIG_ENDIAN) # misp32

print("capstone output:")
for i in md.disasm(bytes(encoding), ADDRESS):
    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

panda = Panda("mips",
        extra_args=["-M", "configurable", "-nographic"],
        raw_monitor=True) # Allows for a user to ctrl-a + c then type quit if things go wrong

@panda.cb_after_machine_init
def setup(cpu):
    '''
    After our CPU has been created, allocate memory and set starting state
    '''
    print("EXECUTING INITIALIZATION")
    # map 2MB memory for this emulation
    panda.map_memory("mymem", 2 * 1024 * 1024, ADDRESS)

    # Write code into memory
    panda.physical_memory_write(ADDRESS, bytes(encoding))

    # Set up registers
    #cpu.env_ptr.active_tc.gpr[panda.arch.registers['t0']] = 0x10
    panda.arch.set_reg(cpu, 't0', 0x10)

    panda.disable_callback("on_insn2")

    # Set starting_pc
    cpu.env_ptr.active_tc.PC = ADDRESS



@panda.cb_insn_exec
def on_insn1(cpu, pc):
    '''
    At each instruction, print capstone disassembly.
    '''
    global count
    count += 1
    print("on_insn 1")
    print(count)
    if (count >= 4):
        panda.delete_callback("on_insn1")
        panda.enable_callback("on_insn2")
    code = panda.virtual_memory_read(cpu, pc, 4)
    for i in md.disasm(code, pc):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        break
    return 0

@panda.cb_insn_exec
def on_insn2(cpu, pc):
    '''
    At each instruction, print capstone disassembly.
    '''
    global count
    count += 1
    print("on_insn 2")
    print(count)
    if (count >= 10):
        print("Finished execution")
        panda.end_analysis()

    code = panda.virtual_memory_read(cpu, pc, 4)
    for i in md.disasm(code, pc):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        break
    return 0

# Start PANDA running. Callback functions will be called as necessary
panda.cb_insn_translate(lambda x,y: True)
panda.enable_precise_pc()
panda.run()
