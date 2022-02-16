from pandare.arch import PandaArch
from pandare.panda import Panda

panda = Panda("mips", extra_args=["-M", "configurable", "-nographic"], raw_monitor=True)

@panda.cb_after_machine_init
def setup(cpu):
    panda.map_memory("mymem", 2*1024*1024, 0)
    jump_instr = b"\x08\x00\x00\x00"
    panda.physical_memory_write(0, bytes(jump_instr))
    cpu.env_ptr.active_tc.PC = 0
    
    panda.taint_enable()
    
@panda.cb_insn_exec
def taint(cpu, pc):
    skippedRegs = ['ZERO', 'SP', 'K0', 'K1', 'AT', 'GP', 'FP', 'RA']
    for (regname, reg) in panda.arch.registers.items():
        if (regname in skippedRegs): continue
        panda.arch.set_reg(cpu, regname, reg)
        print("tainting "+str(reg)+" "+regname)
        panda.taint_label_reg(reg, reg)
        print(panda.taint_get_reg(reg))
            
panda.run()
