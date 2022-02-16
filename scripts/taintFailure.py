from pandare.arch import PandaArch
from pandare.panda import Panda

panda = Panda("mips", extra_args=["-M", "configurable", "-nographic"], raw_monitor=True)

@panda.cb_after_machine_init
def setup(cpu):
    nonlocal stopaddress
    # Initialize memory and load the first instruction in to initialize the emulation loop
    initializeMemory(panda, "mymem", address=ADDRESS)
    panda.taint_enable()
    
    skippedRegs = ['ZERO', 'SP', 'K0', 'K1', 'AT', 'GP', 'FP', 'RA']
    for (regname, reg) in panda.arch.registers.items():
        if (regname in skippedMipsRegs or not getBit(regBitMask, reg)): continue
            panda.arch.set_reg(cpu, regname, reg)
            print("tainting "+str(reg)+" "+regname)
            panda.taint_label_reg(reg, reg)
            print(panda.taint_get_reg(reg))
            
panda.run()
