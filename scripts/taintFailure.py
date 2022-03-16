from pandare.arch import PandaArch
from pandare.panda import Panda

panda = Panda("mips", extra_args=["-M", "configurable", "-nographic"], raw_monitor=True)

@panda.cb_after_machine_init
def setup(cpu):
    panda.map_memory("mymem", 2*1024*1024, 0)
    nop = b"\x00\x00\x00\x00"
    add = b"\x01\x4b\x48\x20"
    panda.physical_memory_write(0, bytes(add))
    panda.physical_memory_write(4, bytes(add))
    panda.physical_memory_write(8, bytes(add))
    panda.physical_memory_write(12, bytes(add))
    cpu.env_ptr.active_tc.PC = 0
    panda.taint_enable()


@panda.cb_insn_exec
def randomRegState(cpu, pc):
    skippedRegs = ['ZERO', 'SP', 'K0', 'K1', 'AT', 'GP', 'FP', 'RA']
    for (regname, reg) in panda.arch.registers.items():
        # if (regname in skippedRegs): continue
        panda.arch.set_reg(cpu, regname, reg)
        print("tainting reg "+str(reg)+" ("+regname+")")
        panda.taint_label_reg(reg, reg)
        print(panda.taint_get_reg(reg))


@panda.cb_after_insn_exec
def end(cpu, pc):
    if pc > 4:
        # for (regname, reg) in panda.arch.registers.items():
        #     print(panda.taint_get_reg(reg))
        panda.end_analysis()
    return 0


# Tell panda to translate every instruction
@panda.cb_after_insn_translate
def translateAll(env, pc):
    return True


@panda.cb_insn_translate
def translateAllAgain(env, pc):
    return True

panda.run()
