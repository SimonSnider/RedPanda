from modules.generateInstruction import verifierAdapter

def test_setISA():
    verifierAdapter.setISA("mips32")
    assert verifierAdapter.archType == verifierAdapter.CS_MODE_MIPS32 and verifierAdapter.mode == verifierAdapter.CS_MODE_MIPS32

def test_initialize():
    verifierAdapter.setISA("mips32")
    verifierAdapter.initialize()
    assert verifierAdapter.disassembler != -1

def test_disassembleNonsense():
    verifierAdapter.setISA("mips32")
    verifierAdapter.initialize()
    ret = verifierAdapter.isValidInstruction(b"\x00\x00\x00\x00")
    assert not ret

def test_disassembleValidAdd():
    verifierAdapter.setISA("mips32")
    verifierAdapter.initialize()
    ret = verifierAdapter.isValidInstruction(b"\x01\x08\x40\x30")
    assert ret