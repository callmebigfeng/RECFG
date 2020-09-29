from capstone import *

CODE = b"\xc3"
CODE2 =b"\x18\\U\x00\x18\\U\x00\x18\\U\x00\x18\\U\x00\x18\\U\x00\x18"
md = Cs(CS_ARCH_X86, CS_MODE_32)
count = 0
for i in md.disasm(CODE, 0x1000):
    count += 1
    print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
print(CODE)
if count > 1:
    print("转换成多指令")
else :
    print("转换成单指令")
print()
count = 0
for i in md.disasm(CODE2, 0x1000):
    count += 1
    print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
print(CODE2)
if count > 1:
    print("转换成多指令")
else :
    print("转换成单指令")

# 问题 机器码既能转换成单指令又能转换成多指令
