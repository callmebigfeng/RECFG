from capstone import *

CODE = b"\11"
CODE2 =b"\x18\\U\x00\x18\\U\x00\x18\\U\x00\x18\\U\x00\x18\\U\x00\x18"
md = Cs(CS_ARCH_X86, CS_MODE_32)
count = 0
disa = md.disasm(CODE, 0x1000)
print(CODE)
for i in disa:
    count += 1
    print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
if count==0:
    print("无指令")
elif count > 1:
    print("转换成多指令")
else :
    print("转换成单指令")

# 问题 机器码既能转换成单指令又能转换成多指令
