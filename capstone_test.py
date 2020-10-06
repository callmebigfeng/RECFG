from capstone import *

CODE = b"\11"
CODE2 =b"\00"
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
count = 0
disa = md.disasm(CODE2, 0x1f)
print(CODE)
for i in disa:
    count += 1
    print("0x%x:\t%s\t%s\t%s" % (i.address, i.mnemonic, i.op_str,i.reg_read))
    print(i.regs_access)
    if len(i.regs_read) > 0:
        for r in i.regs_read :
            print("%s " % i.reg_name(r)),
        print()
    if len(i.groups) > 0:
        for g in i.groups:
            print("%u" %g)
        print()
if count==0:
    print("无指令")
elif count > 1:
    print("转换成多指令")
else :
    print("转换成单指令")

# 问题 机器码既能转换成单指令又能转换成多指令
# code = b'\x04\x10\x40\x00'
# asm = cs_disasm_quick(CS_ARCH_X86, CS_MODE_32,code,0x100,count=1)
# print(asm)