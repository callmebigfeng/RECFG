from capstone import *

CODE = b"\11"
CODE2 =b"\x8b\xff\x55\x8b\xec\x8b\x45\x08\x66\x8b\x08\x66\x83\xf9\x20\x74\x06\x66\x83\xf9\x09\x75\x04\x40\x40\xeb\xed\x5d\xc2\x04\x00"
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
count = 0
for i in range(0,32):
    disa = md.disasm(CODE2[i:], 0x00)
    for i in disa:
         print("0x%x:\t%s\t%s\t%s\t%s" % (i.address, i.mnemonic, i.op_str,i.reg_read,i.bytes))
    print()
    # if len(i.regs_read) > 0:
    #     for r in i.regs_read :
    #         print("%s\t%s" % (i.reg_name(r),i.reg_read))
    #     print()
#     if len(i.groups) > 0:
#         for g in i.groups:
#             print("%u" %g)
#         print()
# if count==0:
#     print("无指令")
# elif count > 1:
#     print("转换成多指令")
# else :
#     print("转换成单指令")

# 问题 机器码既能转换成单指令又能转换成多指令
# code = b'\x04\x10\x40\x00'
# asm = cs_disasm_quick(CS_ARCH_X86, CS_MODE_32,code,0x100,count=1)
# print(asm)