from capstone import *

CODE = b"\xff\xf1\x00\x00\x10\x03\x00\x00\x00\xff\xff\x00"
md = Cs(CS_ARCH_X86,CS_MODE_32)
print(md.disasm(CODE,0x1000))
count = 0
for i in md.disasm_lite(CODE,0x1000) :
    count+=1
    print("0x%x:\t%s\t%s"%(i.address,i.mnemonic,i.op_str))
    if count>1:
        print("无法转换指令！")
        break
# asdaskjdlas
#q
# lst = md.disasm(CODE,0x1000,count=1)
# print(type(lst))
# for i in lst:
#     print(i.mnemonic)
#

#问题 机器码既能转换成单指令又能转换成多指令  ————这个方法不合适