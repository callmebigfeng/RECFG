import pefile
from capstone import *
path = "./PE/GifCam.exe"

pe = pefile.PE(path)

for section in pe.sections:
    if section.Name == b'.text\x00\x00\x00':
        start_address = section.PointerToRawData                   #  .text代码起始地址
        end_address = section.PointerToRawData  +  section.SizeOfRawData     # .text代码结束地址
        print("PE文件读取成功！")

        f = open(path, "rb+")
        i = 1
        text = []                 #.text 代码
        ret = []                    #ret位置
        while i<=end_address:
            c = f.read(1)
            if i > start_address :
                text.append(c)
            i = i + 1
        if section.SizeOfRawData == len(text):
            print('代码段存取成功!')
        print(".text前100个字节：")
        print(text[:100])
        print(".text 代码总字节长度： %d" % len(text))
        print('c2出现次数：   %d' % text.count(b'\xc2'))
        print('c3出现次数：   %d' % text.count(b'\xc3'))
        tmp = b''.join(text)
        print(tmp)
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        for i in md.disasm(tmp, 0x00000):
            print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))




