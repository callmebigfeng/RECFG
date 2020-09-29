import pefile
from capstone import *
path = "./PE/GifCam.exe"

pe = pefile.PE(path)


# 找出.text代码节
for section in pe.sections:
    if section.Name == b'.text\x00\x00\x00':
        start_address = section.PointerToRawData                   #  .text代码起始地址
        end_address = section.PointerToRawData  +  section.SizeOfRawData     # .text代码结束地址
        print("PE文件读取成功！")

        #  获取整个.text 代码节
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
        #print('c2出现次数：   %d' % text.count(b'\xc2'))
        #print('c3出现次数：   %d' % text.count(b'\xc3'))
        tmp = b''.join(text)


        #编译整个.text代码节
        #  问题  ：  遇到大量无法反汇编的字节，capstone不报错，自动停止，不知道这段字节长度
        #  问题二  ：  capstone 和IDA　　完全对不上
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        mnem = []     #存储反汇编后地址，指令，操作数，二进制，指令长度
        offset = 0
        print("代码段总长度： %d" %len(text))
        while offset < len(text) :
            for i in md.disasm(tmp[offset:], offset):
                print("0x%x:\t%s\t%s\t%s\t%d" % (i.address, i.mnemonic, i.op_str,i.bytes,i.size))
                mnem.append((i.address,i.mnemonic, i.op_str,i.bytes,i.size))
            offset+=(mnem[-1][0]+mnem[-1][4])

        #生成程序流程图
        CFG = dict()  # CFG图
        for i in range(len(mnem)) :
            if mnem[i][1] == 'jmp' :         #  还有一些 ret，call之类的指令
                if mnem[i][2][:2]==  '0x' :       # 跟着地址直接跳转
                    for  j in range(len(mnem)) :
                        if hex(mnem[j][0])== mnem[i][2]   :
                            CFG[mnem[i][0], mnem[i][1], mnem[i][2], str(mnem[i][3])] = [(           #   jmp ->  address
                            mnem[j][0], mnem[j][1], mnem[j][2], str(mnem[j][3]))]
                else :
                    pass          #  未完成 ：jmp  dword ptr   寄存器/地址   需要取出寄存器的值？
            else:
                if i < len(mnem)-1 :
                    CFG[mnem[i][0],mnem[i][1],mnem[i][2],str(mnem[i][3])] = [(mnem[i+1][0],mnem[i+1][1],mnem[i+1][2],str(mnem[i+1][3]))]    # 将上一条指令指向下一条指令
                if  mnem[i][1] == 'jz' :      #  还有其他跳转指令
                    pass       #  代码同  jmp    将跳转位置添加到key中
        #print(CFG)



