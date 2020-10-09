from capstone import *
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt


CODE =b"\x8b\xff\x55\x8b\xec\x8b\x45\x08\x66\x8b\x08\x66\x83\xf9\x20\x74\x06\x66\x83\xf9\x09\x75\x04\x40\x40\xeb\xed\x5d\xc2\x04\x00"
md = Cs(CS_ARCH_X86, CS_MODE_32)
for i in range(0,32):
    mnem = []
    disa = md.disasm(CODE[i:], 0x00)           #反汇编
    for i in disa:
        print("0x%x:\t%s\t%s\t%s\t%s" % (i.address, i.mnemonic, i.op_str,i.reg_read,i.bytes))
        mnem.append((i.address, i.mnemonic, i.op_str, i.bytes, i.size))
    print()


    #用字典表示程序流程图
    CFG = dict()  # CFG图
    for i in range(len(mnem)):           # 将上一条指令指向下一条指令
        if i < len(mnem) - 1:
            CFG[mnem[i][0], mnem[i][1], mnem[i][2], str(mnem[i][3])] = [
                (mnem[i + 1][0], mnem[i + 1][1], mnem[i + 1][2], str(mnem[i + 1][3]))]
    for i in range(len(mnem)):
        if mnem[i][1] == 'je'or mnem[i][1] == 'jne':             # 还有其他跳转指令
            if mnem[i][2][:2] == '0x' or (ord(mnem[i][2]) <= ord('9') and ord(mnem[i][2]) >= ord('0')):     # jmp后直接跟地址
                for j in range(len(mnem)):
                    if hex(mnem[j][0]) == mnem[i][2]:
                        CFG[mnem[i][0], mnem[i][1], mnem[i][2], str(mnem[i][3])].append((mnem[j][0], mnem[j][1], mnem[j][2], str(mnem[j][3])))
            else :         # 后面跟寄存器情况，可能跳转到所有地址
                for j in range(len(mnem)):
                    CFG[mnem[i][0], mnem[i][1], mnem[i][2], str(mnem[i][3])].append(
                        (mnem[j][0], mnem[j][1], mnem[j][2], str(mnem[j][3])))
        if mnem[i][1] == 'jmp':
            CFG[mnem[i][0], mnem[i][1], mnem[i][2], str(mnem[i][3])].remove((mnem[i+1][0], mnem[i+1][1], mnem[i+1][2], str(mnem[i+1][3])))
            if mnem[i][2][:2] == '0x' or (ord(mnem[i][2]) <= ord('9') and ord(mnem[i][2]) >= ord('0')):  # jmp后直接跟地址
                for j in range(len(mnem)):
                    if hex(mnem[j][0]) == mnem[i][2] or hex(mnem[j][0])=='0x'+mnem[i][2] :
                        CFG[mnem[i][0], mnem[i][1], mnem[i][2], str(mnem[i][3])].append((mnem[j][0], mnem[j][1], mnem[j][2], str(mnem[j][3])))
            else:        # 后面跟寄存器情况，可能跳转到所有地址
                for j in range(len(mnem)):
                    CFG[mnem[i][0], mnem[i][1], mnem[i][2], str(mnem[i][3])].append((mnem[j][0], mnem[j][1], mnem[j][2], str(mnem[j][3])))

    print(CFG)

    # 程序流程图  字典 ——> 邻接矩阵
    CFG = {k: [v for v in vs] for k, vs in CFG.items()}
    edges = [(a, b) for a, bs in CFG.items() for b in bs]
    tmp = [(a, a) for a in CFG.keys()]
    total_value = []
    for vs in CFG.values():
        total_value += vs
    tmp2 = [(v, v) for v in total_value]

    edges += tmp + tmp2
    edges = list(set(edges))

    df = pd.DataFrame(edges)
    matrix = pd.crosstab(df[0], df[1])
    # print(matrix)

    # 将图的邻接矩阵转化成图
    G = nx.Graph()
    size = len(matrix)
    for i in range(size):
        for j in range(size):
            if i != j and matrix.iloc[i][j] == 1:
                G.add_edge(i, j)

    nx.draw(G)
    plt.show()

    break
