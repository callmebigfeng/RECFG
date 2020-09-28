import os, string, shutil, re
import pefile  ##记得import pefile

PEfile_Path = "./PE/3dframes.exe"

pe = pefile.PE(PEfile_Path)
print("PE可选头结构：")
print("代码区块起始虚拟地址：" + hex(pe.OPTIONAL_HEADER.BaseOfCode))
print("代码区块大小：" + hex(pe.OPTIONAL_HEADER.SizeOfCode))
print("节表结构：")
print("代码区块起始虚拟地址：" + hex(pe.sections[0].VirtualAddress))         #
print("代码区块大小：" + hex(pe.sections[0].SizeOfRawData))                #

#  测试PE头 和 节表头 的偏移地址