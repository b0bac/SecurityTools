
import re
import sys
import binascii
import capstone
from collections import defaultdict


def load_system_call_maps(operating_system, arch_mode):
        system_call_dictionary = {
            # Linux系统调用 (x86_64)
            "linux_x64": {
                0x00: "sys_read",
                0x01: "sys_write",
                0x02: "sys_open",
                0x03: "sys_close",
                0x2a: "sys_socket",
                0x21: "sys_connect",
                0x22: "sys_accept",
                0x29: "sys_sendto",
                0x2b: "sys_recvfrom",
                0x3b: "sys_execve",
                0x3c: "sys_exit"
            },
            # Linux系统调用 (x86)
            "linux_x86": {
                0x03: "sys_read",
                0x04: "sys_write",
                0x05: "sys_open",
                0x06: "sys_close",
                0x66: "sys_socketcall",
                0xb0: "sys_execve",
                0xfc: "sys_exit"
            },
            # Windows系统调用 (x64)
            "windows_x64": {
                0x002A: "NtCreateFile",
                0x003A: "NtOpenFile",
                0x0016: "NtReadFile",
                0x0017: "NtWriteFile",
                0x000C: "NtClose",
                0x00AD: "NtCreateThreadEx",
                0x0108: "NtAllocateVirtualMemory",
                0x011C: "NtProtectVirtualMemory"
            },
            # Windows系统调用 (x86)
            "windows_x86": {
                0x002A: "NtCreateFile",
                0x003A: "NtOpenFile",
                0x0016: "NtReadFile",
                0x0017: "NtWriteFile",
                0x000C: "NtClose",
                0x00A2: "NtCreateThread",
                0x0018: "NtAllocateVirtualMemory",
                0x0050: "NtProtectVirtualMemory"
            }
        }
        index_key = "%s_%s" % (str(operating_system), str(arch_mode))
        return system_call_dictionary[index_key]


def disassemble(shellcode, operating_system, index_string, arch_type=capstone.CS_ARCH_X86, arch_mode=capstone.CS_MODE_64, base_addr=0x10000000):
    statistics = defaultdict(int)
    system_call_maps = load_system_call_maps(operating_system, index_string)
    operator = capstone.Cs(arch_type, arch_mode)
    disassembly = []
    system_calls = []
    try:
        for item in operator.disasm(shellcode, base_addr):
            disassembly.append({
                "address": item.address,
                "mnemonic": item.mnemonic,
                "op_str": item.op_str,
                "bytes": binascii.hexlify(item.bytes).decode()
            })
    except Exception as e:
        raise RuntimeError(f"反汇编失败: {str(e)}")
    statistics["instruction_count"] = len(disassembly)
    control_flow_instructions = {"jmp", "je", "jne", "jz", "jnz", "call", "ret", "cmp", "test"}
    memory_instructions = {"mov", "lea", "push", "pop", "add", "sub", "and", "or", "xor", "inc", "dec"}
    for item in disassembly:
        if item["mnemonic"] in control_flow_instructions:
            statistics["control_flow_instructions"] += 1
        if item["mnemonic"] in memory_instructions:
            statistics["memory_instructions"] += 1
    # 系统调用检测
    system_call_instructions = {"syscall", "int", "int 0x80", "int 0x2e"}
    for i, item in enumerate(disassembly):
        if item["mnemonic"] in system_call_instructions or (item["mnemonic"] == "int" and "0x80" in item["op_str"]):
            # 尝试获取系统调用号
            system_call_num = None
            # 检查前一条指令是否设置系统调用号
            if i > 0 and disassembly[i - 1]["mnemonic"] in ["mov", "xor"]:
                prev_op = disassembly[i - 1]["op_str"]
                if arch_mode == capstone.CS_MODE_64 and "rax" in prev_op:
                    try:
                        system_call_num = int(prev_op.split(",")[-1].strip(), 16)
                    except:
                        pass
                elif arch_mode == capstone.CS_MODE_32 and "eax" in prev_op:
                    try:
                        system_call_num = int(prev_op.split(",")[-1].strip(), 16)
                    except:
                        pass

            call_name = system_call_maps.get(system_call_num, "未知系统调用[%s]" % str(system_call_num))
            system_calls.append({
                "address": item["address"],
                "instruction": f"{item['mnemonic']} {item['op_str']}",
                "syscall_num": system_call_num,
                "name": call_name
            })
            statistics["system_calls"] += 1
    print("[+] ShellCode详细信息:")
    print("  [+] 指令数量: " + str(statistics['instruction_count']))
    print("  [+] 控制流指令: " + str(statistics['control_flow_instructions']))
    print("  [+] 内存操作指令: " + str(statistics['memory_instructions']))
    print("  [+] 系统调用数量: " + str(statistics['system_calls']))
    print("  [+] 汇编代码:")
    for item in disassembly:
        print((f"    0x{item['address']:x}:\t{item['mnemonic']}\t{item['op_str']}"))


def get_string_from_shellcode(shellcode) -> None:
    ascii_strings: list = []
    current_str: str = ""
    index_number: int = 1
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    url_pattern = re.compile(r"https?://[^\s]+|www\.[^\s]+\.[^\s]+")
    for byte in shellcode:
        if 0x20 <= byte <= 0x7E:
            current_str += chr(byte)
        else:
            if len(current_str) >= 4:
                ascii_strings.append(current_str)
            current_str = ""
    if len(current_str) >= 4:
        ascii_strings.append(current_str)
    for strings in list(set(ascii_strings)):
        if re.search(ip_pattern, strings):
            print("  [*] 字符串%s  %s [发现IP地址]" % (str(index_number), str(strings)))
        elif re.search(url_pattern, strings):
            print("  [*] 字符串%s  %s [发现URL]" % (str(index_number), str(strings)))
        else:
            print("  [*] 字符串%s  %s" % (str(index_number), str(strings)))
        index_number += 1
    return None


if __name__ == "__main__":
    arch_type = None
    arch_mode = None
    index_string = None
    operating_system = sys.argv[1]
    if operating_system not in ["windows", "linux", "macos"]:
        print("[-] 未知操作系统")
        exit(0)
    elif operating_system not in ["windows", "linux"]:
        print("[-] 暂不支持MacOS的ShellCode分析")
    arch_string = sys.argv[2]
    if arch_string in ["x86_64", "amd64", "x64"]:
        arch_type = capstone.CS_ARCH_X86
        arch_mode = capstone.CS_MODE_64
        index_string = "x64"
    elif arch_string in ["x86", "amd32", "286", "386", "486", "586", "686"]:
        arch_type = capstone.CS_ARCH_X86
        arch_mode = capstone.CS_MODE_32
        index_string = "x86"
    elif arch_string in ["arm", "arm64"]:
        arch_type = capstone.CS_ARCH_ARM if arch_string == "arm" else capstone.CS_ARCH_ARM64
        arch_mode = capstone.CS_MODE_ARM
        print("暂不支持ARM架构的ShellCode分析")
        exit(0)
    elif arch_string  == "arm_thumb":
        arch_type = capstone.CS_ARCH_ARM
        arch_mode = capstone.CS_MODE_THUMB
        print("暂不支持ARM架构的ShellCode分析")
        exit(0)
    else:
        print("暂不支持未知架构的ShellCode分析")
        exit(0)
    shellcode_string = sys.argv[3]
    print("#################################################################")
    print("ShellCode 分析 V1.0")
    print("Author: b0b@c")
    print("当前仅支持分析字符串，提取URL 以及反汇编功能")
    print("#################################################################")
    print("[+] 操作系统版本: %s" % str(operating_system))
    print("[+] 体系架构: %s" % str(arch_string))
    shellcode_string = binascii.unhexlify(shellcode_string)
    print("[+] ShellCode长度: %s 字节" % str(len(shellcode_string)))
    print("[+] 关键字符串:")
    get_string_from_shellcode(shellcode_string)
    disassemble(shellcode_string, operating_system, index_string, arch_type, arch_mode)


