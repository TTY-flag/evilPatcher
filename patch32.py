from pwn import *
import sys
import os
from subprocess import getoutput  # Importing getoutput from subprocess


class patch32_handler:
    def __init__(self, filename, sandboxfile, debugFlag):
        context.arch = 'i386'
        self.filename = filename
        self.ct = self.make_sandbox(sandboxfile)
        self.elf = ELF(filename)
        self.debugFlag = debugFlag

    def pr(self, a, addr):
        log.success(f'{a} ===> {hex(addr)}')

    def run(self):
        if self.debugFlag == 0:
            sys.stdout = open(os.devnull, 'w')
        if self.elf.pie:
            self.patch_pie_elf()
        else:
            self.patch_nopie_elf()
        sys.stdout = sys.__stdout__
        self.elf.save(self.filename + '.patch')
        os.system('chmod +x ' + self.filename + '.patch')
        log.success('input file: ' + self.filename)
        log.success('output file: ' + self.filename + '.patch')
        print("File patched")

    def run_partial(self):
        if self.debugFlag == 0:
            sys.stdout = open(os.devnull, 'w')

        inject_code = asm('endbr32')
        inject_code += asm('push ebp')
        inject_code += self.inject_code_build() + 3 * asm('nop')
        print('============================inject code into .eh_frame============================')
        print(disasm(inject_code))
        eh_frame_section = self.elf.get_section_by_name('.eh_frame').header
        print('.eh_frame.sh_size ===> {}'.format(hex(eh_frame_section.sh_size)))
        print('inject_code.length ===> {}'.format(hex(len(inject_code))))
        eh_frame_addr = eh_frame_section.sh_addr
        self.elf.write(eh_frame_addr, inject_code)
        self.edit_program_table_header()

        sys.stdout = sys.__stdout__

        self.elf.save(self.filename + '.patch')
        os.system('chmod +x ' + self.filename + '.patch')
        log.success('input file: ' + self.filename)
        log.success('output file: ' + self.filename + '.patch')
        print('Patch file successfully!!!')

    def make_sandbox(self, sandboxfile):
        sandboxCt = eval(getoutput(f'seccomp-tools asm {sandboxfile} -a i386 -f inspect'))
        os.system(f'seccomp-tools asm {sandboxfile} -a i386 -f raw | seccomp-tools disasm -a i386 -')
        ct = []
        # Change division to floor division for Python 3
        for i in range(len(sandboxCt) // 8):
            ct.append(u64(sandboxCt[i * 8:i * 8 + 8]))
        ct.reverse()
        ct2 = []
        for i in ct:
            ct2.append(i >> 32)
            ct2.append(i & 0xffffffff)
        return ct2

    def inject_code_build(self):
        inject_code = asm(shellcraft.prctl(38, 1, 0, 0, 0))
        for i in self.ct:
            a = f'push {hex(i)}'
            inject_code += asm(a)
        inject_code += asm(shellcraft.push('esp'))
        inject_code += asm(shellcraft.push(len(self.ct) // 2))  # integer division
        inject_code += asm(shellcraft.prctl(0x16, 2, 'esp'))
        tmp = len(self.ct) * 4 + 0x8
        inject_code += asm(f'add esp, {str(hex(tmp))}')
        return inject_code

    def edit_program_table_header(self):
        program_table_header_start = self.elf.address + self.elf.header.e_phoff
        num_of_program_table_header = self.elf.header.e_phnum
        size_of_program_headers = self.elf.header.e_phentsize
        if self.debugFlag != 0:
            self.pr('program_table_header_start', program_table_header_start)
            self.pr('num_of_program_table_header', num_of_program_table_header)
            self.pr('size_of_program_headers', size_of_program_headers)
        for i in range(num_of_program_table_header):
            p_type = self.elf.get_segment(i).header.p_type
            p_flags = self.elf.get_segment(i).header.p_flags
            if p_type == 'PT_LOAD' and p_flags == 4:
                self.elf.write(program_table_header_start + i * size_of_program_headers + 0x18, p32(5))
                print(f'edit program_table_element[{i}].p_flags ===> r_x')

    def patch_pie_elf(self):
        eh_frame_addr = self.elf.get_section_by_name('.eh_frame').header.sh_addr
        start_offset = self.elf.header.e_entry
        got_start = 0
        try:
            got_start = self.elf.get_section_by_name('.got.plt').header.sh_addr
        except Exception:
            got_start = self.elf.get_section_by_name('.got').header.sh_addr
        offset = self.elf.read(start_offset, 0x40).find(b'\x50\x51\x56')
        offset1 = u32(self.elf.read(start_offset + offset + 3 + 2, 4))  # push DWORD PTR [ebx+offset1]
        offset2 = got_start - eh_frame_addr
        main_addr = u32(self.elf.read((got_start + offset1) & 0xffffffff, 4))
        self.pr('eh_frame_addr', eh_frame_addr)
        self.pr('got_start', got_start)
        self.pr('main_addr', main_addr)
        print('=================================edit _start==================================')
        print('replace _start+' + hex(offset + 3) + '------>change __libc_start_main\'s first parameter: main->.eh_frame')
        print(disasm(self.elf.read(start_offset + offset + 3, 6)))
        s = asm(f'lea ecx,[ebx-{offset2}];push ecx;')
        tmp = self.elf.read(start_offset + offset + 3 + 6, 5)
        main_offset = u32(tmp[1:]) - 1
        tmp = tmp[0:1] + p32(main_offset)
        s += tmp
        print('                ||               ')
        print('                ||               ')
        print('                \/               ')
        print(disasm(s))
        inject_code = self.inject_code_build()
        tail = b'\xe9' + p32(0xffffffff & (main_addr - (eh_frame_addr + len(inject_code) + 5)))
        inject_code += tail
        print('============================inject code into .eh_frame========================')
        print(disasm(inject_code))
        print('.eh_frame.sh_size ===> ' + str(hex(self.elf.get_section_by_name('.eh_frame').header.sh_size)))
        print('inject_code.length ===> ' + str(hex(len(inject_code))))
        self.elf.write(start_offset + offset + 3, s)
        self.elf.write(eh_frame_addr, inject_code)
        self.edit_program_table_header()
    def patch_nopie_elf(self):
        program_base = self.elf.address
        self.pr('program_base', program_base)
        eh_frame_addr = self.elf.get_section_by_name('.eh_frame').header.sh_addr
        start_offset = self.elf.header.e_entry
        offset = self.elf.read(start_offset, 0x40).find(b'\x50\x51\x56')
        main_addr = u32(self.elf.read(start_offset + offset + 5, 4))
        # Maybe compiled by ubuntu16.04
        if offset == -1:
            offset = self.elf.read(start_offset, 0x30).find(b'\xf4') - 10  # hlt
            main_addr = u32(self.elf.read(start_offset + offset + 1, 4))
            self.pr('eh_frame_addr', eh_frame_addr)
            self.pr('start_offset', start_offset)
            self.pr('main_addr', main_addr)
            print('=================================edit _start==================================')
            print(f'replace _start+{hex(offset)} ------> change __libc_start_main\'s first parameter: main->.eh_frame')
            print(disasm(self.elf.read(start_offset + offset, 5)))
            s = asm(f'push {hex(eh_frame_addr)}')
            print('                ||               ')
            print('                ||               ')
            print('                \/               ')
            print(disasm(s))
            self.elf.write(start_offset + offset, s)
        else:
            self.pr('eh_frame_addr', eh_frame_addr)
            self.pr('start_offset', start_offset)
            self.pr('main_addr', main_addr)
            print('=================================edit _start==================================')
            print(f'replace _start+{hex(offset + 3)} ------> change __libc_start_main\'s first parameter: main->.eh_frame')
            print(disasm(self.elf.read(start_offset + offset + 3, 6)))
            s = asm(f'mov eax, {hex(eh_frame_addr)}; nop;')
            print('                ||               ')
            print('                ||               ')
            print('                \/               ')
            print(disasm(s))
            self.elf.write(start_offset + offset + 3, s)

        # ===================sandbox rule==============
        inject_code = self.inject_code_build()
        tail = asm(f'mov eax, {main_addr}; jmp eax;')
        inject_code += tail
        print('==========================inject code into .eh_frame==========================')
        print(disasm(inject_code))
        print('.eh_frame.sh_size ===> ' + str(hex(self.elf.get_section_by_name('.eh_frame').header.sh_size)))
        print('inject_code.length ===> ' + str(hex(len(inject_code))))
            
        self.elf.write(eh_frame_addr, inject_code)
        self.edit_program_table_header()
    

def main():
    if len(sys.argv) < 3:
        print("Usage: {} <filename> <sandboxfile> [<debugFlag>]".format(sys.argv[0]))
        return
    
    filename = sys.argv[1]
    sandboxfile = sys.argv[2]
    debugFlag = int(sys.argv[3]) if len(sys.argv) > 3 else 0

    handler = patch32_handler(filename, sandboxfile, debugFlag)
    handler.run_partial()

if __name__ == '__main__':
    main()