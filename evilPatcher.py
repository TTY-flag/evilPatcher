# !/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time : 2021.10.30
# @Author : TTY
# @Email : 1617889365@qq.com

import os, sys
from pwn import *
import traceback
from commands import getoutput
from patch64 import patch64_handler
from patch32 import patch32_handler


def check():
    # Check seccomp-tools
    if not os.path.exists('/usr/local/bin/seccomp-tools') :
        print 'You should intsall seccomp-tools first!'
        print 'Github address : https://github.com/david942j/seccomp-tools'
        exit(0)

    # Check Parameters
    filename = ''
    sandboxFile = ''
    try:
        filename = sys.argv[1]
        sandboxFile = sys.argv[2]
    except:
        print 'Parameter missing...'
        print 'Usage: python evil_patcher.py elfFile sandboxFile'
        print '       python evil_patcher.py elfFile sandboxFile 1 (more detailed process message)'
        exit(0)

    # Check filename and sandboxFile
    if not os.path.exists(filename):
        print 'ELF file not exists!'
        exit(0)
    if not os.path.exists(sandboxFile):
        print 'Sandbox file not exists!'
        exit(0)


def main():
    check()
    filename = sys.argv[1]
    sandboxFile = sys.argv[2]
    debugFlag = 0
    try:
        tmp = sys.argv[3]
        debugFlag = 1
    except:
        pass
    arch = ELF(filename).arch
    if arch == 'i386':
        patch32_handler(filename, sandboxFile, debugFlag).run()
    elif arch == 'amd64':
        patch64_handler(filename, sandboxFile, debugFlag).run()
    else:
        print arch + ' is not supported!!! Only i386 and amd64!!!'

    
if __name__ == '__main__':
    try:
        main()
    except Exception:
        traceback.print_exc()
        print 'If you find any bugs, please contact me with e-mail : 1617889365@qq.com'
