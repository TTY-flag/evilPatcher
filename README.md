# retpatch

One project for awd forked from https://github.com/TTY-flag/evilPatcher
Since the old program haven't been updated in around a year, I optimized it into Python3 and changed some updated python3 expressions.


* Replace commands.getoutput() with subprocess.getoutput() for executing shell commands in Python 3.
* Replace '\x48\x8d\x3d' with b'\x48\x8d\x3d'. In Python 3, strings prefixed with 'b' are considered byte strings. In byte strings, the backslash and following characters (like \x) are not considered escape sequences, they are just part of the byte string.

*Note: The way to call shellcraft may have changed, you need to modify this part of the code based on the specific pwntools version. For instance, shellcraft.prctl might need to be changed to shellcraft.amd64.prctl.*

### 目录说明

**sandboxs文件夹**

​	sandboxs里面存放了禁用的规则，这里根据自己的需要进行修改和选择。

实例（sandbox1.asm）

```
A = sys_number
A >= 0x40000000 ? dead : next
A == execve ? dead : next
A == open ? dead : next
return ALLOW
dead:
return KILL
```

**test文件夹**

​	执行`./complie.sh`生成四个可执行文件可供测试，分别是64/32位和pie开启/关闭的排列组合。

![](picture/1.png)

### 运行脚本命令

​	第一个参数是需要patch的elf文件，第二个参数是沙箱规则文件，可以从sandboxs文件夹里选，假如想输出更多的中间过程可以在最后参数加上一个1。（已自动识别32位和64位）

```
Usage: python evil_patcher.py elfFile sandboxFile
       python evil_patcher.py elfFile sandboxFile 1 (more detailed process message)
```

**运行**

![](picture/2.png)

​	结果输出一个patch过后的文件，文件名为原来文件加上.patch后缀，再改回原来的名字就可以传到靶机上了。

![](picture/3.png)

**验证**

![](picture/4.png)


**更多细节**

https://bbs.pediy.com/thread-273437.htm
