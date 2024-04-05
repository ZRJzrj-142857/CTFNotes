初级ROP

'a'*num+p64(0x....).decode("uniform_escape")||b'a'*num+p64(0x....)

ret2text

原理

ret2text 即控制程序执行程序本身已有的的代码 (即， .text 段中的代码) 。其实，这种攻击方法是一种笼统的描述。我们控制执行程序已有的代码的时候也可以控制程序执行好几段不相邻的程序已有的代码(也就是 gadgets)，这就是我们所要说的ROP。

这时，我们需要知道对应返回的代码的位置。当然程序也可能会开启某些保护，我们需要想办法去绕过这些保护。

操作

main()中get()显然存在栈溢出漏洞，寻找system("/bin/sh").
据此shell sendline 终interactive。




ret2shellcode

原理

ret2shellcode，即控制程序执行 shellcode 代码。shellcode 指的是用于完成某个功能的汇编代码，常见的功能主要是获取目标系统的 shell。通常情况下，shellcode 需要我们自行编写，即此时我们需要自行向内存中填充一些可执行的代码。

在栈溢出的基础上，要想执行 shellcode，需要对应的 binary 在运行时，shellcode 所在的区域具有可执行权限。

需要注意的是，在新版内核当中引入了较为激进的保护策略，程序中通常不再默认有同时具有可写与可执行的段，这使得传统的 ret2shellcode 手法不再能直接完成利用。

操作

寻找有同时具有可写与可执行的段，sendline

ret2syscall

原理

ret2syscall，即控制程序执行系统调用，获取 shell。

操作

系统调用号，即 eax 应该为 0xb
第一个参数，即 ebx 应该指向 /bin/sh 的地址，其实执行 sh 的地址也可以。
第二个参数，即 ecx 应该为 0
第三个参数，即 edx 应该为 0

控制这些寄存器的值--only 'pop|ret'    
ex: 0x...... result:pop eax;ret\\控制eax的地址
payload='a'*溢出+控制eax的地址+操作函数地址+int0x80截断


ret2libc

原理

ret2libc 即控制函数的执行 libc 中的函数，通常是返回至某个函数的 plt 处或者函数的具体位置(即函数对应的 got表项的内容)。一般情况下，我们会选择执行 system("/bin/sh")，故而此时我们需要知道 system 函数的地址。（无"/bin/sh"&&NX enable）

操作

payload1 = b"a" * offset + puts_plt + addr_start + puts_got  
  
puts_real_addr = u32(p.recv()[0:4])  #接收puts的真实地址  
libc_addr = puts_real_addr - libc.sym['puts']  #算基地址
system_addr = libc_addr + libc.sym["system"]
binsh_addr = libc_addr + next(libc.search(b"/bin/sh"))
payload2 = b'a' * 112 + p32(system_addr) + b"aaaa" + p32(binsh_add）