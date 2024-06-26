整数溢出

在C语言中，整数的基本数据类型分为短整型(short)，整型(int)，长整型(long)，这三个数据类型还分为有符号和无符号，每种数据类型都有各自的大小范围

上界溢出

上界溢出有两种情况，一种是 0x7fff + 1， 另一种是 0xffff + 1。

因为计算机底层指令是不区分有符号和无符号的，数据都是以二进制形式存在(编译器的层面才对有符号和无符号进行区分，产生不同的汇编指令)。

所以 add 0x7fff, 1 == 0x8000，这种上界溢出对无符号整型就没有影响，但是在有符号短整型中，0x7fff 表示的是 32767，但是 0x8000 表示的是 -32768，用数学表达式来表示就是在有符号短整型中 32767+1 == -32768。

第二种情况是 add 0xffff, 1，这种情况需要考虑的是第一个操作数。

比如上面的有符号型加法的汇编代码是 add eax, 1，因为 eax=0xffff，所以 add eax, 1 == 0x10000，但是无符号的汇编代码是对内存进行加法运算 add word ptr [rbp - 0x1a], 1 == 0x0000。

在有符号的加法中，虽然 eax 的结果为 0x10000，但是只把 ax=0x0000 的值储存到了内存中，从结果看和无符号是一样的。

再从数字层面看看这种溢出的结果，在有符号短整型中，0xffff==-1，-1 + 1 == 0，从有符号看这种计算没问题。

但是在无符号短整型中，0xffff == 65535, 65535 + 1 == 0。

下界溢出¶
下届溢出的道理和上界溢出一样，在汇编代码中，只是把 add 替换成了 sub。

一样也是有两种情况：

第一种是 sub 0x0000, 1 == 0xffff，对于有符号来说 0 - 1 == -1 没问题，但是对于无符号来说就成了 0 - 1 == 65535。

第二种是 sub 0x8000, 1 == 0x7fff，对于无符号来说是 32768 - 1 == 32767 是正确的，但是对于有符号来说就变成了 -32768 - 1 = 32767。

类型混淆

在WebKit核心中，类型混淆是一个安全问题，它发生在对象的类型标签被错误地修改时，这可能导致运行时的不一致性，从而可能导致安全漏洞。