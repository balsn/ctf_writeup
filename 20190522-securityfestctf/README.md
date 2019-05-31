# Security Fest 2019

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20190522-securityfestctf/) of this writeup.**


 - [Security Fest 2019](#security-fest-2019)
   - [Crypto](#crypto)
     - [cactus](#cactus)
       - [First Guess](#first-guess)
       - [Final Guess](#final-guess)
   - [Misc](#misc)
     - [Darkwebmessageboard](#darkwebmessageboard)
     - [Locksmith](#locksmith)


## Crypto

### cactus
This is a weird challange :no_mouth:
here's the chal script (with some modification):


```python=

import random
from flag import FLAG

class Oracle:

    def __init__(self, secret, bits=512):
        self.secret = secret
        self.bits = bits
        self.range = 2*self.bits

    def sample(self, w):
        r = random.randint(0, 2^self.range)
        idx = range(self.bits)
        random.shuffle(idx)
        e = sum(1<<i for i in idx[:w])
        return self.secret*r+e

assert (type(FLAG) is int)
o = Oracle(FLAG)
f = open('output.txt', 'w')
for i in range(100):
    f.write(str(o.sample(10)) + '\n')
f.close()

```

The point is, r is calculated as `random.randint(0, 2^self.range)`, while e is calculated as `sum(1<<i for i in idx[:w])`, the scale of these two differ quite a lot, so we can simply bruteforce `r`

#### First Guess
Note that the scale of `e` is 512 bits, and it only contains 10 non-zero bits, so it is quite possible that `output / r` still contains the flag header `sctf`. Simply bruteforce this and we can get a broken flag
`sctf�wh@0ps_th4t_w4s�t_sxp0nent1ati0n}`

#### Final Guess
The rest is quite the same:
1. guess a small snippet of flag
2. bruteforce `r` to find possible one
3. fix the broken flag

flag : `sctf{wh00ps_th4t_w4snt_3xp0nent1ati0n}`



## Misc

### Darkwebmessageboard

In html source:

` <!-- | Dark Web Message Board | DEVELOPED BY K1tsCr3w | Open source at Kits-AB | -->`

then I serached github and found this repo: https://github.com/kits-ab/the-dark-message-board

and there is a encrypted message in the `http://darkboard-01.pwn.beer:5001/boards/1`:

`rW+fOddzrtdP7ufLj9KTQa9W8T9JhEj7a2AITFA4a2UbeEAtV/ocxB/t4ikLCMsThUXXWz+UFnyXzgLgD9RM+2toOvWRiJPBM2ASjobT+bLLi31F2M3jPfqYK1L9NCSMcmpVGs+OZZhzJmTbfHLdUcDzDwdZcjKcGbwEGlL6Z7+CbHD7RvoJk7Ft3wvFZ7PWIUHPneVAsAglOalJQCyWKtkksy9oUdDfCL9yvLDV4H4HoXGfQwUbLJL4Qx4hXHh3fHDoplTqYdkhi/5E4l6HO0Qh/jmkNLuwUyhcZVnFMet1vK07ePAuu7kkMe6iZ8FNtmluFlLnrlQXrE74Z2vHbQ==
`

the production key is in the git log: https://github.com/kits-ab/the-dark-message-board/commit/d95b029a044491a954b909a280ebebcf6e357ef4#diff-ea209ce78604d811cf3f3771a0f89ea2

with this log message: `from some file that reminds me of the song 'here i am something like a hurricane'`

after searching `here i am something like a hurricane` on google, I got this `here i am. Rock you like a hurricane`.

so we need to brute force the password from `rockyou.txt`.

we use this [tool](https://github.com/bwall/pemcracker.git) to crack the password.

Result: `Password is falloutboy for test.pem`

the plaintext of the encrypted message is `Bank url: http://bankofsweden-01.pwn.beer`

but 80 port of this website is closed.

so I use nmap to scan all ports of this site, then I found 5000 port is open.

http://bankofsweden-01.pwn.beer:5000

It is a bank website.

In register step, there is a parameter `is_active`, if we set to `1`, then we will become authenticated user.

After login, I found there is a LFI vulnerability in export function.

So I download the `app.py` and got the flag: `SECFEST{h4ck3r5_60nn4_h4ck_4nd_b4nk3r5_60nn4_cr4ck}`

### Locksmith
This challange starts with 9 random number $v_1$ to $v_9$, it also provides us 9 kinds of operation, each of them will add 9 positive number to each of $v_i$, the goal is to make all $v_i$ to a given constant.
The point is, we can send multiple request at one time, which can massively reduce the overhead of IO. The rest is just a simply linear algebra.
