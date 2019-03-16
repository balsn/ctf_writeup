# Pragyan CTF 2019

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20190308-pragyanctf/) of this writeup.**


 - [Pragyan CTF 2019](#pragyan-ctf-2019)
   - [Forensics](#forensics)
     - [Welcome](#welcome)
   - [Web](#web)
     - [Mandatory PHP](#mandatory-php)
   - [Binary](#binary)


## Forensics

### Welcome
* welcome.jpeg:
![](https://i.imgur.com/HbwpkgB.png)
Use binwalk to extract `d.zip`, unzip it we got `a.zip` and `secret.bmp`.
* secret.bmp:
```
okdq09i39jkc-evw.;[23760o-keqayiuhxnk42092jokdspb;gf&^IFG{:DSV>{>#Fqe'plverH%^rw[.b]w[evweA#km7687/*98<M)}?>_{":}>{>~?!@{%pb;gf&^IFG{:DSV>{>#Fqe'plverH%^rw[.b]w[evweA#km7687/*98<M)}?>_{":}>{>~?!?@{%&{:keqay^IFG{wfdoiajwlnh[8-7.=p54.b=dGhlIHBhc3N3b3JkIGlzOiBoMzExMF90aDNyMyE==
```
* `echo dGhlIHBhc3N3b3JkIGlzOiBoMzExMF90aDNyMyE== | base64 -D`
    * the password is: h3110_th3r3!

Unzip a.zip, got a.png.
* a.png:
![](https://i.imgur.com/EnrLKWY.png)
* stegosolve
![](https://i.imgur.com/y7yLxjv.png)



## Web

### Mandatory PHP

> bookgin

```php
<?php
include 'flag.php';
highlight_file('index.php');
$a = $_GET["val1"];
$b = $_GET["val2"];
$c = $_GET["val3"];
$d = $_GET["val4"];
if(preg_match('/[^A-Za-z]/', $a))
die('oh my gawd...');
$a=hash("sha256",$a);
$a=(log10($a**(0.5)))**2;
if($c>0&&$d>0&&$d>$c&&$a==$c*$c+$d*$d)
$s1="true";
else
    die("Bye...");
if($s1==="true")
    echo $flag1;
for($i=1;$i<=10;$i++){
    if($b==urldecode($b))
        die('duck');
    else
        $b=urldecode($b);
}    
if($b==="WoAHh!")
$s2="true";
else
    die('oops..');
if($s2==="true")
    echo $flag2;
die('end...');
?> 
```

The payload:
```
http://159.89.166.12:14000/?val1=jM&val3=1e-309&val4=1e-308&val2=WoAHh%2525252525252525252521

# pctf{b3_c4r3fu1_w1th_pHp_f31145}
```

Explanation:

- val2: It need one more `%25` because Apache/PHP will decode it first before passing into php engine.
- val1: Because `sha256("jM")=01bd8c1....`, when casting to integer, it becomes `1`.
- val3, val4: We abuse floating-point "precision".

```php
php > var_dump(1e-308*1e-308);
float(0)
```
## Binary
