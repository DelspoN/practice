# Side-channel Attack

## Key words

- side channel attack
- pin tool

## Pin Tool

핀툴은 인텔에서 만든 Dynamic Binary Instrumentation 툴입니다. 처리 속도가 빠르지만 인텔 아키텍처가 아닌 바이너리에는 사용이 불가능합니다. (`https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool`에서 다운로드할 수 있습니다.)

다운로드 받은 디렉토리를 살펴보면 `source/tools/SimpleExamples` 디렉토리에 다양한 예제 파일들이 존재합니다.

```
total 372
-rw-r----- 1 11270804 12453  1918 Aug 27 20:44 bsr_bsf_app.cpp
-rw-r----- 1 11270804 12453  2228 Aug 27 20:44 bsr_bsf_asm.asm
-rw-r----- 1 11270804 12453  2230 Aug 27 20:44 bsr_bsf_asm.s
-rw-r----- 1 11270804 12453  6095 Aug 27 20:44 bsr_bsf.cpp
-rwxr-x--- 1 11270804 12453   228 Aug 27 21:11 bsr_bsf.reference
-rwxr-x--- 1 11270804 12453 11851 Aug 27 21:11 callgraph.py
-rw-r----- 1 11270804 12453  7607 Aug 27 20:44 calltrace.cpp
-rw-r----- 1 11270804 12453  8723 Aug 27 20:44 catmix.cpp
-rw-r----- 1 11270804 12453  8143 Aug 27 20:44 coco.cpp
-rw-r----- 1 11270804 12453 11475 Aug 27 20:44 dcache.cpp
-rw-r----- 1 11270804 12453 12898 Aug 27 20:44 dcache.H
-rw-r----- 1 11270804 12453  9378 Aug 27 20:44 edgcnt.cpp
-rw-r----- 1 11270804 12453  3330 Aug 27 20:44 emuload.cpp
-rw-r----- 1 11270804 12453  8960 Aug 27 20:44 extmix.cpp
-rw-r----- 1 11270804 12453 14793 Aug 27 20:44 fence.cpp
-rwxr-x--- 1 11270804 12453 13499 Aug 27 21:11 flowgraph.py
-rw-r----- 1 11270804 12453    57 Aug 27 21:11 get_source_app.cpp
-rw-r----- 1 11270804 12453  6333 Aug 27 20:44 get_source_location.cpp
-rw-r----- 1 11270804 12453  3604 Aug 27 20:44 icount.cpp
-rw-r----- 1 11270804 12453  9064 Aug 27 20:44 ilenmix.cpp
-rw-r----- 1 11270804 12453  5668 Aug 27 20:44 inscount2_mt.cpp
-rw-r----- 1 11270804 12453  5094 Aug 27 20:44 inscount2_vregs.cpp
-rw-r----- 1 11270804 12453  7850 Aug 27 20:44 inscount_and_check_tls.cpp
-rw-r----- 1 11270804 12453  6079 Aug 27 20:44 jumpmix.cpp
-rw-r----- 1 11270804 12453 10519 Aug 27 20:44 ldstmix.cpp
-rw-r----- 1 11270804 12453   676 Aug 27 21:11 makefile
-rw-r----- 1 11270804 12453  8398 Aug 27 21:11 makefile.rules
-rw-r----- 1 11270804 12453  5042 Aug 27 20:44 malloctrace.cpp
-rwxr-x--- 1 11270804 12453   675 Aug 27 21:11 objdump-routine.csh
-rw-r----- 1 11270804 12453 14836 Aug 27 20:44 opcodemix.cpp
-rw-r----- 1 11270804 12453  1759 Aug 27 20:44 oper_imm_app.cpp
-rw-r----- 1 11270804 12453  2032 Aug 27 20:44 oper_imm_asm.asm
-rw-r----- 1 11270804 12453  2029 Aug 27 20:44 oper_imm_asm.s
-rw-r----- 1 11270804 12453  6509 Aug 27 20:44 oper-imm.cpp
-rwxr-x--- 1 11270804 12453  1043 Aug 27 21:11 oper-imm.ia32.reference
-rwxr-x--- 1 11270804 12453  1051 Aug 27 21:11 oper-imm.intel64.reference
-rw-r----- 1 11270804 12453  7141 Aug 27 20:44 pinatrace.cpp
-rw-r----- 1 11270804 12453  8359 Aug 27 20:44 regmix.cpp
-rw-r----- 1 11270804 12453  2436 Aug 27 20:44 regval_app.cpp
-rw-r----- 1 11270804 12453  4981 Aug 27 20:44 regval.cpp
-rw-r----- 1 11270804 12453 12788 Aug 27 20:44 topopcode.cpp
-rw-r----- 1 11270804 12453  7441 Aug 27 20:44 toprtn.cpp
-rw-r----- 1 11270804 12453  5692 Aug 27 20:44 trace.cpp
-rw-r----- 1 11270804 12453  4656 Aug 27 20:44 xed-print.cpp
-rw-r----- 1 11270804 12453  3447 Aug 27 20:44 xed-use.cpp
```

자신에게 필요한 예제를 골라서 잘 활용하면 됩니다. 이 중에서 실행되는 인스트럭터의 갯수를 카운트해주는 `icount.cpp`를 사용해보도록 하겠습니다.

```c
#include "pin.H"
#include <iostream>

UINT64 ins_count = 0;

INT32 Usage()
{
    cerr <<
        "This tool prints out the number of dynamic instructions executed to stderr.\n"
        "\n";

    cerr << KNOB_BASE::StringKnobSummary();

    cerr << endl;

    return -1;
}

VOID docount()
{
    ins_count++;
}

VOID Instruction(INS ins, VOID *v)
{
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_END);
}

VOID Fini(INT32 code, VOID *v)
{
    cerr <<  "Count [" << ins_count << "]" << endl;
    
}

int main(int argc, char *argv[])
{
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();
    
    return 0;
}
```

위는 `icount.cpp`의 코드입니다. 자신의 상황에 맞게 조금씩 수정하여 컴파일하면 됩니다.

```
$ make					# 64비트 컴파일
$ make TARGET=ia32		# 32비트 컴파일
```

컴파일 환경은  `source/tools/MyPinTool` 디렉토리에 미리 세팅되어 있습니다. `icount.cpp`코드를 `MyPinTool.cpp`로 복사한 후, make 해줍니다.(옵션을 통해 바이너리에 맞게 컴파일 해줍니다.)

```
$ ./pin -t source/tools/MyPinTool/obj-ia32/MyPinTool.so -- ../ass01
a
Wrong
Count [46258]
```

컴파일된 라이브러리를 활용하여 위처럼 실행할 수 있습니다.

## 문제 풀이1

ass01은 어셈블리로 짜여진 32비트 바이너리입니다. 패스워드를 알아맞추는 리버싱 문제입니다. ~~코드를 하나하나 분석하기는 너무 귀찮기 때문에~~ 사이드 채널 공격을 통해 ass01의 패스워드를 알아내겠습니다. 패스워드 입력 후 프로세스가 작동되는 시간으로도 공격이 가능은 합니다만 해보면 알겠지만 너무 다양한 값이 나오기 때문에 이를 식별하려면 수많은 데이터가 필요합니다. 반면, 핀툴을 통해 바이너리에서 실행되는 인스트럭터를 카운트하면 비교적으로 정확한 공격이 가능합니다.

공격 가능성을 확인하기 위해 아래의 코드를 이용하여 테스트 해보겠습니다.

```python
from pwn import *
import string

frequency = {}
password = ""

for i in range(len(string.printable)):
	p = process(["../../pin/pin", "-t", "./MyPinTool.so", "--", "./ass01"])
	p.sendline(password + string.printable[i])
	response = p.recvuntil("Count [")
	count = p.recvuntil("]")[:-1]
	print "[{}] ".format(string.printable[i]) + str(count)
	p.close()
```

아래의 실행 결과를 통해, 입력값이 i,j,k와 n,o,p,q일 때 실행되는 인스트럭터의 갯수는 일정함을 확인할 수있습니다. 반면 l의 경우 다른 값이 나옵니다. 즉 i,j,k,n,o,p,q는 패스워드가 아니고 l이 패스워드라는 것을 의미합니다.

```
[i] 46258
[j] 46258
[k] 46258
[l] 45952
[m] 46196
[n] 46196
[o] 46196
[p] 46196
[q] 46196
[r] 46196
[s] 46196
```

이는 패스워드가 한바이트씩 비교되는 방식이기 때문입니다. 옳지 않은 패스워드 값이 입력되면 똑같은 로직으로 들어가기 때문에 실행되는 인스트럭터의 갯수가 같고, 옳은 패스워드 값이 들어가면 실행되는 인스터럭터의 갯수가 다릅니다. 이 원리를 이용하여 패스워드를 맞추면 됩니다. 아래는 제가 작성한 브루트포싱 코드입니다.

```python
from pwn import *
import string

frequency = {}
password = ""
end_flag = 0
string.printable = string.printable.replace("\t\n\r\x0b\x0c", "")

while True:
	for i in range(len(string.printable)):
		p = process(["../../pin/pin", "-t", "./MyPinTool.so", "--", "./ass01"])
		p.sendline(password + string.printable[i])
		response = p.recvuntil("Count [")
		if "Wrong" not in response:
			password += string.printable[i]
			print "=================="
			print password
                        print "=================="
			exit()
		count = p.recvuntil("]")[:-1]
		if count not in frequency:
			frequency[count] = [1, string.printable[i]]
		else:
			frequency[count][0] += 1
		#print "[{}] ".format(string.printable[i]) + str(count)
		p.close()

	for k in frequency.keys():
		if frequency[k][0] == 1:
			password += frequency[k][1]
			frequency.clear()
			break
	print password
```

## Result

```
$ python ex_ass01.py
==================
l3ss_1s_m0r3!
==================
$ ./ass01
l3ss_1s_m0r3!
Key: l3ss_1s_m0r3!
```



## 문제풀이2

핀툴을 공부한 후 때마침 2017 화이트햇 콘테스트에 핀툴을 이용하는 리버싱 문제가 나왔습니다.

```
$ ./crackme 
PASSCODE : aaaaa
FAILED
```
바이너리를 실행해보면 패스코드를 맞추는 문제라는 것을 알 수 있습니다. 64비트 핀툴 라이브러리 코드를 컴파일한 후, 문제1의 코드를 조금만 수정하면 문제를 해결할 수 있습니다.

```python
from pwn import *
import string

frequency = {}
password = ""
end_flag = 0
string.printable = string.printable.replace("\t\n\r\x0b\x0c", "")

while True:
	for i in range(len(string.printable)):
		p = process(["../../pin/pin", "-t", "./MyPinTool_64.so", "--", "./crackme"])
		p.recv()
		p.sendline(password + string.printable[i])
		response = p.recvuntil("Count [")
		if "FAILED" not in response:
			password += string.printable[i]
			print "=================="
			print password
                        print "=================="
			exit()
		count = p.recvuntil("]")[:-1]
		if count not in frequency:
			frequency[count] = [1, string.printable[i]]
		else:
			frequency[count][0] += 1
		#print "[{}] ".format(string.printable[i]) + str(count)
		p.close()

	for k in frequency.keys():
		if frequency[k][0] == 1:
			password += frequency[k][1]
			frequency.clear()
			break
	print password
```

## Result

```
$ python ex_crackme.py 
==================
H4PPyW1THC0nCTF!
==================
```

