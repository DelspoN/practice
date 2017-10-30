# Side-channel Attack

## Key words

- side channel attack
- pin tool

## Pin Tool 사용법

`source/tools/SimpleExamples` 디렉토리에 다양한 예제 파일들이 존재합니다.

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

자신에게 필요한 예제를 골라서 잘 활용하면 됩니다. 이 중에서 `icount.cpp`를 사용해보도록 하겠습니다.

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

 위는 `icount.cpp`의 코드입니다. 바이너리에서 실행되는 instructor를 카운트해줍니다. 위 코드를 컴파일해보겠습니다.

```
$ make					# 64비트 컴파일
$ make TARGET=ia32		# 32비트 컴파일
```

 `source/tools/MyPinTool` 디렉토리에 컴파일 환경이 미리 세팅되어 있습니다. `icount.cpp`코드를 `MyPinTool.cpp`로 복사한 후, make 해줍니다.(옵션을 통해 바이너리에 맞게 컴파일 해줍니다.)

```
# ./pin -t source/tools/MyPinTool/obj-ia32/MyPinTool.so -- ../ass01
a
Wrong
Count [46258]
```

컴파일된 라이브러리를 활용하여 위처럼 실행할 수 있습니다.

## Solution - ass01

ass01은 어셈블리로 짜여진 바이너리입니다. 코드를 분석하기는 너무 복잡하기 때문에 사이드 채널 공격을 통해 ass01의 패스워드를 알아내겠습니다. 프로세스가 작동하는 시간으로도 공격이 가능은 합니다. 하지만 데이터를 많이 쌓아야 하고, 해보면 알겠지만 너무 다양한 값이 나오기 때문에 이는 불안정한 방법입니다. 그래서 핀툴을 통해 바이너리에서 실행되는 인스트럭터를 카운트하여 공격했습니다.

패스워드가 한바이트씩 비교되는 방식이기 때문에 한바이트씩 브루트포싱하여 패스워드가 옳지 않으면 똑같은 로직으로 들어가면서 실행되는 인스트럭터의 갯수가 같을 것입니다. 유니크한 값을 찾아서 패스워드를 맞추면 됩니다. 

```
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

