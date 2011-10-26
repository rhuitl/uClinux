#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#define THREADS 4
#define LOOPTIME 1

pthread_t t[THREADS];
int cnt[THREADS];
int loop;

void* thread_code(void* arg) {
  int idx = (int)arg;
  while(loop) {
    cnt[idx]++;
    sched_yield();
  };
  pthread_exit(0);
  return 0;
};

int main(int argc, char* argv[]) {
  int i;
#ifdef FSUTHREADS
  pthread_init();
#endif

  for(i=0;i<THREADS;i++) cnt[i]=0;

  loop=1;
  for(i=0;i<THREADS;i++) pthread_create(&t[i],0,thread_code,(void*)i);

  for(i=0;i<LOOPTIME;i++) sleep(1);

  loop=0;
  for(i=0;i<THREADS;i++) pthread_join(t[i],0);

  for(i=0;i<THREADS;i++) printf("thread %i runs: %i\n",i,cnt[i]/LOOPTIME);

  return 0;
};
