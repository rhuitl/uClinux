#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#define THREADS 4
#define LOOPTIME 5

pthread_t t[THREADS];
int cnt;
int loop;

pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;

void* thread_code(void* arg) {
  while(loop) {
    pthread_mutex_lock(&m);
    cnt++;
    pthread_mutex_unlock(&m);
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

  loop=1;
  for(i=0;i<THREADS;i++) pthread_create(&t[i],0,thread_code,(void*)i);

  for(i=0;i<LOOPTIME;i++) sleep(1);

  loop=0;
  for(i=0;i<THREADS;i++) pthread_join(t[i],0);

  printf("total runs: %i\n",cnt/LOOPTIME);

  return 0;
};
