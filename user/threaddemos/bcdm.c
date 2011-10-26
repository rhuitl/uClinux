#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#define THREADS 4
#define LOOPTIME 1

pthread_t t_master;
pthread_t t_slave[THREADS];
int master_cnt;
int slave_cnt[THREADS];
int loop;
int done;

pthread_cond_t c = PTHREAD_COND_INITIALIZER;
pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;

void* master_thread_code(void* arg) {
  while(loop) {

    pthread_mutex_lock(&m);
    done=0;
    pthread_cond_broadcast(&c);
    pthread_mutex_unlock(&m);

    pthread_mutex_lock(&m);
    while(done != ((1<<THREADS)-1)) pthread_cond_wait(&c,&m);   
    pthread_mutex_unlock(&m);

    master_cnt++;

  };
  pthread_exit(0);
  return 0;
};

void* slave_thread_code(void* arg) {
  int idx = (int)arg;
  int flag = 1<<idx;
  while(loop) {

    pthread_mutex_lock(&m);
    while(done&flag) pthread_cond_wait(&c,&m);    
    pthread_mutex_unlock(&m);

    pthread_mutex_lock(&m);
    done|=flag;
    pthread_cond_broadcast(&c);
    pthread_mutex_unlock(&m);    

    slave_cnt[idx]++;

  };
  pthread_exit(0);
  return 0;
};

int main(int argc, char* argv[]) {
  int i;

#ifdef FSUTHREADS
  pthread_init();
#endif

  master_cnt=0;
  for(i=0;i<THREADS;i++) slave_cnt[i]=0;

  loop=1;
  for(i=0;i<THREADS;i++) pthread_create(&t_slave[i],0,slave_thread_code,(void*)i);
  pthread_create(&t_master,0,master_thread_code,0);

  for(i=0;i<LOOPTIME;i++) sleep(1);
  loop=0;

  printf("master thread runs: %i\n",master_cnt/LOOPTIME);
  for(i=0;i<THREADS;i++) printf("slave thread %i runs: %i\n",i,slave_cnt[i]/LOOPTIME);

#ifdef FSUTHREADS
  printf("done ... terminate with kill command!\n");
#else
  printf("done ... terminate with kill command or CRTL+C\n");
#endif

  /* this won't work because of dead-lock :-( */
  pthread_join(t_master,0);
  for(i=0;i<THREADS;i++) pthread_join(t_slave[i],0);

  return 0;
};
