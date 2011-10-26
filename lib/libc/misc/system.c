
#include <stddef.h>
#include <signal.h>
#include <unistd.h>

int
system(command)
char * command;
{
   int wait_val, wait_ret, pid;
   __sighandler_t save_quit, save_int, save_chld;

   if( command == 0 ) return 1;

   save_quit = signal(SIGQUIT, SIG_IGN);
   save_int  = signal(SIGINT,  SIG_IGN);
   save_chld = signal(SIGCHLD, SIG_DFL);

   if( (pid=vfork()) < 0 )
   {
      signal(SIGQUIT, save_quit);
      signal(SIGINT,  save_int);
      signal(SIGCHLD, save_chld);
      return -1;
   }
   if( pid == 0 )
   {
      signal(SIGQUIT, SIG_DFL);
      signal(SIGINT,  SIG_DFL);
      signal(SIGCHLD, SIG_DFL);

      execl("/bin/sh", "sh", "-c", command, (char*)0);
      _exit(127);
   }
   /* Signals are not absolutly guarenteed with vfork */
   signal(SIGQUIT, SIG_IGN);
   signal(SIGINT,  SIG_IGN);
   
   printf("Waiting for child %d\n", pid);

   if (wait4(pid, &wait_val, 0, 0) == -1)
      wait_val = -1;

   signal(SIGQUIT, save_quit);
   signal(SIGINT,  save_int);
   signal(SIGCHLD, save_chld);
   return wait_val;
}
