/* Minimal shell C source - (c) 1999, Spock (Oscar Portela Arjona) */

#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#define chkerr(c,msg) if (c < 0) {perror("ERROR (" msg ")"); exit(-1);}
#define mvdesc(d1,d2) {close(d1); dup(d2); close(d2);}
#define redir(n,f)    {close(n); chkerr(open(fv[n],f,0666),"open");}
#define size(v,s,u,n) {(v = realloc(v,s))[u] = n;}
#define l2            l1[vc]
#define l3            l2[p[0]]

int main(void) {
  char ***l1 = NULL, *fv[3] ,dir[50] ,c;
  int vc, bg, id, p[2], d;

  signal(SIGINT, SIG_IGN);	signal(SIGQUIT,SIG_IGN);

  while (1) {
    getcwd(dir,50); write(1,dir,strlen(dir)); write(1," $ ",d = bg = 3);
    for (;bg; fv[bg] = NULL) realloc(fv[--bg],0); size(l1,4,0,NULL);
    for (vc = p[0] = 0; read(0,&c,1) && (c != '\n');)
    switch(c) {
     case '<': d = 0; break;
     case '>': d = 1; break;
     case '|': if (l2) {vc++; p[0] = 0;} d = 3; break;
     case '&': if (d < 3) d++; else bg = 1; break;
     case ' ': if (d < 3) {if (fv[d]) d = 3;} else if (l2 && l3) p[0]++; break;
     default:  if (d < 3) {if (!fv[d]) size(fv[d],1,0,'\0');
                  size(fv[d],(id=strlen(fv[d]))+2,id,c); fv[d][id+1]='\0';}
               else { if (!l2) {size(l1,vc*4+8,vc+1,NULL); size(l2,4,0,NULL);}
                  if (!l3) {size(l2,p[0]*4+8,p[0]+1,NULL); size(l3,1,0,'\0');}
                  size(l3,(id=strlen(l3))+2,id,c); l3[id+1] = '\0';}}

    for (vc = 0; l2;) {
      if (!vc) d = dup(0);
      if (l1[vc+1]) chkerr(pipe(p),"pipe");
      if (!strcmp(l2[0],"exit")) exit(0);
      if (!strcmp(l2[0],"cd")) {if (chdir(l2[1]) < 0) chdir(getenv("HOME"));}
      else {if (!(id = fork())) {
	       if (fv[0] && !vc) redir(0,O_RDONLY) else mvdesc(0,d);
	       if (fv[1]) redir(1,O_CREAT|O_WRONLY|O_TRUNC);
	       if (fv[2]) redir(2,O_CREAT|O_WRONLY|O_TRUNC);
	       if (l1[vc+1]) {mvdesc(1,p[1]); close(p[0]);}
	       if (!bg) {signal(SIGINT,SIG_DFL); signal(SIGQUIT,SIG_DFL);}
	       chkerr(execvp(l2[0],l2),"exec");}
            if (!l1[vc+1] && !bg) while (wait(NULL) != id);}
      for (id = 0; l2[id]; realloc(l2[id++],0)); realloc(l2,0);
      close(d); if (l1[++vc]) {d = dup(p[0]); close(p[0]); close(p[1]);}}}}
