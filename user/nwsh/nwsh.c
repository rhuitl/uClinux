/*  nwsh: the new shell
 *  Copyright 1999/2000 Mooneer Salem (mooneer@earthlink.net)
 *  Some code taken from the book "Developing Linux Applications"
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pwd.h>

#define MAX_COMMAND_LEN 250     /* max length of a single command 
                                   string */
#define JOB_STATUS_FORMAT "[%d] %-22s %.40s\n"

enum redirectionType { REDIRECT_INPUT, REDIRECT_OVERWRITE, REDIRECT_APPEND };

struct jobSet {
    struct job * head;      /* head of list of running jobs */
    struct job * fg;        /* current foreground job */
};

struct redirectionSpecifier {
    enum redirectionType type;  /* type of redirection */
    int fd;                 /* file descriptor being redirected */
    char * filename;        /* file to redirect fd to */
};

struct childProgram {
    pid_t pid;              /* 0 if exited */
    char ** argv;           /* program name and arguments */
    int numRedirections;    /* elements in redirection array */
    struct redirectionSpecifier * redirections;  /* I/O redirections */
    glob_t globResult;      /* result of parameter globbing */
    int freeGlob;           /* should we globfree(&globResult)? */
    int isStopped;          /* is the program currently running? */
};

struct job {
    int jobId;              /* job number */
    int numProgs;           /* total number of programs in job */
    int runningProgs;       /* number of programs running */
    char * text;            /* name of job */
    char * cmdBuf;          /* buffer various argv's point into */
    pid_t pgrp;             /* process group ID for the job */
    struct childProgram * progs; /* array of programs in job */
    struct job * next;      /* to track background commands */
    int stoppedProgs;       /* number of programs alive, but stopped */
};

/* Added in case readline.h and history.h aren't available */
#ifdef HAVE_LIBREADLINE
extern char *readline (char *);
extern void add_history (char *);
#endif

void freeJob(struct job * cmd) {
    int i;

    for (i = 0; i < cmd->numProgs; i++) {
        free(cmd->progs[i].argv);
        if (cmd->progs[i].redirections) free(cmd->progs[i].redirections);
        if (cmd->progs[i].freeGlob) globfree(&cmd->progs[i].globResult);
    }
    free(cmd->progs);
    if (cmd->text) free(cmd->text);
    free(cmd->cmdBuf);
}

char *input_line = NULL;

int getCommand(FILE * source, char * command) {
    char *tmpuser, *prompt;

    if (source == stdin) {
        if (!geteuid()) {
           prompt = "# ";
        } else {
           prompt = "$ ";
        }
        fflush(stdout);
    }

#ifdef HAVE_LIBREADLINE
    if (source == stdin) {
       input_line = readline(prompt);
       add_history(input_line);
       sprintf(command, "%s", input_line);
       free(input_line);
    } else {
#else
        printf(prompt);
        fflush(stdout);
#endif
        if (!fgets(command, MAX_COMMAND_LEN, source)) {
            if (source == stdin) printf("\n");
            return 1;
        } 
        /* remove trailing newline */
        command[strlen(command) - 1] = '\0';
#ifdef HAVE_LIBREADLINE
    }
#endif

    return 0;
}

void globLastArgument(struct childProgram * prog, int * argcPtr,
                        int * argcAllocedPtr) {
    int argc = *argcPtr;
    int argcAlloced = *argcAllocedPtr;
    int rc;
    int flags;
    int i;
    char * src, * dst;

    if (argc > 1) {             /* cmd->globResult is already initialized */
        flags = GLOB_APPEND;
        i = prog->globResult.gl_pathc;
    } else {
        prog->freeGlob = 1;
        flags = 0;
        i = 0;
    }

    rc = glob(prog->argv[argc - 1], flags, NULL, &prog->globResult);
    if (rc == GLOB_NOSPACE) {
        fprintf(stderr, "out of space during glob operation\n");
        return;
    } else if (rc == GLOB_NOMATCH || 
               (!rc && (prog->globResult.gl_pathc - i) == 1 && 
                !strcmp(prog->argv[argc - 1], 
                        prog->globResult.gl_pathv[i]))) {
        /* we need to remove whatever \ quoting is still present */
        src = dst = prog->argv[argc - 1];
        while (*src) {
            if (*src != '\\') *dst++ = *src;
            src++;
        }
        *dst = '\0';
    } else if (!rc) {
        argcAlloced += (prog->globResult.gl_pathc - i);
        prog->argv = realloc(prog->argv, argcAlloced * sizeof(*prog->argv));
        memcpy(prog->argv + (argc - 1), prog->globResult.gl_pathv + i,
                sizeof(*(prog->argv)) * (prog->globResult.gl_pathc - i));
        argc += (prog->globResult.gl_pathc - i - 1);
    }

    *argcAllocedPtr = argcAlloced;
    *argcPtr = argc;
}

/* Return cmd->numProgs as 0 if no command is present (e.g. an empty
   line). If a valid command is found, commandPtr is set to point to
   the beginning of the next command (if the original command had more 
   then one job associated with it) or NULL if no more commands are 
   present. */
int parseCommand(char ** commandPtr, struct job * job, int * isBg) {
    char * command;
    char * returnCommand = NULL;
    char * src, * buf, * chptr;
    int argc = 0;
    int done = 0;
    int argvAlloced;
    int i;
    char quote = '\0';  
    int count;
    struct childProgram * prog;

    /* skip leading white space */
    while (**commandPtr && isspace(**commandPtr)) (*commandPtr)++;

    /* this handles empty lines */
    if (!**commandPtr) {
        job->numProgs = 0;
        *commandPtr = NULL;
        return 0;
    }

    *isBg = 0;
    job->numProgs = 1;
    job->progs = malloc(sizeof(*job->progs));

    /* We set the argv elements to point inside of this string. The 
       memory is freed by freeJob(). 

       Getting clean memory relieves us of the task of NULL 
       terminating things and makes the rest of this look a bit 
       cleaner (though it is, admittedly, a tad less efficient) */
    job->cmdBuf = command = calloc(1, strlen(*commandPtr) + 1);
    job->text = NULL;

    prog = job->progs;
    prog->numRedirections = 0;
    prog->redirections = NULL;
    prog->freeGlob = 0;
    prog->isStopped = 0;

    argvAlloced = 5;
    prog->argv = malloc(sizeof(*prog->argv) * argvAlloced);
    prog->argv[0] = job->cmdBuf;

    buf = command;
    src = *commandPtr;
    while (*src && !done) {
        if (quote == *src) {
            quote = '\0';
        } else if (quote) {
            if (*src == '\\') {
                src++;
                if (!*src) {
                    fprintf(stderr, "character expected after \\\n");
                    freeJob(job);
                    return 1;
                }

                /* in shell, "\'" should yield \' */
                if (*src != quote) *buf++ = '\\';
            } else if (*src == '*' || *src == '?' || *src == '[' || 
                       *src == ']')
                *buf++ = '\\';
            *buf++ = *src;
        } else if (isspace(*src)) {
            if (*prog->argv[argc]) {
                buf++, argc++;
                /* +1 here leaves room for the NULL which ends argv */
                if ((argc + 1) == argvAlloced) {
                    argvAlloced += 5;
                    prog->argv = realloc(prog->argv, 
				    sizeof(*prog->argv) * argvAlloced);
                }
                prog->argv[argc] = buf;

                globLastArgument(prog, &argc, &argvAlloced);
            }
        } else switch (*src) {
          case '"':
          case '\'':
            quote = *src;
            break;

          case '#':                         /* comment */
            done = 1;
            break;

          case '>':                         /* redirections */
          case '<':
            i = prog->numRedirections++;
            prog->redirections = realloc(prog->redirections, 
                                sizeof(*prog->redirections) * (i + 1));

            prog->redirections[i].fd = -1;
            if (buf != prog->argv[argc]) {
                /* the stuff before this character may be the file number 
                   being redirected */
                prog->redirections[i].fd = strtol(prog->argv[argc], &chptr, 10);

                if (*chptr && *prog->argv[argc]) {
                    buf++, argc++;
                    globLastArgument(prog, &argc, &argvAlloced);
                }
            }

            if (prog->redirections[i].fd == -1) {
                if (*src == '>')
                    prog->redirections[i].fd = 1;
                else
                    prog->redirections[i].fd = 0;
            }

            if (*src++ == '>') {
                if (*src == '>')
                    prog->redirections[i].type = REDIRECT_APPEND, src++;
                else 
                    prog->redirections[i].type = REDIRECT_OVERWRITE;
            } else {
                prog->redirections[i].type = REDIRECT_INPUT;
            }

            /* This isn't POSIX sh compliant. Oh well. */
            chptr = src;
            while (isspace(*chptr)) chptr++;

            if (!*chptr) {
                fprintf(stderr, "file name expected after %c\n", *src);
                freeJob(job);
                return 1;
            }

            prog->redirections[i].filename = buf;
            while (*chptr && !isspace(*chptr)) 
                *buf++ = *chptr++;

            src = chptr - 1;                /* we src++ later */
            prog->argv[argc] = ++buf;
            break;

          case '|':                         /* pipe */
            /* finish this command */
            if (*prog->argv[argc]) argc++;
            if (!argc) {
                fprintf(stderr, "empty command in pipe\n");
                freeJob(job);
                return 1;
            }
            prog->argv[argc] = NULL;

            /* and start the next */
            job->numProgs++;
            job->progs = realloc(job->progs, 
                                 sizeof(*job->progs) * job->numProgs);
            prog = job->progs + (job->numProgs - 1);
            prog->numRedirections = 0;
            prog->redirections = NULL;
            prog->freeGlob = 0;
            argc = 0;

            argvAlloced = 5;
            prog->argv = malloc(sizeof(*prog->argv) * argvAlloced);
            prog->argv[0] = ++buf;

            src++;
            while (*src && isspace(*src)) src++;

            if (!*src) {
                fprintf(stderr, "empty command in pipe\n");
                return 1;
            }
            src--;              /* we'll ++ it at the end of the loop */

            break;

          case '&':                         /* background */
            *isBg = 1;
          case ';':                         /* multiple commands */
            done = 1;
            returnCommand = *commandPtr + (src - *commandPtr) + 1;
            break;

          case '\\':
            src++;
            if (!*src) {
                freeJob(job);
                fprintf(stderr, "character expected after \\\n");
                return 1;
            }
            if (*src == '*' || *src == '[' || *src == ']' || *src == '?')
                *buf++ = '\\';
            /* fallthrough */
          default:
            *buf++ = *src;
        }

        src++;
    }

    if (*prog->argv[argc]) {
        argc++;
        globLastArgument(prog, &argc, &argvAlloced);
    }
    if (!argc) {
        freeJob(job);
        return 0;
    }
    prog->argv[argc] = NULL;

    if (!returnCommand) {
        job->text = malloc(strlen(*commandPtr) + 1);
        strcpy(job->text, *commandPtr);
    } else {
        /* This leaves any trailing spaces, which is a bit sloppy */

        count = returnCommand - *commandPtr;
        job->text = malloc(count + 1);
        strncpy(job->text, *commandPtr, count);
        job->text[count] = '\0';
    }

    *commandPtr = returnCommand;

    return 0;
}

int setupRedirections(struct childProgram * prog) {
    int i;
    int openfd;
    int mode = 0;
    struct redirectionSpecifier * redir = prog->redirections;

    for (i = 0; i < prog->numRedirections; i++, redir++) {
        switch (redir->type) {
          case REDIRECT_INPUT:
            mode = O_RDONLY;
            break;
          case REDIRECT_OVERWRITE:
            mode = O_RDWR | O_CREAT | O_TRUNC; 
            break;
          case REDIRECT_APPEND:
            mode = O_RDWR | O_CREAT | O_APPEND;
            break;
        }

        openfd = open(redir->filename, mode, 0666);
        if (openfd < 0) {
            /* this could get lost if stderr has been redirected, but
               bash and ash both lose it as well (though zsh doesn't!) */
            fprintf(stderr, "error opening %s: %s\n", redir->filename,
                        strerror(errno));
            return 1;
        }

        if (openfd != redir->fd) {
            dup2(openfd, redir->fd);
            close(openfd);
        }
    }

    return 0;
}

int runCommand(struct job newJob, struct jobSet * jobList, 
               int inBg) {
    struct job * job;
    char * newdir, * buf;
    int i, len;
    int nextin, nextout;
    int pipefds[2];             /* pipefd[0] is for reading */
    char * statusString;
    int jobNum;
    struct passwd *userPass;

    /* handle built-ins here -- we don't fork() so we can't background
       these very easily */
    if (!strcmp(newJob.progs[0].argv[0], "exit")) {
        /* this should return a real exit code */
        exit(0);
    } else if (!strcmp(newJob.progs[0].argv[0], "pwd")) {
        len = 50;
        buf = malloc(len);
        while (!getcwd(buf, len)) {
            len += 50;
            buf = realloc(buf, len);
        }
        printf("%s\n", buf);
        free(buf);
        return 0;
    } else if (!strcmp(newJob.progs[0].argv[0], "cd")) {
        if (!newJob.progs[0].argv[1] == 1) { 
            newdir = getenv("HOME");
        } else {
            if (*newJob.progs[0].argv[1] == '~') {
               if (!(*(newJob.progs[0].argv[1] + 1))) {
                  newdir = getenv("HOME");
               } else {
                  userPass = getpwnam((newJob.progs[0].argv[1] + 1));
                  newdir = userPass->pw_dir;
               }
            } else {
               newdir = newJob.progs[0].argv[1];
            }
        }
        if (chdir(newdir)) 
            printf("failed to change current directory: %s\n",
                    strerror(errno));
        return 0;
    } else if (!strcmp(newJob.progs[0].argv[0], "jobs")) {
        for (job = jobList->head; job; job = job->next) {
            if (job->runningProgs == job->stoppedProgs)
                statusString = "Stopped";
            else
                statusString = "Running";

            printf(JOB_STATUS_FORMAT, job->jobId, statusString,
                    job->text);
        }
        return 0;
    } else if (!strcmp(newJob.progs[0].argv[0], "fg") ||
               !strcmp(newJob.progs[0].argv[0], "bg")) {
        if (!newJob.progs[0].argv[1] || newJob.progs[0].argv[2]) {
            fprintf(stderr, "%s: exactly one argument is expected\n",
                    newJob.progs[0].argv[0]);
            return 1;
        }

        if (sscanf(newJob.progs[0].argv[1], "%%%d", &jobNum) != 1) {
            fprintf(stderr, "%s: bad argument '%s'\n",
                    newJob.progs[0].argv[0], newJob.progs[0].argv[1]);
            return 1;
        }

        for (job = jobList->head; job; job = job->next) 
            if (job->jobId == jobNum) break;

        if (!job) {
            fprintf(stderr, "%s: unknown job %d\n",
                    newJob.progs[0].argv[0], jobNum);
            return 1;
        }

        if (*newJob.progs[0].argv[0] == 'f') {
            /* Make this job the foreground job */

	  /*            if (tcsetpgrp(0, job->pgrp))
			perror("tcsetpgrp");*/
            jobList->fg = job;
        }

        /* Restart the processes in the job */
        for (i = 0; i < job->numProgs; i++) 
            job->progs[i].isStopped = 0;

        kill(-job->pgrp, SIGCONT);

        job->stoppedProgs = 0;
        
        return 0;
    }

    nextin = 0, nextout = 1;
    for (i = 0; i < newJob.numProgs; i++) {
        if ((i + 1) < newJob.numProgs) {
            pipe(pipefds);
            nextout = pipefds[1];
        } else {
            nextout = 1;
        }

#ifdef __uClinux__
        if (!(newJob.progs[i].pid = vfork())) {
#else
        if (!(newJob.progs[i].pid = fork())) {
#endif
            signal(SIGTTOU, SIG_DFL);

            if (nextin != 0) {
                dup2(nextin, 0);
                close(nextin);
            }

            if (nextout != 1) {
                dup2(nextout, 1);
                close(nextout);
            }

            /* explicit redirections override pipes */
            setupRedirections(newJob.progs + i);

            execvp(newJob.progs[i].argv[0], newJob.progs[i].argv);
            fprintf(stderr, "exec() of %s failed: %s\n", 
                    newJob.progs[i].argv[0], 
                    strerror(errno));
            exit(1);
        }

        /* put our child in the process group whose leader is the
           first process in this pipe */
        setpgid(newJob.progs[i].pid, newJob.progs[0].pid);

        if (nextin != 0) close(nextin);
        if (nextout != 1) close(nextout);

        /* If there isn't another process, nextin is garbage 
           but it doesn't matter */
        nextin = pipefds[0];
    }

    newJob.pgrp = newJob.progs[0].pid;

    /* find the ID for the job to use */
    newJob.jobId = 1;
    for (job = jobList->head; job; job = job->next)
        if (job->jobId >= newJob.jobId)
            newJob.jobId = job->jobId + 1;

    /* add the job to the list of running jobs */
    if (!jobList->head) {
        job = jobList->head = malloc(sizeof(*job));
    } else {
        for (job = jobList->head; job->next; job = job->next);
        job->next = malloc(sizeof(*job));
        job = job->next;
    }

    *job = newJob;
    job->next = NULL;
    job->runningProgs = job->numProgs;
    job->stoppedProgs = 0;

    if (inBg) {
        /* we don't wait for background jobs to return -- append it 
           to the list of backgrounded jobs and leave it alone */

        printf("[%d] %d\n", job->jobId, 
               newJob.progs[newJob.numProgs - 1].pid);
    } else {
        jobList->fg = job;

        /* move the new process group into the foreground */
	/*        
        if (tcsetpgrp(0, newJob.pgrp))
	perror("tcsetpgrp");*/
    }

    return 0;
}

void removeJob(struct jobSet * jobList, struct job * job) {
    struct job * prevJob;

    freeJob(job); 
    if (job == jobList->head) {
        jobList->head = job->next;
    } else {
        prevJob = jobList->head;
        while (prevJob->next != job) prevJob = prevJob->next;
        prevJob->next = job->next;
    }

    free(job);
}

/* Checks to see if any background processes have exited -- if they 
   have, figure out why and see if a job has completed */
void checkJobs(struct jobSet * jobList) {
    struct job * job;
    pid_t childpid;
    int status;
    int progNum = 0;
   
    while ((childpid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        for (job = jobList->head; job; job = job->next) {
            progNum = 0;
            while (progNum < job->numProgs && 
                        job->progs[progNum].pid != childpid)
                progNum++;
            if (progNum < job->numProgs) break;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            /* child exited */
            job->runningProgs--;
            job->progs[progNum].pid = 0;

            if (!job->runningProgs) {
                printf(JOB_STATUS_FORMAT, job->jobId, "Done", job->text);
                removeJob(jobList, job);
            }
        } else {
            /* child stopped */
            job->stoppedProgs++;
            job->progs[progNum].isStopped = 1;

            if (job->stoppedProgs == job->numProgs) {
                printf(JOB_STATUS_FORMAT, job->jobId, "Stopped", job->text);
            }
        }
    }

    if (childpid == -1 && errno != ECHILD)
        perror("waitpid");
}

int main(int argc, char ** argv) {
    char command[MAX_COMMAND_LEN + 1];
    char * nextCommand = NULL;
    struct jobSet jobList = { NULL, NULL };
    struct job newJob;
    FILE * input = stdin;
    int i;
    int status;
    int inBg;

    if (argc > 2) {
        fprintf(stderr, "unexpected arguments; usage: ladsh1 "
                        "<commands>\n");
        exit(1);
    } else if (argc == 2) {
        input = fopen(argv[1], "r");
        if (!input) {
            perror("fopen");
            exit(1);
        }
    }

    /* don't pay any attention to this signal; it just confuses 
       things and isn't really meant for shells anyway */
    signal(SIGTTOU, SIG_IGN);
    
    while (1) {
        if (!jobList.fg) {
            /* no job is in the foreground */

            /* see if any background processes have exited */
            checkJobs(&jobList);

            if (!nextCommand) {
                if (getCommand(input, command)) break;
                nextCommand = command;
            }

            if (!parseCommand(&nextCommand, &newJob, &inBg) &&
                              newJob.numProgs) {
                runCommand(newJob, &jobList, inBg);
            }
        } else {
            /* a job is running in the foreground; wait for it */
            i = 0;
            while (!jobList.fg->progs[i].pid ||
                   jobList.fg->progs[i].isStopped) i++;

            waitpid(jobList.fg->progs[i].pid, &status, WUNTRACED);

            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                /* the child exited */
                jobList.fg->runningProgs--;
                jobList.fg->progs[i].pid = 0;
            
                if (!jobList.fg->runningProgs) {
                    /* child exited */

                    removeJob(&jobList, jobList.fg);
                    jobList.fg = NULL;

                    /* move the shell to the foreground */
		    /*       if (tcsetpgrp(0, getpid()))
			     perror("tcsetpgrp");*/
                }
            } else {
                /* the child was stopped */
                jobList.fg->stoppedProgs++;
                jobList.fg->progs[i].isStopped = 1;

                if (jobList.fg->stoppedProgs == jobList.fg->runningProgs) {
                    printf("\n" JOB_STATUS_FORMAT, jobList.fg->jobId, 
                                "Stopped", jobList.fg->text);
                    jobList.fg = NULL;
                }
            }

            if (!jobList.fg) {
                /* move the shell to the foreground */
	      /*if (tcsetpgrp(0, getpid()))
		perror("tcsetpgrp");*/
            }
        }
    }

    return 0;
}





