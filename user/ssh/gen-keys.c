#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include "config.h"
#include <config/autoconf.h>


/* This little program is a wrapper for the ssh key-gen program that produces
 * ssh keys as required.  The basic outline is simple, keys will be produced
 * at boot time for sshd only if they don't already exist.  For ssh the path
 * is slightly more complex, keys will be created every boot unless sshd is
 * also installed in which case its behaviour will override.
 *
 * In addition, the flash file system will be synced if sshd is enabled.
 * This means that sshd will only use a single set of keys which is good
 * because ssh causes pain if the daemon it is connecting to changes its
 * keys.
 */


/* Where we end up installing our key files */
#define BASE_DIR	"/etc/config/"

/* List of file names to mangle.
 * The key type is included at the end after a \0 which happens to terminate
 * the string for us :-)
 */
static const char *files[] = {
	"ssh_host_rsa_key\0rsa",
#ifndef CONFIG_USER_SSH_ONLY_RSA_V2_KEYGEN
	"ssh_host_dsa_key\0dsa",
	"ssh_host_key\0rsa1",
#if defined(INCLUDE_SSH)
	"id_rsa\0rsa",
	"id_dsa\0dsa",
	"identity\0rsa1",
#endif
#endif /* CONFIG_USER_SSH_ONLY_RSA_V2_KEYGEN */
	NULL
};


#if defined(INCLUDE_SSHD) || defined(INCLUDE_SSH)
/* Check if the key files are alreayd there or not */
static inline int check_files(void) {
int		  i;
struct stat	  st;
char		  fname[40];
	for (i=0; files[i] != NULL; i++) {
		strcpy(fname, BASE_DIR);
		strcpy(fname+sizeof(BASE_DIR)-1, files[i]);
		if (-1 == stat(fname, &st))
			return 0;
		strcat(fname, ".pub");
		if (-1 == stat(fname, &st))
			return 0;
	}
	return 1;
}
#endif


/* Remove all key files.  The key generator fails if they're already there */
static inline void remove_files(void) {
int		  i;
char		  fname[40];
	for (i=0; files[i] != NULL; i++) {
		strcpy(fname, BASE_DIR);
		strcpy(fname+sizeof(BASE_DIR)-1, files[i]);
		unlink(fname);
		strcat(fname+sizeof(BASE_DIR)-1, ".pub");
		unlink(fname);
	}
}


/* Exec the key generation program with the specified args */
static void exec(char *const av[]) {
extern char	**environ;
int		  status;
pid_t		  pid;
#ifdef __uClinux__
	pid = vfork();
#else
	pid = fork();
#endif
	if (pid == 0) {
		/* Child */
		execve("/bin/ssh-keygen", av, environ);
#ifdef __uClinux__
		_exit(0);
#else
		exit(0);
#endif
	} else if (pid != -1) {
		waitpid(pid, &status, 0);
	}
}


/* Scan through and generate the appropriate keys */
static inline void gen_files(void) {
char		 *av[14];
int		  ac, tc;
char		  fname[40];
int		  i;
	/* set up command args... */
	ac = 0;
	av[ac++] = "ssh-keygen";
	av[ac++] = "-q";
	av[ac++] = "-f";
	strcpy(fname, BASE_DIR);
	av[ac++] = fname;
	av[ac++] = "-C";
	av[ac++] = "";
	av[ac++] = "-N";
	av[ac++] = "";
	av[ac++] = "-t";
	tc = ac++;		/* Placeholder for type */
	av[ac] = NULL;

	/* Loop through the files creating keys */
	for (i=0; files[i] != NULL; i++) {
		strcpy(fname+sizeof(BASE_DIR)-1, files[i]);
		av[tc] = 1+strchr(files[i], '\0');
		exec(av);
	}
}


#if defined(INCLUDE_SSHD) || defined(INCLUDE_SSH)
/* Write back our config file system */
static inline void
sync_files(void)
{
	system("exec flatfsd -s");
}
#endif


/* The main driver routine */
int main(int argc, char *argv[]) {
	sleep(10);	
#if defined(INCLUDE_SSHD) || defined(INCLUDE_SSH)
	if (check_files())
		return 0;
#endif
	remove_files();
	gen_files();
#if defined(INCLUDE_SSHD) || defined(INCLUDE_SSH)
	sync_files();
#endif
	return 0;
}
