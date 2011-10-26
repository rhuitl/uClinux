#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>

int
main (void)
{
	register struct passwd * upw = getpwuid(getuid());

	if (upw) {
		write(STDOUT_FILENO,upw->pw_name,strlen(upw->pw_name));
		write(STDOUT_FILENO,"\n",1);
		exit (0);
	}
	exit (1);
}
