
#include <features.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>

char * mktemp(template)
char * template;
{
	int i;
static	int num;
	int n2;
	int l = strlen(template);
	struct stat stbuf;
	struct timeval tv;
	
	if (l<6) {
		errno = EINVAL;
		return 0;
	}
	
	for(i=l-6;i<l;i++)
		if (template[i] != 'X') {
			errno = EINVAL;
			return 0;
		}
	
	/* Initialise our seed value to something a bit more exciting.
	 * We're using urandom to ensure we don't block here.  We only
	 * do this the very first time through (or when the seed hits zero).
	 */
	if (num == 0) {
		i = open("/dev/urandom", O_RDONLY);
		if (i >= 0) {
			read(i, &num, sizeof(int));
			close(i);
		}
	}
	/* Perterb the seen value a little */
	gettimeofday(&tv, NULL);
	num += (tv.tv_usec << 16) ^ tv.tv_sec ^ getpid();
	num += (tv.tv_usec << 16) ^ tv.tv_sec ^ getpid();
	/* Now ensure that the seed number is both positive and that there
	 * is sufficient "space" left so that we can iterate over the entire
	 * possible range of values without turning negative ever.
	 */
	num &= 0xfffffff;
again:	
	n2 = num;
	for(i=l-1;i>=l-6;i--) {
		template[i] = '0' + n2 % 10;
		n2 /= 10;
	}
	
	if (stat(template, &stbuf) == 0) {
		num++;
		goto again;
	}
	
	return template;
}
