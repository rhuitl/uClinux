#ifdef AA_EXTERN_ONLY
/* Record an attempted access, either successful or not */
extern void access__attempted(const int denied, const char *const user);

/* Quick check to see if the specified user is permitted to attempt to
 * authenticate or not.
 */
extern int access__permitted(const char *const user);
#else
#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <config/autoconf.h>
#include <signal.h>
#include <sys/file.h>
#include <time.h>

#define AA_COUNTER_FILE	"/etc/config/access_counts"
#define AA_SINGLE_CHARS	"*-+@#"

/* The special single characters are defined thus:
 *
 *	*	global count (defined only if CONFIG_PROP_SECURITY_COUNT_GLOBAL enabled)
 *	-	count overrun limit beyond whichs bad stuff happens (default 10)
 *	+	number of lines in the user database (default 100)
 *	#	lockout time interval in seconds (default 1800)
 *	@	locked out until specified time(2)
 *
 * Not all of these are used all of the time.  For example, the * is only
 * relevant if a global count is being maintained.
 */
#define STR_LOCKOUT		"@"
#define STR_LOCKOUT_INTERVAL	"#"
#define STR_MAX_DB_SIZE		"+"
#define STR_MAX_FAILURES	"-"
#define STR_GLOBAL_COUNT	"*"

#define LOCKOUT_DEFAULT_INTERVAL	1800
#define DEFAULT_MAX_DB_SIZE		100


static void __access__set_count(const char *const user, const int count) {
	FILE *f, *fnew;
	char buf[50];

	if ((f = fopen(AA_COUNTER_FILE, "r")) == NULL) {
		if (count && (f=fopen(AA_COUNTER_FILE, "w")) != NULL) {
			fprintf(f, "%s %d\n", user, count);
			fclose(f);
		}
		return;
	}
	if ((fnew = fopen(AA_COUNTER_FILE ".tmp", "w")) == NULL) {
		fclose(f);
		return;
	}
	while (fgets(buf, sizeof(buf), f) != NULL) {
		char *const p = strchr(buf, ' ');
		if (p != NULL) {
			*p = '\0';
			if (strcmp(buf, user) == 0)
				continue;
			*p = ' ';
		}
		fputs(buf, fnew);
	}
	if (count)
		fprintf(fnew, "%s %d\n", user, count);
	fclose(f);
	fclose(fnew);
	rename(AA_COUNTER_FILE ".tmp", AA_COUNTER_FILE);
}


static int __access__get_count(const char *const user) {
	FILE *f = fopen(AA_COUNTER_FILE, "r");
	char buf[50];

	if (f == NULL)
		return 0;
	while (fgets(buf, sizeof(buf), f) != NULL) {
		char *const p = strchr(buf, ' ');
		if (p == NULL) continue;
		*p = '\0';
		if (strcmp(buf, user) == 0) {
			fclose(f);
			return atoi(p+1);
		}
	}
	fclose(f);
	return 0;
}


static void __access__bump_count(const char *const user) {
	const int max = __access__get_count(STR_MAX_FAILURES)?:CONFIG_PROP_SECURITY_COUNT_MAX;
	const int n = __access__get_count(user);
	if (n >= max) {
		system("/bin/logd message access attempt overrun!");
		syslog(LOG_EMERG, "access attempt overrun!");
#ifdef CONFIG_PROP_SECURITY_COUNT_LOCKOUT
		{
			__access__set_count(user, 0);

			time_t now = time(NULL);
			int interval = __access__get_count(STR_LOCKOUT_INTERVAL);
#ifdef CONFIG_PROP_SECURITY_COUNT_LOCKOUT_TIME
			if (interval <= 0)
				interval = CONFIG_PROP_SECURITY_COUNT_LOCKOUT_TIME;
#endif
			if (interval <= 0)
				interval = LOCKOUT_DEFAULT_INTERVAL;

			syslog(LOG_INFO, "accesses locked out for %d seconds", interval);
			__access__set_count(STR_LOCKOUT, now + interval);
		}
#endif

#if CONFIG_PROP_SECURITY_COUNT_IMMOLATE
#if CONFIG_USER_FLATFSD_FLATFSD
		if (system("exec flatfsd -i") != -1)
			sleep(60); /* we should reboot while ehile, but just in case */
#endif
		system("/bin/reboot");
		_exit(0);
#endif
	} else
		__access__set_count(user, n+1);
}


static void __access__trim_lines(void) {
	FILE *f, *fnew;
	char buf[50];
	int c=__access__get_count(STR_MAX_DB_SIZE);

	if (c <= 0)
		c = DEFAULT_MAX_DB_SIZE;

	if ((f = fopen(AA_COUNTER_FILE, "r")) == NULL)
		return;
	while (fgets(buf, sizeof(buf), f) != NULL)
		if (buf[1] != ' ' || strchr(AA_SINGLE_CHARS, buf[0]) == NULL)
			c--;
	if (c >= 0) {
		fclose(f);
		return;
	}
	if ((fnew = fopen(AA_COUNTER_FILE ".tmp", "w")) == NULL) {
		fclose(f);
		return;
	}
	rewind(f);
	while (fgets(buf, sizeof(buf), f) != NULL)
		if ((buf[1] == ' ' && strchr(AA_SINGLE_CHARS, buf[0]) != NULL) ||
				c++>=0)
			fputs(buf, fnew);
	fclose(f);
	fclose(fnew);
	rename(AA_COUNTER_FILE ".tmp", AA_COUNTER_FILE);
}


/* Some routines to provide us with some locking capability.
 * Having two things update the database file is bad as is having
 * something reading it and something else writing it.
 */
static int __access_lock(void) {
	int lck = open("/bin/login", O_RDONLY);
	flock(lck, LOCK_EX);
	return lck;
}

static void __access_unlock(int lck) {
	flock(lck, LOCK_UN);
	close(lck);
}


/* Main entry point.  An access has been attempted for the specified
 * user and it either succeeded or it didn't.  Simply track the relevant
 * changes.
 */
void access__attempted(const int denied, const char *const user) {
	const int lck = __access_lock();

	if (0) { ; }
#if CONFIG_PROP_SECURITY_COUNT_GLOBAL
	else if (strcmp(user, STR_MAX_FAILURES) == 0)
		goto bcom;
#endif
	else if (denied) {
		__access__bump_count(user);
#if CONFIG_PROP_SECURITY_COUNT_GLOBAL
bcom:		__access__bump_count(STR_GLOBAL_COUNT);
#endif
		__access__trim_lines();
	} else {
		if (__access__get_count(user) == 0)
#if CONFIG_PROP_SECURITY_COUNT_GLOBAL
			if (__access__get_count(STR_GLOBAL_COUNT) == 0)
#endif
				goto fin;
		__access__set_count(user, 0);
#if CONFIG_PROP_SECURITY_COUNT_GLOBAL
		__access__set_count(STR_GLOBAL_COUNT, 0);
#endif
	}
#ifdef CONFIG_USER_FLATFSD_FLATFSD
	system("exec flatfsd -s");
#endif

fin:	__access_unlock(lck);
}


/* Return non-zero if access by the specified user is permitted at
 * this point in time.  Return zero otherwise.
 */
int access__permitted(const char *const user) {
	const int lck = __access_lock();
	int res = 1;		// Assume permitted
#ifdef CONFIG_PROP_SECURITY_COUNT_LOCKOUT
	const time_t when = __access__get_count(STR_LOCKOUT);

	if (when != 0) {
		const time_t now = time(NULL);
		if (when >= now)
			res = 0;
		else {
			__access__set_count(STR_LOCKOUT, 0);
#ifdef CONFIG_USER_FLATFSD_FLATFSD
			system("exec flatfsd -s");
#endif
		}
	}
#endif
	__access_unlock(lck);
	return res;
}

#endif
