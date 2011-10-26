#ifndef _LIBIPT_SET_H
#define _LIBIPT_SET_H

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#ifdef DEBUG
#define DEBUGP(x, args...) fprintf(stderr, x, ## args)
#else
#define DEBUGP(x, args...) 
#endif

static void
parse_bindings(const char *opt_arg, struct ipt_set_info *info)
{
	char *saved = strdup(opt_arg);
	char *ptr, *tmp = saved;
	int i = 0;
	
	while (i < (IP_SET_MAX_BINDINGS - 1) && tmp != NULL) {
		ptr = strsep(&tmp, ",");
		if (strncmp(ptr, "src", 3) == 0)
			info->flags[i++] |= IPSET_SRC;
		else if (strncmp(ptr, "dst", 3) == 0)
			info->flags[i++] |= IPSET_DST;
		else
			xtables_error(PARAMETER_PROBLEM,
				   "You must spefify (the comma separated list of) 'src' or 'dst'.");
	}

	if (tmp)
		xtables_error(PARAMETER_PROBLEM,
			   "Can't follow bindings deeper than %i.", 
			   IP_SET_MAX_BINDINGS - 1);

	free(saved);
}

#endif /*_LIBIPT_SET_H*/
