
#include <unistd.h>

#include "version.h"
#include "compile.h"

extern char global_stamp[];
extern char local_stamp[];

#define check_version_argument					\
	if ((argc>1) && !strcmp(argv[1], "--version")) {	\
		puts( global_stamp );				\
		puts( local_stamp );				\
		exit(0);					\
	}
