
#include "compile.h"
#include "version.h"
#include "programid.h"

#define check_version_argument					\
	if ((argc>1) && !strcmp(argv[1], "--version")) {	\
		printf(	"$Program: " PROGRAM_NAME	 	\
			" release " PROGRAM_RELEASE		\
			", version " PROGRAM_VERSION		\
			" $\n");				\
		printf(	"$Toolchain: " TOOLCHAIN_NAME 		\
			" release " TOOLCHAIN_RELEASE		\
			", version " TOOLCHAIN_VERSION		\
			" $\n");				\
		exit(0);					\
	}
