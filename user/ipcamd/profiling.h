#pragma once

#include "config.h"

#include <stdio.h>
#include <sys/time.h>

extern int g_profileDepth;

#ifdef PROFILING
#define PROFILE_BEGIN(section) \
	printf("%*s>>> Section %s start\n", g_profileDepth++, "", #section); \
	struct timeval section##_start, section##_end; \
	clock_t section##_start_clk = clock(), section##_end_clk; \
	gettimeofday(&section##_start, NULL);
#define PROFILE_END(section) \
	gettimeofday(&section##_end, NULL); \
	section##_end_clk = clock(); \
	printf("%*s<<< Section %s took %d ms (%d ms CPU time) to complete\n", \
	           --g_profileDepth, "", \
	           #section, section##_end.tv_sec*1000 + section##_end.tv_usec/1000 - \
	                    section##_start.tv_sec*1000 - section##_start.tv_usec/1000, \
	                    (section##_end_clk - section##_start_clk) / (CLOCKS_PER_SEC/1000) );
#else
#define PROFILE_BEGIN(section)
#define PROFILE_END(section)
#endif
