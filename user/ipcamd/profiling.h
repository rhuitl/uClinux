/*
This file is part of ipcamd, an embedded web server for IP cameras.

Copyright (c) 2011-2013, Robert Huitl <robert@huitl.de>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

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
