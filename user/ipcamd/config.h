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

#define BUFFER_COUNT 3
// We should probably not set MIN_QUEUED lower as 2, as this means that there
// can be times where no buffer is queued at all.
#define MIN_QUEUED   2

#define LOCKS
#define HTTPD
//#define JPEG_SIGN
//#define JPEG_DECODE
//#define MOTION_DETECTION

//#define BUFFER_DEBUG
//#define PROFILING
#define ENUM_CONTROLS


#define CONFIG_MTD	"/dev/mtd3"

struct cam_config {
	char valid;              /* 0 => run init_config() */
	char version;            /* config version. valid versions: 0 */
	unsigned int ip;         /* 0 = dhcp */
	char cam_name[10];
};

int read_config(struct cam_config* c);
int write_config(struct cam_config* c);
void print_config(struct cam_config* c);
void init_config(struct cam_config* c);

