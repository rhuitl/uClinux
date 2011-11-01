#pragma once

#define BUFFER_COUNT 3
// We should probably not set MIN_QUEUED lower as 2, as this means that there
// can be times where no buffer is queued at all.
#define MIN_QUEUED   2

#define LOCKS
#define HTTPD
#define JPEG_SIGN
#define JPEG_DECODE

//#define BUFFER_DEBUG
#define PROFILING
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

