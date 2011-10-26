#include <linux/posix_types.h>
#define dev_t __kernel_dev_t
#include <linux/loop.h>
#undef dev_t
