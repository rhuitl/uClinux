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

