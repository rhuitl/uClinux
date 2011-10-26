#define UCFRONT_VERSION "0.2"

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <utime.h>
#include <stdarg.h>
#include <dirent.h>
#include <limits.h>

typedef unsigned uint32;

void cc_log(const char *format, ...);
void fatal(const char *format, ...);

void x_asprintf(char **ptr, const char *format, ...);
char *x_strdup(const char *s);
void *x_realloc(void *ptr, size_t size);
void *x_malloc(size_t size);
void traverse(const char *dir, void (*fn)(const char *, struct stat *));
char *str_basename(const char *s);
char *dirname(char *s);
int lock_fd(int fd);
size_t file_size(struct stat *st);
int safe_open(const char *fname);
char *x_realpath(const char *path);
char *gnu_getcwd(void);
int create_empty_file(const char *fname);

int execute(char **argv, 
	    const char *path_stdout,
	    const char *path_stderr);
char *find_executable(const char *name, const char *exclude_name);

typedef struct {
	char **argv;
	int argc;
} ARGS;

ARGS *args_init(int , char **);
void args_add(ARGS *args, const char *s);
void args_add_with_spaces(ARGS *args, const char *s);
void args_add_prefix(ARGS *args, const char *s);
void args_pop(ARGS *args, int n);
void args_strip(ARGS *args, const char *prefix);
void args_remove_first(ARGS *args);

#if HAVE_COMPAR_FN_T
#define COMPAR_FN_T __compar_fn_t
#else
typedef int (*COMPAR_FN_T)(const void *, const void *);
#endif
