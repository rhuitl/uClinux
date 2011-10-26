#include <stdio.h>

int local_creat(char *name, int flags);
int local_fclose(FILE *fp);
int local_fseek(FILE *fp, int offset, int whence);
int local_putc(int ch, FILE *fp);
int local_write(int fd, void *buf, int count);
FILE *local_fdopen(int fd, char *flags);
