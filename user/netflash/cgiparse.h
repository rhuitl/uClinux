#ifndef CGIPARSE_H
#define CGIPARSE_H

#include <stdlib.h>

#define CGIPARSE_ERR_NONE       0
#define CGIPARSE_ERR_FORMAT     1
#define CGIPARSE_ERR_DATA       2
#define CGIPARSE_ERR_TIMEDOUT   3

typedef void output_buffer_function(const char *name, const char *content_type, const char *buf, size_t len, off_t pos);

/**
 * Extracts a sections from multipart mime data on stdin.
 *
 * Outputs to the writer.
 */
int cgi_extract_sections(output_buffer_function *writer);

#endif
