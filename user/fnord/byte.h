#ifndef BYTE_H
#define BYTE_H

#include <sys/cdefs.h>

#ifndef __pure__
#define __pure__
#endif

/* byte_chr returns the smallest integer i between 0 and len-1
 * inclusive such that one[i] equals needle, or len it not found. */
unsigned int byte_chr(const void* haystack, unsigned int len, char needle) __pure__;

/* byte_rchr returns the largest integer i between 0 and len-1 inclusive
 * such that one[i] equals needle, or len if not found. */
unsigned int byte_rchr(const void* haystack,unsigned int len,char needle) __pure__;

/* byte_copy copies in[0] to out[0], in[1] to out[1], ... and in[len-1]
 * to out[len-1]. */
void byte_copy(void* out, unsigned int len, const void* in);

/* byte_copyr copies in[len-1] to out[len-1], in[len-2] to out[len-2],
 * ... and in[0] to out[0] */
void byte_copyr(void* out, unsigned int len, const void* in);

/* byte_diff returns negative, 0, or positive, depending on whether the
 * string a[0], a[1], ..., a[len-1] is lexicographically smaller
 * than, equal to, or greater than the string b[0], b[1], ...,
 * b[len-1]. When the strings are different, byte_diff does not read
 * bytes past the first difference. */
int byte_diff(const void* a, unsigned int len, const void* b) __pure__;

/* byte_zero sets the bytes out[0], out[1], ..., out[len-1] to 0 */
void byte_zero(void* out, unsigned len);

#define byte_equal(s,n,t) (!byte_diff((s),(n),(t)))

#endif
