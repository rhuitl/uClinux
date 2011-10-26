#ifndef KMP_H
#define KMP_H

/* Implementation of the Knuth-Morris-Pratt fast searching algorithm
 * from http://www-igm.univ-mlv.fr/~lecroq/string/node8.html
 */

typedef int getblock_function(const char **text, void *cookie);

/**
 * Searches for an exact string match for 'x' of length 'm' in a stream
 * Using the Knuth-Morris-Pratt algorith.
 *
 * 'getter' returns one character at a time from the stream
 * and EOF at end of file. 'cookie' is passed to 'getter'.
 *
 * If a match is found, returns the offset character JUST PAST THE END OF THE MATCH.
 * e.g. KMP("abc", "xxabcyy") will return 5.
 * The input stream will be read to this point.
 *
 * Returns -1 if the string is not found.
 */
int KMP(const char *x, int m, getblock_function *getter, void *cookie);

#endif
