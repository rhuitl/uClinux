#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "kmp.h"

/* Implementation of the Knuth-Morris-Pratt fast searching algorithm
 * from http://www-igm.univ-mlv.fr/~lecroq/string/node8.html
 */

/**
 * Prepare the search string 'x' of length m.
 *
 * Stores the preprocessed data in kmpNext[] which must
 * be at least of length 'm'.
 */
static void preKmp(const char *x, int m, int kmpNext[])
{
	int i, j;

	i = 0;
	j = kmpNext[0] = -1;
	while (i < m - 1) {
		while (j > -1 && x[i] != x[j]) {
			j = kmpNext[j];
		}
		i++;
		j++;
		if (x[i] == x[j]) {
			kmpNext[i] = kmpNext[j];
		}
		else {
			kmpNext[i] = j;
		}
	}
}

int KMP(const char *x, int m, getblock_function *getter, void *cookie)
{
	int i, j, k, kmpNext[m];
	const char *text;
	int len;

	/* Preprocessing */
	preKmp(x, m, kmpNext);

	/* Searching */
	i = j = 0;

	for (;;) {
		len = getter(&text, cookie);
		if (len == 0)
			break;

		for (k = 0; k < len; k++) {
			while (i > -1 && x[i] != text[k]) {
				i = kmpNext[i];
			}
			i++;
			j++;
			if (i >= m) {
				/* We return the position just after the match.
				 * This is where our getter input is left
				 */
				return j;
			}
		}
	}
	/* Not found */
	return -1;
}
