#include "mconf.h"
#include "mathf.h"

double modf(double x, double *iptr) {
	if (x == 0) {
		*iptr = 0;
		return 0;
	} else {
		int neg;
		double y;

		if (x < 0) {
			neg = 1;
			x = -x;
		} else
			neg = 0;
		y = floor(x);
		*iptr = neg?-y:y;

		y = x-y;
		return neg?-y:y;
	}
}
