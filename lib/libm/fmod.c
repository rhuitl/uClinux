#include "mconf.h"
#include "mathf.h"

double fmod(double x, double y) {
	if (y == 0) {
		mtherr("fmod", DOMAIN);
		return 0.0;
	} else {
		double div;
		div = x/y;
		if (div < 0)
			div = -floor(-div);
		else
			div = floor(div);
		return (x - div * y);
	}
}
