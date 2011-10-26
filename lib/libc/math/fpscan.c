
double fp_scan(neg, eneg, n, frac, expo, fraclen)
int neg, eneg, n, frac, expo, fraclen;
{
	double f;
	//printf("neg=%d,eneg=%d,n=%d,frac=%d,expo=%d,fraclen=%d\n", neg,eneg,n,frac,expo,fraclen);
	f = frac;
	while (fraclen-->0)
		f /= 10;
	f += n;
	if (neg)
		f = -f;
	return f;
}
