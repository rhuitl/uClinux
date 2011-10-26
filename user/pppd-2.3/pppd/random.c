#ifdef EMBED

static unsigned int	_seed;

void srandom(unsigned int seed)
{
	_seed = seed;
}

long random(void)
{
	_seed += 13;
	return((_seed * (_seed + 1)) | (_seed << (_seed % 30)));
}

#endif /* EMBED */
