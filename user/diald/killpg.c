
int killpg(int pgrp, int sig)
{
	printf("%s(%d): killpg(pgrp=%d,sig=%d)\n", __FILE__, __LINE__,
		pgrp, sig);
	return(0);
}

