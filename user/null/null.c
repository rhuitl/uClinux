
int main()
{
	printf("Accessing invalid pointer...\n");

	*((volatile unsigned char *) 0xa0000000) = 0;

	return(0);
}
