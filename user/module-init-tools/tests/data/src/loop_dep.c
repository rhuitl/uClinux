/* Requires a module in the loop */
extern int from_loop1;

static void foo(void)
{
	from_loop1 = 0;
}
