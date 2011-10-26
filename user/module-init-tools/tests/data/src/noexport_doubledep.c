/* A module which requires symbols from two other sources */
extern int exported1, exported2, exported3;

static void foo(void)
{
	exported1 = exported2 = exported3;
}
