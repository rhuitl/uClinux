/* A module exporting no symbols, and requiring two */
extern int exported1, exported2;

static void foo(void)
{
	exported1 = exported2;
}
