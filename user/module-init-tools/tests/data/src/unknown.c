/* An undefined symbol */
extern int undefined;

static void foo(void)
{
	undefined = 1;
}
