/* A depends on B, C and D.  B depends on E.  C depends on B and E.  D
   depends on B. */
extern int b, c, d;

static void foo(void)
{
	b = c = d = 0;
}


