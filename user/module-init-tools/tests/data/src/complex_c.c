/* A depends on B, C and D.  B depends on E.  C depends on B and E.  D
   depends on B. */
int c;
extern int b, e;

static void foo(void)
{
	c = b = e = 0;
}

#define MODULE_NAME_LEN (64 - sizeof(unsigned long))
struct kernel_symbol
{
	unsigned long value;
	char name[MODULE_NAME_LEN];
};

#define EXPORT_SYMBOL(sym)				\
	const struct kernel_symbol __ksymtab_##sym	\
	__attribute__((section("__ksymtab")))		\
	= { (unsigned long)&sym, #sym }

EXPORT_SYMBOL(c);

