/* A depends on B, C and D.  B depends on E.  C depends on B and E.  D
   depends on B. */
int d;
extern int b;

static void foo(void)
{
	d = b;
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

EXPORT_SYMBOL(d);

