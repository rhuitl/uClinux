/* A module exporting a symbol, and requiring a symbol */
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

extern int exported1;
int exported3;

EXPORT_SYMBOL(exported3);

static void foo(void)
{
	exported3 = exported1;
}
