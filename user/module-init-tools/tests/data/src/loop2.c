/* Part of a simple module loop */
extern int from_loop1;

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

int from_loop2;

EXPORT_SYMBOL(from_loop2);

static void foo(void)
{
	from_loop2 = from_loop1;
}
