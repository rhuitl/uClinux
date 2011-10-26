/* A module exporting two symbols, and requiring none.  New-style */
#define MODULE_NAME_LEN (64 - sizeof(unsigned long))
struct kernel_symbol
{
	unsigned long value;
	const char *name;
};

#define EXPORT_SYMBOL(sym)					\
	const char __ksymtab_string_##sym[]			\
	__attribute__((section("__ksymtab_strings"))) = #sym;	\
	const struct kernel_symbol __ksymtab_##sym		\
	__attribute__((section("__ksymtab")))			\
	= { (unsigned long)&sym, __ksymtab_string_##sym }

int exported1, exported2;

EXPORT_SYMBOL(exported1);
EXPORT_SYMBOL(exported2);
