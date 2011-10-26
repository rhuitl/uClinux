/* Simple module with aliases. */
/* For userspace: you can also call me... */
#define ___module_cat(a,b) a ## b
#define __module_cat(a,b) ___module_cat(a,b)
#define MODULE_ALIAS(alias)					\
	static const char __module_cat(__alias_,__LINE__)[]	\
		__attribute__((section(".modalias"))) = alias

MODULE_ALIAS("alias1");
MODULE_ALIAS("alias2");
