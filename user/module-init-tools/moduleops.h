#ifndef MODINITTOOLS_MODULEOPS_H
#define MODINITTOOLS_MODULEOPS_H
#include <stdio.h>

/* All the icky stuff to do with manipulating 64 and 32-bit modules
   belongs here. */
struct kernel_symbol32 {
	char value[4];
	char name[64 - 4];
};

struct kernel_symbol64 {
	char value[8];
	char name[64 - 8];
};

struct module_ops
{
	void (*load_symbols)(struct module *module);
	void (*calculate_deps)(struct module *module, int verbose);
	void (*fetch_tables)(struct module *module);
	char *(*get_aliases)(struct module *module, unsigned long *size);
	char *(*get_modinfo)(struct module *module, unsigned long *size);
};

extern struct module_ops mod_ops32, mod_ops64;

#endif /* MODINITTOOLS_MODULEOPS_H */
