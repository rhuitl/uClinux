#ifndef MODINITTOOLS_DEPMOD_H
#define MODINITTOOLS_DEPMOD_H
#include "list.h"

struct module;

/* Functions provided by depmod.c */
void fatal(const char *fmt, ...) __attribute__ ((noreturn,
						 format (printf, 1, 2)));
void warn(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
void *do_nofail(void *ptr, const char *file, int line, const char *expr);
#define NOFAIL(ptr)	do_nofail((ptr), __FILE__, __LINE__, #ptr)

void add_symbol(const char *name, struct module *owner);
struct module *find_symbol(const char *name, const char *modname, int weak);
void add_dep(struct module *mod, struct module *depends_on);

/* I hate strcmp. */
#define streq(a,b) (strcmp((a),(b)) == 0)

struct module
{
	/* Next module in list of all modules */
	struct module *next;

	/* 64 or 32 bit? */
	struct module_ops *ops;

	/* Convert endian? */
	int conv;

	/* Dependencies: filled in by ops->calculate_deps() */
	unsigned int num_deps;
	struct module **deps;

	/* Set while we are traversing dependencies */
	struct list_head dep_list;

	/* Tables extracted from module by ops->fetch_tables(). */
	unsigned int pci_size;
	void *pci_table;
	unsigned int usb_size;
	void *usb_table;
	unsigned int ieee1394_size;
	void *ieee1394_table;
	unsigned int ccw_size;
	void *ccw_table;
	unsigned int pnp_size;
	void *pnp_table;
	unsigned int pnp_card_size;
	unsigned int pnp_card_offset;
	void *pnp_card_table;
	unsigned int input_size;
	void *input_table;
	unsigned int input_table_size;
	unsigned int serio_size;
	void *serio_table;
	unsigned int of_size;
	void *of_table;

	/* File contents and length. */
	void *data;
	unsigned long len;

	char pathname[0];
};

#define END(x, conv)							  \
({									  \
	typeof(x) __x;							  \
	if (conv) __convert_endian(&(x), &(__x), sizeof(__x));		  \
	else __x = (x);							  \
	__x;								  \
})

static inline void __convert_endian(const void *src, void *dest,
				    unsigned int size)
{
	unsigned int i;
	for (i = 0; i < size; i++)
		((unsigned char*)dest)[i] = ((unsigned char*)src)[size - i-1];
}
#endif /* MODINITTOOLS_DEPMOD_H */
