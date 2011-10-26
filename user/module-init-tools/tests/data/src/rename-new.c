/* Old-style module with module in __this_module */

#define MODULE_NAME_LEN (64 - sizeof(unsigned long))
struct kernel_symbol
{
	unsigned long value;
	char name[MODULE_NAME_LEN];
};

struct list_head {
	struct list_head *next, *prev;
};

struct kernel_symbol_group
{
	/* Links us into the global symbol list */
	struct list_head list;

	/* Module which owns it (if any) */
	struct module *owner;

	unsigned int num_syms;
	const struct kernel_symbol *syms;
};

struct exception_table
{
	struct list_head list;

	unsigned int num_entries;
	const struct exception_table_entry *entry;
};

enum module_state
{
	MODULE_STATE_LIVE,
	MODULE_STATE_COMING,
	MODULE_STATE_GOING,
};

struct module
{
	enum module_state state;

	/* Member of list of modules */
	struct list_head list;

	/* Unique handle for this module */
	char name[MODULE_NAME_LEN];

	/* Exported symbols */
	struct kernel_symbol_group symbols;

	/* Exception tables */
	struct exception_table extable;

	/* Startup function. */
	int (*init)(void);

	/* If this is non-NULL, vfree after init() returns */
	void *module_init;

	/* Here is the actual code + data, vfree'd on unload. */
	void *module_core;

	/* Here are the sizes of the init and core sections */
	unsigned long init_size, core_size;

	/* Arch-specific module values */
	struct { } arch;

	/* Am I unsafe to unload? */
	int unsafe;

	/* The command line arguments (may be mangled).  People like
	   keeping pointers to this stuff */
	char *args;
};

#define __stringify_1(x)	#x
#define __stringify(x)		__stringify_1(x)

static struct module __this_module
__attribute__((section("__module"))) = {
	.name = "rename_new_" __stringify(BITS_PER_LONG),
};

