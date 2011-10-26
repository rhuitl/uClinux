/* Simple file with a PCI map in it. */
#define __stringify_1(x)	#x
#define __stringify(x)		__stringify_1(x)

#define MODULE_GENERIC_TABLE(gtype,name)			\
static const unsigned long __module_##gtype##_size		\
  __attribute__ ((unused)) = sizeof(struct gtype##_id);		\
static const struct gtype##_id * __module_##gtype##_table	\
  __attribute__ ((unused)) = name;				\
extern const struct gtype##_id __mod_##gtype##_table		\
  __attribute__ ((unused, alias(__stringify(name))))

#define MODULE_DEVICE_TABLE(type,name)		\
  MODULE_GENERIC_TABLE(type##_device,name)

struct of_device_id {
	char name[32];
	char type[32];
	char compatible[128];
	void *data;
};

static struct of_device_id of_ids[] = {
	{
		.name		= "test_name_1",
	},
	{
		.type		= "test_type_1",
	},
	{
		.compatible	= "test_compat_1",
	},
	{
		.name		= "test_name_2",
		.type		= "test_type_2",
	},
	{
		.name		= "test_name_3",
		.compatible	= "test_compat_2",
	},
	{
		.type		= "test_type_3",
		.compatible	= "test_compat_3",
	},
	{
		.name		= "test_name_4",
		.type		= "test_type_4",
		.compatible	= "test_compat_4",
	},
	{}
};
MODULE_DEVICE_TABLE(of, of_ids);
