/* Module with random crap in modinfo */
#define __stringify_1(x)	#x
#define __stringify(x)		__stringify_1(x)
#define ___module_cat(a,b) __mod_ ## a ## b
#define __module_cat(a,b) ___module_cat(a,b)
#define MODULE_INFO(tag, info) \
static const char __module_cat(tag,__LINE__)[]	\
	__attribute__((section(".modinfo"),unused)) = __stringify(tag) "=" info

#define MODULE_ALIAS(_alias) MODULE_INFO(alias, _alias)
#define MODULE_LICENSE(_license) MODULE_INFO(license, _license)
#define MODULE_AUTHOR(_author) MODULE_INFO(author, _author)
#define MODULE_DESCRIPTION(_description) MODULE_INFO(description, _description)
#define MODULE_PARM_DESC(_parm, desc) MODULE_INFO(parm, #_parm ":" desc)

MODULE_INFO(randomcrap, "my random crap which I use to test stuff with");
MODULE_INFO(vermagic, "my magic");
MODULE_AUTHOR("AUTHOR");
MODULE_DESCRIPTION("DESCRIPTION");
MODULE_ALIAS("ALIAS1");
MODULE_ALIAS("ALIAS2");

/* Parameter description, no param type (before 2.6.11) */
MODULE_PARM_DESC(foo, "The number of foos on the card");

/* Parameter, no description. */
MODULE_INFO(parmtype, "undescribed:int");

/* Parameter, with description */
MODULE_INFO(parmtype, "described:uint");
MODULE_PARM_DESC(described, "A well-described parameter");
