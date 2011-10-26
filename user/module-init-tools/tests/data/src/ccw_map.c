/* Simple file with a CCW map in it. */
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

struct ccw_device_id {
	unsigned short	match_flags;	/* which fields to match against */

	unsigned short	cu_type;	/* control unit type     */
	unsigned short	dev_type;	/* device type           */
	unsigned char	cu_model;	/* control unit model    */
	unsigned char	dev_model;	/* device model          */

	unsigned long driver_info;
};

enum match_flag {
	CCW_DEVICE_ID_MATCH_CU_TYPE      = 0x01,
	CCW_DEVICE_ID_MATCH_CU_MODEL     = 0x02,
	CCW_DEVICE_ID_MATCH_DEVICE_TYPE  = 0x04,
	CCW_DEVICE_ID_MATCH_DEVICE_MODEL = 0x08,
};

static struct ccw_device_id ccw_ids[] = {
	{ CCW_DEVICE_ID_MATCH_CU_TYPE |
	  CCW_DEVICE_ID_MATCH_CU_MODEL |
	  CCW_DEVICE_ID_MATCH_DEVICE_TYPE |
	  CCW_DEVICE_ID_MATCH_DEVICE_MODEL,
	  1, 2, 3, 4, 0xdeadbeef },
	{ CCW_DEVICE_ID_MATCH_CU_TYPE |
	  CCW_DEVICE_ID_MATCH_CU_MODEL |
	  CCW_DEVICE_ID_MATCH_DEVICE_TYPE |
	  CCW_DEVICE_ID_MATCH_DEVICE_MODEL,
	  11, 12, 13, 14, 0xdeadbee5 },
	{ /* end of list */ }
};

MODULE_DEVICE_TABLE(ccw, ccw_ids);
