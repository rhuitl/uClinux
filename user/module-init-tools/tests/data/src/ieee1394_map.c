/* Simple file with a ieee1394 map in it. */
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

struct ieee1394_device_id {
	unsigned int match_flags;
	unsigned int vendor_id;
	unsigned int model_id;
	unsigned int specifier_id;
	unsigned int version;
	void *driverptr;
};

#define IEEE1394_MATCH_VENDOR_ID	0x0001
#define IEEE1394_MATCH_MODEL_ID		0x0002
#define IEEE1394_MATCH_SPECIFIER_ID	0x0004
#define IEEE1394_MATCH_VERSION		0x0008

/*
 * Unit spec id and sw version entry for some protocols
 */
#define AVC_UNIT_SPEC_ID_ENTRY					0x0000A02D
#define AVC_SW_VERSION_ENTRY					0x00010001
#define CAMERA_UNIT_SPEC_ID_ENTRY				0x0000A02D
#define CAMERA_SW_VERSION_ENTRY					0x00000100

static struct ieee1394_device_id ieee1394_ids[] 
= { {
	.match_flags	= IEEE1394_MATCH_SPECIFIER_ID | IEEE1394_MATCH_VERSION,
	.specifier_id	= AVC_UNIT_SPEC_ID_ENTRY & 0xffffff,
	.version	= AVC_SW_VERSION_ENTRY & 0xffffff
}, {
	.match_flags	= IEEE1394_MATCH_SPECIFIER_ID | IEEE1394_MATCH_VERSION,
	.specifier_id	= CAMERA_UNIT_SPEC_ID_ENTRY & 0xffffff,
	.version	= CAMERA_SW_VERSION_ENTRY & 0xffffff
},
    { }
};

MODULE_DEVICE_TABLE(ieee1394, ieee1394_ids);
