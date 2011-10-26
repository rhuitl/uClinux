/* Simple file with an INPUT map in it. */
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

#define INPUT_DEVICE_ID_MATCH_VENDOR	2
#define INPUT_DEVICE_ID_MATCH_PRODUCT	4
#define INPUT_DEVICE_ID_MATCH_VERSION	8

#define INPUT_DEVICE_ID_MATCH_EVBIT	0x010
#define INPUT_DEVICE_ID_MATCH_KEYBIT	0x020
#define INPUT_DEVICE_ID_MATCH_RELBIT	0x040
#define INPUT_DEVICE_ID_MATCH_ABSBIT	0x080
#define INPUT_DEVICE_ID_MATCH_MSCIT	0x100
#define INPUT_DEVICE_ID_MATCH_LEDBIT	0x200
#define INPUT_DEVICE_ID_MATCH_SNDBIT	0x400
#define INPUT_DEVICE_ID_MATCH_FFBIT	0x800
#define INPUT_DEVICE_ID_MATCH_SWBIT    0x1000

#define INPUT_DEVICE_ID_MATCH_DEVICE\
	(INPUT_DEVICE_ID_MATCH_BUS | INPUT_DEVICE_ID_MATCH_VENDOR | INPUT_DEVICE_ID_MATCH_PRODUCT)
#define INPUT_DEVICE_ID_MATCH_DEVICE_AND_VERSION\
	(INPUT_DEVICE_ID_MATCH_DEVICE | INPUT_DEVICE_ID_MATCH_VERSION)

#define EV_MAX			0x1f
#define KEY_MAX			0x1ff
#define REL_MAX			0x0f
#define ABS_MAX			0x3f
#define MSC_MAX			0x07
#define LED_MAX			0x0f
#define REP_MAX			0x01
#define SND_MAX			0x07
#define FF_MAX			0x7f
#define SW_MAX			0x0f

#define BIT(x)	(1UL<<((x)%BITS_PER_LONG))
#define NBITS(x) ((((x)-1)/BITS_PER_LONG)+1)

struct input_id {
	unsigned short bustype;
	unsigned short vendor;
	unsigned short product;
	unsigned short version;
};

struct input_device_id {

	unsigned long flags;

	struct input_id id;

	unsigned long evbit[NBITS(EV_MAX)];
	unsigned long keybit[NBITS(KEY_MAX)];
	unsigned long relbit[NBITS(REL_MAX)];
	unsigned long absbit[NBITS(ABS_MAX)];
	unsigned long mscbit[NBITS(MSC_MAX)];
	unsigned long ledbit[NBITS(LED_MAX)];
	unsigned long sndbit[NBITS(SND_MAX)];
	unsigned long ffbit[NBITS(FF_MAX)];
	unsigned long swbit[NBITS(SW_MAX)];

	unsigned long driver_info;
};

#define EV_SND			0x12
#define EV_KEY			0x01
#define SW_0			0

static struct input_device_id kbd_ids[] = {
	{
                .flags = INPUT_DEVICE_ID_MATCH_EVBIT|INPUT_DEVICE_ID_MATCH_SWBIT,
                .evbit = { BIT(EV_KEY) },
		.swbit = { BIT(SW_0) },
        },
	
	{
                .flags = INPUT_DEVICE_ID_MATCH_EVBIT,
                .evbit = { BIT(EV_SND) },
        },	

	{ },    /* Terminating entry */
};

MODULE_DEVICE_TABLE(input, kbd_ids);
