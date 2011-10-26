/* Simple file with an ISAPNP map in it. */
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

#define PNP_MAX_DEVICES		8
#define PNP_ID_LEN		8

struct pnp_device_id {
	char id[PNP_ID_LEN];
	unsigned long driver_data;	/* data private to the driver */
};

struct pnp_card_device_id {
	char id[PNP_ID_LEN];
	unsigned long driver_data;	/* data private to the driver */
	struct {
		char id[PNP_ID_LEN];
	} devs[PNP_MAX_DEVICES];	/* logical devices */
};

static struct pnp_card_device_id snd_ad1816a_pnpids[] = {
	/* Analog Devices AD1815 */
	{ .id = "ADS7150", .devs = { { .id = "ADS7150" }, { .id = "ADS7151" } } },
	/* Analog Devices AD1816A - added by Kenneth Platz <kxp@atl.hp.com> */
	{ .id = "ADS7181", .devs = { { .id = "ADS7180" }, { .id = "ADS7181" } } },
	/* end */
	{ .id = "" }
};

MODULE_DEVICE_TABLE(pnp_card, snd_ad1816a_pnpids);

/* All cs4232 based cards have the main ad1848 card either as CSC0000 or
 * CSC0100. */
static const struct pnp_device_id cs4232_pnp_table[] = {
	{ .id = "CSC0100", .driver_data = 0 },
	{ .id = "CSC0000", .driver_data = 0 },
	/* Guillemot Turtlebeach something appears to be cs4232 compatible
	 * (untested) */
	{ .id = "GIM0100", .driver_data = 0 },
	{ .id = ""}
};

MODULE_DEVICE_TABLE(pnp, cs4232_pnp_table);
