#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "depmod.h"
#include "tables.h"

/* Turn /lib/modules/2.5.49/kernel/foo.ko(.gz) => foo */
static void make_shortname(char *dest, const char *src)
{
	char *ext;
	const char *slash;

	slash = strrchr(src, '/') ?: src-1;
	strcpy(dest, slash + 1);
	ext = strchr(dest, '.');
	if (ext)
		*ext = '\0';
}

/* We set driver_data to zero */
static void output_pci_entry(struct pci_device_id *pci, char *name, FILE *out,
			     int conv)
{
	fprintf(out,
		"%-20s 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x0\n",
		name,
		END(pci->vendor, conv),
		END(pci->device, conv),
		END(pci->subvendor, conv),
		END(pci->subdevice, conv),
		END(pci->class, conv),
		END(pci->class_mask, conv));
}

void output_pci_table(struct module *modules, FILE *out)
{
	struct module *i;

	fprintf(out, "# pci module         vendor     device     subvendor"
		"  subdevice  class      class_mask driver_data\n");

	for (i = modules; i; i = i->next) {
		struct pci_device_id *e;
		char shortname[strlen(i->pathname) + 1];

		if (!i->pci_table)
			continue;

		make_shortname(shortname, i->pathname);
		for (e = i->pci_table; e->vendor; e = (void *)e + i->pci_size)
			output_pci_entry(e, shortname, out, i->conv);
	}
}

/* We set driver_info to zero */
static void output_usb_entry(struct usb_device_id *usb, char *name, FILE *out,
			     int conv)
{
	fprintf(out, "%-20s 0x%04x      0x%04x   0x%04x    0x%04x"
		"       0x%04x       0x%02x         0x%02x"
		"            0x%02x            0x%02x"
		"            0x%02x               0x%02x"
		"               0x0\n",
		name,
		END(usb->match_flags, conv),
		END(usb->idVendor, conv),
		END(usb->idProduct, conv),
		END(usb->bcdDevice_lo, conv),
		END(usb->bcdDevice_hi, conv),
		END(usb->bDeviceClass, conv),
		END(usb->bDeviceSubClass, conv),
		END(usb->bDeviceProtocol, conv),
		END(usb->bInterfaceClass, conv),
		END(usb->bInterfaceSubClass, conv),
		END(usb->bInterfaceProtocol, conv));
}

void output_usb_table(struct module *modules, FILE *out)
{
	struct module *i;

	fprintf(out, "# usb module         ");
	/* Requires all users to be on kernel 2.4.0 or later */
	fprintf(out, "match_flags ");
	fprintf(out, "idVendor idProduct bcdDevice_lo bcdDevice_hi"
		" bDeviceClass bDeviceSubClass bDeviceProtocol"
		" bInterfaceClass bInterfaceSubClass"
		" bInterfaceProtocol driver_info\n");

	for (i = modules; i; i = i->next) {
		struct usb_device_id *e;
		char shortname[strlen(i->pathname) + 1];

		if (!i->usb_table)
			continue;

		make_shortname(shortname, i->pathname);
		for (e = i->usb_table; 
		     e->idVendor || e->bDeviceClass || e->bInterfaceClass;
		     e = (void *)e + i->usb_size)
			output_usb_entry(e, shortname, out, i->conv);
	}
}

static void output_ieee1394_entry(struct ieee1394_device_id *fw, char *name,
				  FILE *out, int conv)
{
	fprintf(out, "%-20s 0x%08x  0x%06x  0x%06x 0x%06x     0x%06x\n",
		name,
		END(fw->match_flags, conv),
		END(fw->vendor_id, conv),
		END(fw->model_id, conv),
		END(fw->specifier_id, conv),
		END(fw->version, conv));
}

void output_ieee1394_table(struct module *modules, FILE *out)
{
	struct module *i;

	fprintf(out, "# ieee1394 module    ");
	fprintf(out, "match_flags vendor_id model_id specifier_id version\n");

	for (i = modules; i; i = i->next) {
		struct ieee1394_device_id *fw;
		char shortname[strlen(i->pathname) + 1];

		if (!i->ieee1394_table)
			continue;

		make_shortname(shortname, i->pathname);
		for (fw = i->ieee1394_table; fw->match_flags;
		     fw = (void *) fw + i->ieee1394_size)
			output_ieee1394_entry(fw, shortname, out, i->conv);
	}
}


/* We set driver_data to zero */
static void output_ccw_entry(struct ccw_device_id *ccw, char *name, FILE *out,
			     int conv)
{
	fprintf(out, "%-20s 0x%04x      0x%04x  0x%02x      0x%04x  0x%02x\n",
		name, END(ccw->match_flags, conv),
		END(ccw->cu_type, conv),  END(ccw->cu_model, conv),
		END(ccw->dev_type, conv), END(ccw->dev_model, conv));
}

void output_ccw_table(struct module *modules, FILE *out)
{
	struct module *i;

	fprintf(out, "# ccw module         ");
	fprintf(out, "match_flags cu_type cu_model dev_type dev_model\n");

	for (i = modules; i; i = i->next) {
		struct ccw_device_id *e;
		char shortname[strlen(i->pathname) + 1];

		if (!i->ccw_table)
			continue;

		make_shortname(shortname, i->pathname);
		for (e = i->ccw_table;
		     e->cu_type || e->cu_model || e->dev_type || e->dev_model;
		     e = (void *) e + i->ccw_size)
			output_ccw_entry(e, shortname, out, i->conv);
	}
}

#define ISAPNP_VENDOR(a,b,c)	(((((a)-'A'+1)&0x3f)<<2)|\
				((((b)-'A'+1)&0x18)>>3)|((((b)-'A'+1)&7)<<13)|\
				((((c)-'A'+1)&0x1f)<<8))
#define ISAPNP_DEVICE(x)	((((x)&0xf000)>>8)|\
				 (((x)&0x0f00)>>8)|\
				 (((x)&0x00f0)<<8)|\
				 (((x)&0x000f)<<8))

static void put_isapnp_id(FILE *out, const char *id)
{
	unsigned short vendor, device;

	vendor = ISAPNP_VENDOR(id[0], id[1], id[2]);
	device = (unsigned short)strtol(&id[3], NULL, 16);
	device = ISAPNP_DEVICE(device);
	fprintf(out, " 0x%04x     0x%04x    ", vendor, device);
}

void output_isapnp_table(struct module *modules, FILE *out)
{
	struct module *i;

	fprintf(out, "# isapnp module      ");
	fprintf(out, "cardvendor carddevice driver_data vendor     function   ...\n");

	for (i = modules; i; i = i->next) {
		char shortname[strlen(i->pathname) + 1];

		if (i->pnp_table) {
			struct pnp_device_id *id;
			make_shortname(shortname, i->pathname);
			for (id = i->pnp_table;
			     id->id[0];
			     id = (void *)id + i->pnp_size) {
				fprintf(out, "%-20s", shortname);
				fprintf(out, " 0xffff     0xffff    ");
				fprintf(out, " 0x00000000 "); /* driver_data */
				put_isapnp_id(out, id->id);
				fprintf(out, "\n");
			}
		}
		if (i->pnp_card_table) {
			void *id;
			make_shortname(shortname, i->pathname);
			for (id = i->pnp_card_table;
			     ((char *)id)[0];
			     id += i->pnp_card_size) {
				int idx;
				struct pnp_card_devid *devid
					= id + i->pnp_card_offset;

				fprintf(out, "%-20s", shortname);
				put_isapnp_id(out, id);
				fprintf(out, " 0x00000000 "); /* driver_data */
				for (idx = 0; idx < 8; idx++) {
					if (!devid->devid[idx][0])
						break;
					put_isapnp_id(out, devid->devid[idx]);
				}
				fprintf(out, "\n");
			}
		}
	}
}

#define MATCH_bustype   1
#define MATCH_vendor    2
#define MATCH_product   4
#define MATCH_version   8

#define MATCH_evbit     0x010
#define MATCH_keybit    0x020
#define MATCH_relbit    0x040
#define MATCH_absbit    0x080
#define MATCH_mscbit    0x100
#define MATCH_ledbit    0x200
#define MATCH_sndbit    0x400
#define MATCH_ffbit     0x800
#define MATCH_swbit     0x1000

#define MATCH(x) (END(input->match_flags, conv) & MATCH_ ## x)
#define PRINT_SCALAR(n) fprintf(out, "  0x%lx", MATCH(n) ? END(input->n, conv) : 0l)
#define PRINT_ARRAY64(n) do {						    \
	fprintf(out, "  ");						    \
	if (MATCH(n))							    \
		output_input_bits_64(out, input->n, sizeof(input->n), conv); \
	else								    \
		fprintf(out, "%d", 0);					    \
	} while (0)

#define PRINT_ARRAY32(n) do {						    \
	fprintf(out, "  ");						    \
	if (MATCH(n))							    \
		output_input_bits_32(out, input->n, sizeof(input->n), conv); \
	else								    \
		fprintf(out, "%d", 0);					    \
	} while (0)

static void output_input_bits_32(FILE *out, unsigned int *bits, int size,
				 int conv)
{
	int i, j;

	size /= sizeof(*bits);
	for (i = size - 1; i >= 0; i--)
		 if (END(bits[i], conv))
			 break;
	if (i < 0)
		i = 0;
	fprintf(out, "%x", END(bits[i], conv));
	for (j = i - 1; j >= 0; j--)
		fprintf(out, ":%x", END(bits[j], conv));
}

static void output_input_bits_64(FILE *out, unsigned long long *bits, int size,
				 int conv)
{
	int i, j;

	size /= sizeof(*bits);
	for (i = size - 1; i >= 0; i--)
		 if (END(bits[i], conv))
			 break;
	if (i < 0)
		i = 0;
	fprintf(out, "%llx", END(bits[i], conv));
	for (j = i - 1; j >= 0; j--)
		fprintf(out, ":%llx", END(bits[j], conv));
}

/* Formats are too different to */
static int output_input_entry_32(struct input_device_id_32 *input,
				 char *name, FILE *out, int conv)
{
	if (!input->match_flags && !input->driver_info)
		return 1;

	fprintf(out, "%-20s0x%x", name, END(input->match_flags, conv));

	PRINT_SCALAR(bustype);
	PRINT_SCALAR(vendor);
	PRINT_SCALAR(product);
	PRINT_SCALAR(version);

	PRINT_ARRAY32(evbit);
	PRINT_ARRAY32(keybit);
	PRINT_ARRAY32(relbit);
	PRINT_ARRAY32(absbit);
	PRINT_ARRAY32(mscbit);
	PRINT_ARRAY32(ledbit);
	PRINT_ARRAY32(sndbit);
	PRINT_ARRAY32(ffbit);
	PRINT_ARRAY32(swbit);

	fprintf(out, "  0x%x\n", END(input->driver_info, conv));
	return 0;
}

static int output_input_entry_32_old(struct input_device_id_old_32 *input,
				     char *name, FILE *out, int conv)
{
	if (!input->match_flags && !input->driver_info)
		return 1;

	fprintf(out, "%-20s0x%x", name, END(input->match_flags, conv));

	PRINT_SCALAR(bustype);
	PRINT_SCALAR(vendor);
	PRINT_SCALAR(product);
	PRINT_SCALAR(version);

	PRINT_ARRAY32(evbit);
	PRINT_ARRAY32(keybit);
	PRINT_ARRAY32(relbit);
	PRINT_ARRAY32(absbit);
	PRINT_ARRAY32(mscbit);
	PRINT_ARRAY32(ledbit);
	PRINT_ARRAY32(sndbit);
	PRINT_ARRAY32(ffbit);

	fprintf(out, "  0x%x\n", END(input->driver_info, conv));
	return 0;
}

static int output_input_entry_64(struct input_device_id_64 *input,
				 char *name, FILE *out, int conv)
{
	if (!input->match_flags && !input->driver_info)
		return 1;

	fprintf(out, "%-20s0x%llx", name, END(input->match_flags, conv));

	PRINT_SCALAR(bustype);
	PRINT_SCALAR(vendor);
	PRINT_SCALAR(product);
	PRINT_SCALAR(version);

	PRINT_ARRAY64(evbit);
	PRINT_ARRAY64(keybit);
	PRINT_ARRAY64(relbit);
	PRINT_ARRAY64(absbit);
	PRINT_ARRAY64(mscbit);
	PRINT_ARRAY64(ledbit);
	PRINT_ARRAY64(sndbit);
	PRINT_ARRAY64(ffbit);
	PRINT_ARRAY64(swbit);

	fprintf(out, "  0x%llx\n", END(input->driver_info, conv));
	return 0;
}

static int output_input_entry_64_old(struct input_device_id_old_64 *input,
				     char *name, FILE *out, int conv)
{
	if (!input->match_flags && !input->driver_info)
		return 1;

	fprintf(out, "%-20s0x%llx", name, END(input->match_flags, conv));

	PRINT_SCALAR(bustype);
	PRINT_SCALAR(vendor);
	PRINT_SCALAR(product);
	PRINT_SCALAR(version);

	PRINT_ARRAY64(evbit);
	PRINT_ARRAY64(keybit);
	PRINT_ARRAY64(relbit);
	PRINT_ARRAY64(absbit);
	PRINT_ARRAY64(mscbit);
	PRINT_ARRAY64(ledbit);
	PRINT_ARRAY64(sndbit);
	PRINT_ARRAY64(ffbit);

	fprintf(out, "  0x%llx\n", END(input->driver_info, conv));
	return 0;
}

void output_input_table(struct module *modules, FILE *out)
{
	struct module *i;

	fprintf(out, "# module         matchBits");
	fprintf(out, " bustype vendor product version evBits keyBits relBits");
	fprintf(out, " absBits mscBits ledBits sndBits ffBits [swBits] driver_info\n");

	for (i = modules; i; i = i->next) {
		void *p;
		char shortname[strlen(i->pathname) + 1];
		int done = 0;

		if (!i->input_table)
			continue;

		make_shortname(shortname, i->pathname);
		/* Guess what size it really is, based on size of
		 * whole table.  Table changed in 2.6.14.  This is a hack. */
		if (i->input_size == sizeof(struct input_device_id_old_64)) {
			if ((i->input_table_size % i->input_size) != 0) {
				i->input_size
					= sizeof(struct input_device_id_64);
			}
		} else {
			if ((i->input_table_size % i->input_size) != 0) {
				i->input_size
					= sizeof(struct input_device_id_32);
			}
		}

		for (p = i->input_table; !done; p += i->input_size) {
			switch (i->input_size) {
			case sizeof(struct input_device_id_old_64):
				done = output_input_entry_64_old(p,
								 shortname,
								 out,
								 i->conv);
				break;
			case sizeof(struct input_device_id_64):
				done = output_input_entry_64(p, shortname,
							     out, i->conv);
				break;
			case sizeof(struct input_device_id_old_32):
				done = output_input_entry_32_old(p,
								 shortname,
								 out,
								 i->conv);
				break;
			case sizeof(struct input_device_id_32):
				done = output_input_entry_32(p, shortname,
							     out, i->conv);
				break;
			}
		}				
	}
}

static void output_serio_entry(struct serio_device_id *serio, char *name, FILE *out)
{
	fprintf(out,
		"%-20s 0x%02x 0x%02x  0x%02x 0x%02x\n",
		name,
		serio->type,
		serio->extra,
		serio->id,
		serio->proto);
}


void output_serio_table(struct module *modules, FILE *out)
{
	struct module *i;

	fprintf(out, "# serio module       type extra id   proto\n");

	for (i = modules; i; i = i->next) {
		struct serio_device_id *e;
		char shortname[strlen(i->pathname) + 1];

		if (!i->serio_table)
			continue;

		make_shortname(shortname, i->pathname);
		for (e = i->serio_table; e->type || e->proto; e = (void *)e + i->serio_size)
			output_serio_entry(e, shortname, out);
	}
}


static void
strip_whitespace (char *str, char chr)
{
	int i;
	if (!str)
		return;
	for (i = strlen (str); i >= 0; --i)
		if (isspace (*str))
			*str = chr;
}

/* We set driver_data to zero */
static void output_of_entry(struct of_device_id *dev, char *name, FILE *out)
{
	char *ofname = NULL, *type = NULL, *compatible = NULL;
	if (dev->name[0]) {
		ofname = strdup (dev->name);
		strip_whitespace (ofname, '_');
	}

	if (dev->type[0]) {
		type = strdup (dev->type);
		strip_whitespace (type, '_');
       }

	if (dev->compatible[0]) {
		compatible = strdup (dev->compatible);
		strip_whitespace (compatible, '_');
	}

        fprintf (out, "%-20s %-20s %-20s %s\n",
                name, ofname ? ofname : "*", type ? type : "*",
                compatible ? compatible : "*");
}

void output_of_table(struct module *modules, FILE *out)
{
	struct module *i;

        fprintf (out, "# of module          name                 type                 compatible\n");                                 
	for (i = modules; i; i = i->next) {
		struct of_device_id *e;
		char shortname[strlen(i->pathname) + 1];

		if (!i->of_table)
			continue;

		make_shortname(shortname, i->pathname);
		for (e = i->of_table; e->name[0]|e->type[0]|e->compatible[0];
                     e = (void *)e + i->of_size)
			output_of_entry(e, shortname, out);
	}
}
