#ifndef __FIRMWARE_H__
#define __FIRMWARE_H__

typedef struct
{
	unsigned long crc;
	unsigned long length;
	const char *id;
} stusb_firmware_id_t;


typedef struct
{
	unsigned char *phase1;
	unsigned char *phase2;
	unsigned long phase1_length;
	unsigned long phase2_length;
} stusb_firmware_t;

stusb_firmware_t *
extract_firmware(const char *boot_file, const char *firm_file, int rev4);

void
free_firmware(stusb_firmware_t *f);

#endif
