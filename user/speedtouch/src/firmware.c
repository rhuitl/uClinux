/*
*  ALCATEL SpeedTouch USB modem microcode extract utility
*  Copyright (C) 2001 Benoit PAPILLAULT
*  
*  This program is free software; you can redistribute it and/or
*  modify it under the terms of the GNU General Public License
*  as published by the Free Software Foundation; either version 2
*  of the License, or (at your option) any later version.
*  
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*  
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*
*  Author   : Edouard Gomez <ed.gomez@free.fr>
*  Creation : 14/02/2004
*
*  Searching for the microcode is done in a two step process:
*   - the boot code.
*   - the main firmware.
*
*  The bootcode is always loaded at 0x00000000 in the modem RAM, so we look for
*  this base address mixed in a special file format signature. The end of the
*  boot code is marked by a command that tells the ARM to jump at the base
*  address and execute (aka boot)
*
*  The base address of the main firmware depends on the modem revision (as of
*  2004-02-14, only rev4 is different). The end pattern is also a jump command.
*
* $Id: firmware.c,v 1.4 2004/02/17 21:45:17 edgomez Exp $
*/

#ifndef _FIRMWARE_C_
#define _FIRMWARE_C_

#include "modem.h"
#include "pppoa3.h"
#include "crc.h"
#include "firmware.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/*****************************************************************************
* Local Prototypes
*****************************************************************************/

static stusb_firmware_t *
extract_firmware_phase(const char *file,
		       const unsigned char *start_pattern,
		       const unsigned char *end_pattern,
		       const int pattern_length,
		       const stusb_firmware_id_t *ids);
static int
search_pattern(const unsigned char *buffer,
	       const unsigned char *pattern,
	       const int buffer_length,
	       const int pattern_length);

static unsigned char *
load_file(const char * file, int * size);

/******************************************************************************
*	Main Lib Function
******************************************************************************/

/*
 * Function    : check_firmware
 * Results     : return 1 if the firmware is OK, 0 otherwise.
 * Description : check that the firmware found is valid
 */

int check_firmware(unsigned char * buf, int len)
{
	unsigned char * current_block;
	int remaining_len;

	unsigned int addr;
	unsigned int size, extra_size;

	int boot_block_seen = 0;
	int last_block_seen = 0;

	current_block = buf;
	remaining_len = len;

	while (remaining_len > 0) {
		if (remaining_len < 8) {
			/* not enougth data to make a block, abort */
			return(0);
		}

		addr =	 current_block[2]      | (current_block[3]<<8) |
			(current_block[4]<<16) | (current_block[5]<<24);

		size	   = current_block[6] | (current_block[7]<<8);
		extra_size = current_block[1] | ((current_block[0]&0x80)<<1);

		switch (current_block[0]) {
		case 0x08:
		case 0x88:
			/* determine the type of block */
			if (extra_size <= 0x1f8 && extra_size > 6) {
				/* last data block & last data block */
				if (boot_block_seen || last_block_seen)
					return 0;

				if (extra_size < 0x1f8)
					last_block_seen = 1;

				if (extra_size != size + 6)
					return 0;

				/* skip over header */
				current_block += 2;
				remaining_len -= 2;
		
				if (remaining_len < extra_size)
					return(0);
		
				/* skip over data */
				current_block += extra_size;
				remaining_len -= extra_size;
		
				if (remaining_len < 3)
					return(0);
		
				if (current_block[0] != 0x40 ||
				    current_block[1] != 0x01 ||
				    current_block[2] != 0x12)
					return(0);
		
				/* skip over trailer */
				current_block += 3;
				remaining_len -= 3;
			} else if (extra_size == 4) {
				/* boot block */
				if (boot_block_seen)
					return(0);

				boot_block_seen = 1;

				/* skip over header */
				current_block += 2;
				remaining_len -= 2;
		
				if (remaining_len < extra_size)
					return(0);
		
				/* skip over data */
				current_block += extra_size;
				remaining_len -= extra_size;
		
				if (remaining_len < 3)
					return(0);
		
				if (current_block[0] != 0x00 ||
				    current_block[1] != 0x01 ||
				    current_block[2] != 0x14)
					return(0);
		
				/* skip over trailer */
				current_block += 3;
				remaining_len -= 3;
			} else {
				/* unknown block again, abort */
				return(0);
			}

			break;
		default:
			/* unknown block, abort */
			return(0);
		}
	}

	return(1);
}

/*
* Function     : extract_microcode
* Return Value : NULL on error
*                valid pointer to the microcode on success
* Description  : We are searching for the best match of a start and end
*                sequence.
*                Those sequence delimits the microcode. You won't get 100%
*                probability, but it will work anyway, for all the microcode
*                I've tested.
*/

#define PATTERN_LENGTH 8

stusb_firmware_t *
extract_firmware(const char *file1, const char *file2, int rev4)
{
	/* Specific byte sequences that mark the start/end of the encapsulated ARM code in firmware files */
	const unsigned char boot_patterns[2][PATTERN_LENGTH] = {
		/* The base address is always 0x00000000 */
		{0x88, 0xf8, 0x00, 0x00, 0x00, 0x00, 0xf2, 0x01}, /* start */
		{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x14}  /* stop */
	};

	const unsigned char firm_patterns[2][2][PATTERN_LENGTH] = {
		{    /* The base address is 0x00400000 */
			{0x88, 0xf8, 0x00, 0x40, 0x00, 0x00, 0xf2, 0x01},  /* start for stusb rev 1,2,3 */
			{0x04, 0x00, 0x40, 0x00, 0x00, 0x00, 0x01, 0x14}  /* stop for stusb rev 1,2,3 */
		}, { /* The base address is 0x00000010 */
			{0x88, 0xf8, 0x00, 0x00, 0x00, 0x10, 0xf2, 0x01},  /* start for stusb rev 4 */
			{0x04, 0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x14}  /* stop for stusb rev 4 */
		}
	};

	const stusb_firmware_id_t stusb_phase1_ids[] = {
		{0xd3e33990, 883, "Ian's Free Software Boot block"},
		{0xd80bf9f7, 991, "Alcatel/Thomson Boot block (old)"},
		{0x69636579, 935, "Alcatel/Thomson Boot block (new)"},
		{0x00000000, 0, NULL}
	};

	const stusb_firmware_id_t stusb_phase2_ids[] = {
		{0xae3ff81f, 526239, "1.3.1 - GNU/Linux"},
		{0xa719bc0e, 523436, "1.3.1 - Win32"},
		{0x94a45435, 526187, "1.3.3 - GNU/Linux - Win32"},
		{0x61914198, 527093, "1.4.0 - Win32(3.0.1800)"},
		{0x37c189ed, 527752, "1.4.0 - Win32(4.0.100)"},
		{0x99cc1c1a, 528738, "1.4.2 - Win32(2.0.500)"},
		{0xe0251a5e, 671665, "1.6.1 - Win32(5.0.1801)"},
		{0x3b4a5854, 671653, "1.6.1 - MacOSX - Win32(1.0.1800)"},
		{0xd673923f, 672264, "2.0.0 - Win32(07)"},
		{0x5bca7d16, 677641, "2.0.1 - MacOSX - Win32(2.0.0)"},
		{0x78039fed, 762650, "3.0.6 - MacOSX - Win32"},
		{0x698eb734, 761389, "3.0.0 - Win32"},
		{0xd7864c39, 774192, "3.0.0 - Win32 (rev 4)"},
		{0x0223733c, 775509, "1.0.10 - Win32 Rev 0400 SACHU3"},
		{0x41d4143c, 775545, "0.0.0 - testing firmware from Thomson"},
		{0x00000000, 0, NULL}
	};

	stusb_firmware_t *boot, *firmware;

	if (file2 == NULL) return(NULL);

	/* If we are not passed a phase1 file, try to find it in the phase2
	 * file. It was the usual way firmwares were packed together in olds
	 * alcatel/thomson drivers */
	if (file1 == NULL) file1 = file2;

	/* Extract the phase1 (boot block) part */
	boot = extract_firmware_phase(file1,
				      boot_patterns[0],
				      boot_patterns[1],
				      PATTERN_LENGTH,
				      stusb_phase1_ids);

	/* Extract the modem's firmware now */
	firmware =  extract_firmware_phase(file2,
					   firm_patterns[(rev4)?1:0][0],
					   firm_patterns[(rev4)?1:0][1],
					   PATTERN_LENGTH,
					   stusb_phase2_ids);

	/* firmware is used as the returned value, it MUST be valid */
	if (firmware == NULL) {
		free_firmware(boot);
		return(NULL);
	}

	/* Data is now loaded, put it where it belongs to
	 * NB: - phase1 slot may be empty, it's up to the caller to fill it with
	 *       default boot block
	 *     - phase2 slot is mandatory and triggers an error if it's missing */
	firmware->phase2 = firmware->phase1;
	firmware->phase2_length = firmware->phase1_length;
	firmware->phase1 = (boot!=NULL)?boot->phase1:NULL;
	firmware->phase1_length = (boot!=NULL)?boot->phase1_length:0;

	/* Free allocated structure (if any) but not the its fields */
	if (boot) free(boot);

	return(firmware);
}

static stusb_firmware_t *
extract_firmware_phase(const char *file,
		       const unsigned char *start_pattern,
		       const unsigned char *stop_pattern,
		       const int pattern_length,
		       const stusb_firmware_id_t *ids)
{
	unsigned char *buf;
	int start_offset, length;
	stusb_firmware_t *firmware;

	length = 0;
	start_offset = 0;

	/* Loads the file into memory (yes, it's a lame, why not a mmap ?) */
	if ((buf = load_file(file, &length)) == NULL)
		return(NULL);

	/* Searches the start and end offsets */
	start_offset = search_pattern(buf,
				      start_pattern,
				      length,
				      pattern_length);
	if (start_offset < 0) {
		free(buf);
		return(NULL);
	}

	length  = search_pattern(buf + start_offset,
				 stop_pattern,
				 length - start_offset,
				 pattern_length);
	if (length < 0) {
		free(buf);
		return(NULL);
	}

	/* We must add the pattern length to obtain the real length */
	length += PATTERN_LENGTH;

	/* Initialize the returned firmware struct */
	if ((firmware = malloc(sizeof(stusb_firmware_t))) == NULL) {
		free(buf);
		return(NULL);
	}
	memset(firmware, 0, sizeof(stusb_firmware_t));

	if ((firmware->phase1 = malloc(length)) == NULL) {
		free(firmware);
		free(buf);
		return(NULL);
	}

	/* Copy the data into the returned firmware
	 * Data is put into phase1 fields -- The caller function may then do
	 * whatever it likes with this data. */
	memcpy(firmware->phase1, buf+start_offset, length);
	firmware->phase1_length = length;

	/* We don't need the file buffer anymore */
	free(buf);

	{
		unsigned long crc;
		const stusb_firmware_id_t *id = ids;
		const char *idstr =
			"Unknown revision - Please report the CRC "
			"and length with the revision number to "
			"speedtouch@ml.free.fr";
		int checked;

		/* Computes this value once */
		crc = ~aal5_calc_crc(firmware->phase1, firmware->phase1_length,~0);

		/* Browse the "known" firmware array */
		while (id->length != 0) {
			if(id->length == length && id->crc == crc) {
				idstr = id->id;
				break;
			}
			id++;
		}

		checked = check_firmware(firmware->phase1,
					 firmware->phase1_length);

#ifndef STANDALONE_EXTRACTER
		report(1, REPORT_INFO,
		       "Firmware info (CRC:0x%08x, Size:%d, Checked: %s, %s)\n",
		       crc, length, checked?"Yes":"No",idstr);
#else
		printf("Firmware info (CRC:0x%08x, Size:%d, Checked: %s, %s)\n",
		       crc, length, checked?"Yes":"No",idstr);
#endif
	}
	/* Returns a pointer to the start adress */
	return(firmware);
}

/*****************************************************************************
*	Local sub routines
*****************************************************************************/

/*
* Function     : load_file
* Return Value : null in case of error
*                a pointer to a buffer allocated using malloc() on success
* NB           : *size contains the returned buffer size
*/

static unsigned char *
load_file(const char * file, int * size)
{
	struct stat statbuf;
	int len;
	unsigned char * buf;
	int fd;

	*size = 0;

	/* Opens the file */
	if ((fd = open(file, O_RDONLY)) < 0) {
		perror(file);
		return(NULL);
	}

	/* Retrieves file informations */
	 if (fstat(fd, &statbuf) != 0) {
		perror("stat");
		return(NULL);
	}

	/* Gets length */
	len = statbuf.st_size;

	/* Allocates the buffer */
	if((buf = (unsigned char *)malloc(len)) == NULL) {
		perror("malloc");
		close (fd);
		return(NULL);
	}

	/* Read all contents in buffer */
	if (read(fd, buf, len) != len) {
		perror(file);
		free (buf);
		close (fd);
		return(NULL);
	}

	/* Closes the file */
	close(fd);

	/* Sets size */
	*size = len;

	return(buf);

}

/*
* Function     : search_match
* Return value : -1 in case of error
*                best match offset on success
* Description  : Search for the longest match of buf2 inside buf1.
*
*/
static int
search_pattern(const unsigned char *buffer,
	       const unsigned char *pattern,
	       const int buffer_length,
	       const int pattern_length)
{
	/* Number of bytes match with pattern */
	int best_match = 0;

	/* Best offset*/
	int best_offset = -1;

	/* Zone where the pattern can reside */
	int potential_length = (buffer_length - pattern_length + 1);

	/* Loop counter */
	int cur_offset;

	for(cur_offset=0; cur_offset< potential_length; cur_offset++) {
		int i;
		int cur_match;

		/* Compute the matching number of bytes at this offset */
		for(i=0, cur_match=0;i<pattern_length;i++)
			if (buffer[cur_offset+i] == pattern[i])
				cur_match++;

		/* Compare to the best known matching offset */
		if(cur_match > best_match) {
			best_offset = cur_offset;
			best_match  = cur_match;

			/* Stops as soon as a perfect match is found */
			if (best_match == pattern_length)
				break;
		}
	}

#ifndef STANDALONE_EXTRACTER
	report(1, REPORT_INFO, "Best offset %6d with probability %3d%%\n",
	       best_offset,
	       (100*best_match)/pattern_length);
#endif
	return((best_match == pattern_length)?best_offset:-1);
}

void
free_firmware(stusb_firmware_t *f)
{
	if (f) {
		if (f->phase1) {
			free(f->phase1);
			f->phase1 = NULL;
			f->phase1_length = 0;
		}
		if (f->phase2) {
			free(f->phase2);
			f->phase2 = NULL;
			f->phase2_length = 0;
		}
		free(f);
	}
}

/******************************************************************************
* A main function to test the extract function
******************************************************************************/

#ifdef STANDALONE_EXTRACTER

#include "crc.c"

void usage(char *progname)
{
	fprintf(stderr,	"Usage: %s [boot file] <firmware file>\n\n", progname);
}

void extract_new(char *file);

int
main(int argc, char *argv[])
{
	char *file1 = NULL;
	char *file2 = NULL;
	stusb_firmware_t *firmware;

	if (argc != 2 && argc != 3) {
		usage(argv[0]);
		return(-1);
	}

	/* Binds filenames where they belong */
	file2 = argv[argc-1];
	file1 = (argc==2)? file2 : argv[argc-2];

	/* Get the firmware */
	firmware = extract_firmware(file1, file2, 0);
	if (firmware == NULL) firmware = extract_firmware(file1, file2, 1);

	/* Report to user all informations that can be useful */
	printf("** Boot block from %s:\n", file1);
	if (firmware && firmware->phase1) {
		int o;
		printf("   CRC: 0x%08x\n", ~aal5_calc_crc(firmware->phase1, firmware->phase1_length,~0));
		printf("   Length: %d\n", (int)firmware->phase1_length);
		o = open("boot.bin", O_CREAT|O_WRONLY|O_TRUNC, 0644);
		if (o != -1) {
			write(o, firmware->phase1, firmware->phase1_length);
			close(o);
		}
	} else {
		printf("   Not found\n");
	}

	printf("** Firmware block from %s:\n", file2);
	if (firmware && firmware->phase2) {
		int o;
		printf("   CRC: 0x%08x\n", ~aal5_calc_crc(firmware->phase2, firmware->phase2_length,~0));
		printf("   Length: %d\n", (int)firmware->phase2_length);
		o = open("firmware.bin", O_CREAT|O_WRONLY|O_TRUNC, 0644);
		if (o != -1) {
			write(o, firmware->phase2, firmware->phase2_length);
			close(o);
		}
	} else {
		printf("   Not found\n");
	}

	/* Free the firmware */
	free_firmware(firmware);

	return(0);
}

#endif /* STANDALONE_EXTRACTER */

#endif /* #ifndef _FIRMWARE_C_ */
