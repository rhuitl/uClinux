/*********************************************************************
 *
 * Copyright:
 *	MOTOROLA, INC. All Rights Reserved.  
 *  You are hereby granted a copyright license to use, modify, and
 *  distribute the SOFTWARE so long as this entire notice is
 *  retained without alteration in any modified and/or redistributed
 *  versions, and that such modified versions are clearly identified
 *  as such. No licenses are granted by implication, estoppel or
 *  otherwise under any patents or trademarks of Motorola, Inc. This 
 *  software is provided on an "AS IS" basis and without warranty.
 *
 *  To the maximum extent permitted by applicable law, MOTOROLA 
 *  DISCLAIMS ALL WARRANTIES WHETHER EXPRESS OR IMPLIED, INCLUDING 
 *  IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR
 *  PURPOSE AND ANY WARRANTY AGAINST INFRINGEMENT WITH REGARD TO THE 
 *  SOFTWARE (INCLUDING ANY MODIFIED VERSIONS THEREOF) AND ANY 
 *  ACCOMPANYING WRITTEN MATERIALS.
 * 
 *  To the maximum extent permitted by applicable law, IN NO EVENT
 *  SHALL MOTOROLA BE LIABLE FOR ANY DAMAGES WHATSOEVER (INCLUDING 
 *  WITHOUT LIMITATION, DAMAGES FOR LOSS OF BUSINESS PROFITS, BUSINESS 
 *  INTERRUPTION, LOSS OF BUSINESS INFORMATION, OR OTHER PECUNIARY
 *  LOSS) ARISING OF THE USE OR INABILITY TO USE THE SOFTWARE.   
 * 
 *  Motorola assumes no responsibility for the maintenance and support
 *  of this software
 ********************************************************************/

/*
 * File:		cbi.c
 * Purpose:		Client Demo Application for the CBI Class
 */

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/vfs.h>
#include <dirent.h>
#include <grp.h>
#include <signal.h>
#include <unistd.h>

#include "usb.h"
#include "descriptors.h"
#include "cbi.h"
#include "uftp_def.h"

/********************************************************************/
//#define DEBUG

#define usb_ep_wait(ep_file)   (ioctl(ep_file, USB_EP_WAIT, 0))

/********************************************************************/

/* Global USB Descriptor Data (application specific) */
extern USB_DEVICE_DESC Descriptors;
extern USB_STRING_DESC string_desc;

uint8 cb[COMMAND_BUFFER_LENGTH];
DEVICE_COMMAND dc;

QUEUE_ITEM * BegQ;
QUEUE_ITEM * EndQ;

uint8 command_block[COMMAND_BUFFER_LENGTH];

uint32 transfer_length = 4096;

int usb_dev_file;
int usb_ep1_file;
int usb_ep2_file;
int usb_ep3_file;

/* Functions that execute commands from the host */
void do_command_read(uint8 *);
			/* Send file to host */
void do_command_write(uint8 *);
			/* Receive file from host */
void do_command_get_file_info(uint8 *);
		/* Send the length of file to host */
void do_command_get_dir(void);
			/* Send the list of files to host */
void do_command_set_transfer_length(uint8 *);
	/* Set transfer length */
void do_command_delete(uint8 *);
		/* Delete file */

static void
 accept_event(int);			/* Asynchronous notification handler */

uint32
 fetch_command(uint8 *)
;
uint32 
get_string_descriptor(uint8 desc_index,
				uint16 languageID, 
				uint16 length)
;
/********************************************************************/
int main (void)
{
uint32 i;
DESC_INFO device_desc;
struct sigaction act;
unsigned int oflags;

	#ifdef DEBUG
		printf("DEBUG prints ON\n");
	#endif

	/* Open device files */	
	usb_dev_file = open(USB_EP0_FILE_NAME, O_RDWR);		/* Control endpoint (ep0) */
        if (usb_dev_file < 0) {
    	    printf ("Can't open device file: %s\n", USB_EP0_FILE_NAME);
    	    exit(-1);
	}
	usb_ep1_file = open(USB_EP1_FILE_NAME, O_WRONLY);	/* Bulk In endpoint (ep1) */
        if (usb_ep1_file < 0) {
    	    printf ("Can't open device file: %s\n", USB_EP1_FILE_NAME);
	    close(usb_dev_file);
    	    exit(-1);
	}
	usb_ep2_file = open(USB_EP2_FILE_NAME, O_RDONLY);	/* Bulk Out endpoint (ep2) */
        if (usb_ep2_file < 0) {
    	    printf ("Can't open device file: %s\n", USB_EP2_FILE_NAME);
	    close(usb_dev_file);
	    close(usb_ep1_file);
    	    exit(-1);
	}
	usb_ep3_file = open(USB_EP3_FILE_NAME, O_WRONLY);	/* Interrupt endpoint (ep3) */
        if (usb_ep3_file < 0) {
    	    printf ("Can't open device file: %s\n", USB_EP3_FILE_NAME);
	    close(usb_dev_file);
	    close(usb_ep1_file);
	    close(usb_ep2_file);
    	    exit(-1);
	}
	
	/* Enable asynchronous notification and setup handler */
	act.sa_handler = &accept_event;
	/* act.sa_mask = 0; */
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGIO, &act, NULL);

	fcntl(usb_dev_file, F_SETOWN, getpid());
	oflags = fcntl(usb_dev_file, F_GETFL);
	fcntl(usb_dev_file, F_SETFL, oflags | FASYNC);

	/* Initialize command buffer */
	dc.cbuffer = cb;
	
	/* Initialize USB driver */
	device_desc.pDescriptor = (uint8 *) &Descriptors;
	device_desc.DescSize = usb_get_desc_size();

	printf("Initializing USB driver...");
        ioctl(usb_dev_file, USB_INIT, (char *)&device_desc);
	printf("done.\n"); 

	while(1)
	{
	/* Wait for the next command from the host */
		if (fetch_command(command_block) == USB_NEW_COMMAND)
		{
			switch (command_block[0])
			{
				case UFTP_READ:
					#ifdef DEBUG
						printf("Command UFTP_READ has been recognized by client\n");
					#endif
					do_command_read(command_block);
					break;
					
				case UFTP_WRITE:
					#ifdef DEBUG
						printf("Command UFTP_WRITE has been recognized by client\n");
					#endif
					do_command_write(command_block);
					break;
					
				case UFTP_GET_FILE_INFO:
					#ifdef DEBUG
						printf("Command UFTP_GET_FILE_INFO has been recognized by client\n");
					#endif
					do_command_get_file_info(command_block);
					break;
					
				case UFTP_GET_DIR:
					#ifdef DEBUG
						printf("Command UFTP_GET_DIR has been recognized by client\n");
					#endif
					do_command_get_dir();
					break;
				
				case UFTP_SET_TRANSFER_LENGTH:
					#ifdef DEBUG
						printf("Command UFTP_SET_TRANSFER_LENGTH has been recognized by client\n");
					#endif
					do_command_set_transfer_length(command_block);
					break;
					
				case UFTP_DELETE:
					#ifdef DEBUG
						printf("Command UFTP_DELETE has been recognized by client\n");
					#endif
					do_command_delete(command_block);
					break;

			}	/* switch */
		}		/* if (fetch_command(command_block)) */
	}			/* while */
	return (0);
}

/********************************************************************/
void
do_command_read(uint8 * combuf)
{
uint16 status;
uint32 size;
uint32 padded_bytes;

uint8 * buffer1;
uint8 * buffer2;
uint8 * bufptr;

FILE * file_desc;
char file_name[256];
char tmpname[256]; 

/* Structure of command UFTP_READ:
	combuf[0] - operation code (1 byte), UFTP_READ;
	combuf[1] - length of file name (1 byte), fname_length;
	combuf[2 : fname_length-1] - name of file without zero at the end of string (fname_length bytes), fname;
*/
        
	memcpy(file_name, (char*)&(combuf[2]), combuf[1]);
	file_name[combuf[1]] = 0;
	sprintf(tmpname, "%s%s", USB_DIR, file_name);
	file_desc = fopen(tmpname, "rb");

	#ifdef DEBUG
		printf("file name = %s\n\n", tmpname);
	#endif

	/* Check if given file exists */
	if (!file_desc)
	{
		#ifdef DEBUG
			printf("File does not exist\n");
		#endif
		
		status = UFTP_FILE_DOES_NOT_EXIST;
		
		usb_ep_wait(usb_ep3_file);
		write(usb_ep3_file, (uint8 *)(&status), 2);
		return;
	}
	
	padded_bytes = (transfer_length & 0x3);
	if (padded_bytes != 0)
		padded_bytes = 4 - padded_bytes;

	/* Allocate memory for intermediate buffers */
	buffer1 = (uint8 *) malloc(2*transfer_length + padded_bytes);
	if (buffer1 == NULL)
	{
		#ifdef DEBUG
			printf("Memory allocation fail\n");
		#endif
		
		status = UFTP_MEMORY_ALLOCATION_FAIL;
		
		usb_ep_wait(usb_ep3_file);
		write(usb_ep3_file, (uint8 *)(&status), 2);
		fclose(file_desc);
		return;
	}
	buffer2 = buffer1 + transfer_length + padded_bytes;
		
	/* Send status to Host via interrupt endpoint */
	status = UFTP_SUCCESS;
	
	if (usb_ep_wait(usb_ep3_file) < 0)
	{
		free(buffer1);
		fclose(file_desc);
		return;
	}
	if (write(usb_ep3_file, (uint8 *)(&status), 2) < 0)
	{
		free(buffer1);
		fclose(file_desc);
		return;
	}
		
	/* The status was O.K. We can send data to Host*/
	bufptr = buffer1;
	size = transfer_length;
	while (size == transfer_length)
	{	
		/* Copy next portion of data from file into buffer */
		size = fread(bufptr, 1, transfer_length, file_desc);
		/* If at least one byte was coppied into buffer, send it ... */
		if (size > 0)
		{
			/* Wait, while endpoint BULK IN is busy. The previous transfer might not be completed.
 */
			/* If transfer completed successfully usb_ep_wait() returns number
			of bytes transferred or negative value in other case */
			if (usb_ep_wait(usb_ep1_file) < 0)
			{
				free(buffer1);
				fclose(file_desc);
				return;
			}
			
			/* Send buffer through BULK IN endpoint*/
			if (write(usb_ep1_file, bufptr, size) < 0)
			{
				free(buffer1);
				fclose(file_desc);
				return;
			}

			/* write() has returned control, but it doesn't mean that the transfer is completed */
			/* We should change pointer to other buffer in order to send first buffer correctly */
			if (bufptr == buffer1)
				bufptr = buffer2;
			else
				bufptr = buffer1;
				
		}
	}

	usb_ep_wait(usb_ep1_file);
	
	free(buffer1);
	fclose(file_desc);
}

/********************************************************************/
void
do_command_write(uint8 * combuf)
{
uint32 flength = 0;
uint8 * pflength;
uint8 fname[FILE_NAME_LENGTH];
uint32 padded_bytes;

uint16 status;
uint8 * buffer1;
uint8 * buffer2;
uint8 * bufptr;
long int pos = 0, size = 0, buf_size = 0;

FILE * file_desc;
char file_name[256];
char tmpname[256]; 
char tmpname2[256]; 
uint32 ret_value;
struct statfs stat_buf;

/* Structure of command UFTP_WRITE:
	combuf[0] - operation code (1 byte), UFTP_WRITE;
	combuf[1 : 4] - length of file (4 bytes), flength;
	combuf[5] - length of file name (1 byte), fname_length;
	combuf[6 : fname_length-1] - name of file without zero at the end of string (fname_length bytes), fname;
*/
        
	/* PC-Host sends us dword with reverse ordered bytes.
	   We have to reorder bytes in flength. */
	pflength = (uint8 *) &flength;
	pflength[0] = combuf[4];
	pflength[1] = combuf[3];
	pflength[2] = combuf[2];
	pflength[3] = combuf[1];
	/* flength contains correct length of file now. */

	memcpy(file_name, (char*)&(combuf[6]), combuf[5]);
	file_name[combuf[5]] = 0;

	#ifdef DEBUG
		printf("file name = %s%s, file length = %u\n\n", USB_DIR, file_name, flength);
	#endif

	padded_bytes = (transfer_length & 0x3);
	if (padded_bytes != 0)
		padded_bytes = 4 - padded_bytes;

	/* Allocate memory for intermediate buffer(s) */
	if ((long int) (flength <= transfer_length))
		buffer1 = (uint8 *) malloc(flength);
	else
		buffer1 = (uint8 *) malloc(2 * transfer_length + padded_bytes);
	
	if (flength && buffer1 == NULL)
	{
		#ifdef DEBUG
			printf("Memory allocation fail\n");
		#endif
		
		status = UFTP_MEMORY_ALLOCATION_FAIL;
		
		usb_ep_wait(usb_ep3_file);
		write(usb_ep3_file, (uint8 *)(&status), 2);
		
		return;
	}
	buffer2 = buffer1 + transfer_length + padded_bytes;

	/* Check for free space for the new file */
	sprintf(tmpname,"%s", USB_DIR);
	ret_value = statfs(tmpname, &stat_buf);
	if ((ret_value == -1) || ((int)(stat_buf.f_bsize * (stat_buf.f_bfree-1)) < (int)flength)
			      || (stat_buf.f_ffree == 0))
	{
		#ifdef DEBUG
			printf("Not enough space for the file\n");
		#endif
		
		status = UFTP_NOT_ENOUGH_SPACE_FOR_FILE;
		
		usb_ep_wait(usb_ep3_file);
		write(usb_ep3_file, (uint8 *)(&status), 2);
		
		free(buffer1);
		
		return;
	}
	/* Get full path of the file */
	sprintf(tmpname, "%s%s", USB_DIR, file_name);
	/* If file already exists we will overwrite it */
	file_desc = fopen(tmpname, "bw+");
	
	/* If we are here, it means that everything is O.K. We are ready to receive file data from Host.
	   Tell Host about it using interrupt endpoint */
	status = UFTP_SUCCESS;
	
	if (usb_ep_wait(usb_ep3_file) < 0)
	{
		free(buffer1);
		fclose(file_desc);
		unlink(tmpname);
		return;
	}
	if (write(usb_ep3_file, (uint8 *)(&status), 2) < 0)
	{
		free(buffer1);
		fclose(file_desc);
		unlink(tmpname);
		return;
	}
	
	/* Initialize pointer to current buffer */
	bufptr = buffer1;
	
	while (pos < flength)
	{
		/* Wait, while endpoint BULK OUT is busy.
		   Then start receiving data into current buffer. */
		if (usb_ep_wait(usb_ep2_file) < 0)
		{
			free(buffer1);
			fclose(file_desc);
			unlink(tmpname);
			return;
		}  

		if ((long int)(flength - pos - size) >= transfer_length)
			size = transfer_length;
		else
			size = flength - pos - size;
  
		if (read(usb_ep2_file, bufptr, size) < 0)
		{
			free(buffer1);
			fclose(file_desc);
			unlink(tmpname);
			return;
		}
		
		/* Change pointer to previous buffer. */
		if (bufptr == buffer1)
			bufptr = buffer2;
		else
			bufptr = buffer1;

		/* Write data from previous buffer into the file. */
		fwrite(bufptr, 1, buf_size, file_desc);

		pos += buf_size;

		buf_size = size;
		/* On a new iteration of the loop previous buffer becomes current buffer and current buffer
	    	becomes previous buffer */
	}
	
	free(buffer1);
	fclose(file_desc);
}

/********************************************************************/
void
do_command_get_file_info(uint8 * combuf)
{
uint32 flength;
uint8 * pflength;
uint8 * pfiles_length;

uint16 status;

char file_name[256];
char tmpname[256];
struct stat file_status;
uint32 file_length;

/* Structure of command UFTP_GET_FILE_INFO:
	combuf[0] - operation code (1 byte), UFTP_GET_FILE_INFO;
	combuf[1] - length of file name (1 byte), fname_length;
	combuf[2 : fname_length-1] - name of file without zero at the end of string (fname_length bytes), fname;
*/
	memcpy(file_name, (char*)&combuf[2], combuf[1]);
	file_name[combuf[1]] = 0;
	sprintf(tmpname, "%s%s", USB_DIR, file_name);
	
	/* Check if given file exists */
	if (stat(tmpname, &file_status)<0)
	{
		#ifdef DEBUG
			printf("File does not exist\n");
		#endif
		
		status = UFTP_FILE_DOES_NOT_EXIST;
		
		usb_ep_wait(usb_ep3_file);
		
		write(usb_ep3_file, (uint8 *)(&status), 2);

		return;
	}
	file_length = file_status.st_size;
	#ifdef DEBUG
		printf("file name = %s, file length = %u\n\n", tmpname, file_length);
	#endif
	
	/* Send 'good' status to Host using interrupt endpoint */
	status = UFTP_SUCCESS;
	
	if (usb_ep_wait(usb_ep3_file) < 0)
		return;
		
	if (write(usb_ep3_file, (uint8 *)(&status), 2) < 0)
		return;
	
	/* Send length of file to Host using BULK IN endpoint */
	/* We need to reorder it for PC-Host, because it reads length of file as dword */
	pflength = (uint8 *) &flength;
	pfiles_length = (uint8 *) &(file_length);
	pflength[0] = pfiles_length[3];
	pflength[1] = pfiles_length[2];
	pflength[2] = pfiles_length[1];
	pflength[3] = pfiles_length[0];
	
	if (usb_ep_wait(usb_ep1_file) < 0)
		return;
		
	if (write(usb_ep1_file, (uint8 *)(&flength), 4) < 0)
		return;
		
	/* We have to wait until file length will be sent.
	   After returning back from subroutine stack pointer changes its value
	   and variable flength may be changed by other routine */
	usb_ep_wait(usb_ep1_file);
}

/********************************************************************/
void
do_command_get_dir(void)
{
uint32 files_count = 0;
uint8 info_buffer[8];
uint32 total_fname_len = 0;
uint8 * pinfo;
uint32 i = 0;
uint16 status;
uint8 fname_length;
uint8 * dir_buffer;

DIR *dirp;
struct	dirent	*dp;
struct stat file_status;
char tmpname[256];

	/* Count transfer length of directory contents */
	dirp = opendir(USB_DIR);
	if (dirp == NULL) {
		perror(USB_DIR);
	}
		while ((dp = readdir(dirp)) != NULL) {
		if (dp->d_name[0] != '.') {
		    sprintf(tmpname, "%s%s", USB_DIR, dp->d_name);
		    if (stat(tmpname, &file_status)>=0) {
			if (!S_ISDIR(file_status.st_mode)) {
			    files_count ++;
			    /* One byte for the length of file name */
			    total_fname_len ++;

			    /* Number of bytes needed for name of file */
			    total_fname_len += strlen(dp->d_name);
			}
		    }
		}    
	}
	closedir(dirp);

	/* Reorder total_fname_len for PC-Host */
	pinfo = (uint8 *) &total_fname_len;
	info_buffer[0] = pinfo[3];
	info_buffer[1] = pinfo[2];
	info_buffer[2] = pinfo[1];
	info_buffer[3] = pinfo[0];
	
	/* Reorder files_count for PC-Host */
	pinfo = (uint8 *) &files_count;
	info_buffer[4] = pinfo[3];
	info_buffer[5] = pinfo[2];
	info_buffer[6] = pinfo[1];
	info_buffer[7] = pinfo[0];
	
	/* Allocate buffer to store length of file name and file name for each file in it */
	dir_buffer = (uint8 *) malloc(total_fname_len);
	if (total_fname_len && dir_buffer == NULL)
	{
		#ifdef DEBUG
			printf("Memory allocation failed (%d bytes)\n", total_fname_len);
		#endif

		status = UFTP_MEMORY_ALLOCATION_FAIL;

		usb_ep_wait(usb_ep3_file);
		write(usb_ep3_file, (uint8 *)(&status), 2);

		return;
	}

	/* Send status to Host using interrupt endpoint */
	status = UFTP_SUCCESS;
	
	if (usb_ep_wait(usb_ep3_file) < 0)
	{
		free(dir_buffer);
		return;
	}
		
	if (write(usb_ep3_file, (uint8 *)(&status), 2) < 0)
	{
		free(dir_buffer);
		return;
	}
	
	/* Fill directory buffer with length of file name and file name for each file */
	dirp = opendir(USB_DIR);
	if (dirp == NULL) {
		perror(USB_DIR);
	}
	while ((dp = readdir(dirp)) != NULL) {
	
		if (dp->d_name[0] != '.') {
		    sprintf(tmpname, "%s%s", USB_DIR, dp->d_name);
		    stat(tmpname, &file_status);
		    if (stat(tmpname, &file_status)>=0) {
			if (!S_ISDIR(file_status.st_mode)) {
			    /* Store length of file name into directory buffer */
			    fname_length = strlen(dp->d_name);
			    dir_buffer[i++] = fname_length;
			
			    /* Store name of file into directory buffer */
			    memcpy(&dir_buffer[i],dp->d_name, fname_length);
			    i += fname_length;
			}	
		    }
		}    
	}
	closedir(dirp);
	
	/* Send length of directory buffer to Host */
	if (usb_ep_wait(usb_ep1_file) < 0)
	{
		free(dir_buffer);
		return;
	}
	
	if (write(usb_ep1_file, info_buffer, sizeof(info_buffer)) < 0)
	{
		free(dir_buffer);
		return;
	}
	
	if (total_fname_len > 0)
	{
		/* Send directory buffer to Host */
		if (usb_ep_wait(usb_ep1_file) < 0)
		{
			free(dir_buffer);
			return;
		}
		
		if (write(usb_ep1_file, dir_buffer, total_fname_len) < 0)
		{
			free(dir_buffer);
			return;
		}
	}
	
	/* We have to wait until buffer is sent.
 */
	usb_ep_wait(usb_ep1_file);
	
	free(dir_buffer);
}

/********************************************************************/
void
do_command_set_transfer_length(uint8 * combuf)
{
uint16 status;
uint8 * ptlength;
uint8 tmplen[4];
/* Structure of command UFTP_SET_TRANSFER_LENGTH:
	combuf[0] - operation code (1 byte), UFTP_SET_TRANSFER_LENGTH;
	combuf[1 : 4] - length of transfer (1 byte), transfer_length;
*/

	/* Send status to Host using interrupt endpoint */
	status = UFTP_SUCCESS;
	
	if (usb_ep_wait(usb_ep3_file) < 0)
		return;
		
	if (write(usb_ep3_file, (uint8 *)(&status), 2) < 0)
		return;
	
	/* PC-Host sends us dword with reverse ordered bytes.
	   We have to reorder bytes in transfer_length. */
	   
	ptlength = (uint8 *) &transfer_length;
	ptlength[0] = combuf[4];
	ptlength[1] = combuf[3];
	ptlength[2] = combuf[2];
	ptlength[3] = combuf[1];
	#ifdef DEBUG
		printf("new transfer length = %u\n", transfer_length);
	#endif
}

/********************************************************************/
void do_command_delete(uint8 * combuf)
{
uint32 flength;
uint8 * pflength;
uint8 * pfiles_length;

uint16 status;

FILE * file_desc;
char file_name[256];
char tmpname[256]; 

/* Structure of command UFTP_DELETE:
	combuf[0] - operation code (1 byte), UFTP_DELETE;
	combuf[1] - length of file name (1 byte), fname_length;
	combuf[2 : fname_length-1] - name of file without zero at the end of string (fname_length bytes), fname;
*/

	/* Check if given file exists */
	memcpy(file_name, (char*)&(combuf[2]), combuf[1]);
	file_name[combuf[1]] = 0;
	sprintf(tmpname, "%s%s", USB_DIR, file_name);
	file_desc = fopen(tmpname, "rb");
	#ifdef DEBUG
		printf("file name = %s\n\n", tmpname);
	#endif

	if (! file_desc)
	{
		#ifdef DEBUG
			printf("File does not exist\n");
		#endif
		
		status = UFTP_FILE_DOES_NOT_EXIST;
	}
	else
	{
		fclose(file_desc);
		unlink(tmpname);
		status = UFTP_SUCCESS;
	}
	
	/* Send status to Host using interrupt endpoint */
	if (usb_ep_wait(usb_ep3_file) < 0)
		return;

	write(usb_ep3_file, (uint8 *)(&status), 2);

}
/********************************************************************/
static void
accept_event(int sig)
{
QUEUE_ITEM * TempC;
uint32 event;

	event = ioctl(usb_dev_file, USB_GET_COMMAND, &dc);

	if (event & USB_NEW_COMMAND)
	{
		/* Test if this command is a request for string descriptor */
		if ((dc.request.bmRequestType == 0x80) &&
		    (dc.request.bRequest == GET_DESCRIPTOR) &&
		    ((dc.request.wValue >> 8) == STRING))
		{
			get_string_descriptor(dc.request.wValue & 0xFF,
						dc.request.wIndex,
						dc.request.wLength);
			return;
		}
	
		/* Test, if client application supports this command */
		if ((dc.request.bmRequestType != 0x21) || (dc.request.bRequest != 0))
		{
		    ioctl(usb_dev_file, USB_NOT_SUPPORTED_COMMAND);
		    return;
		}

		if ((dc.cbuffer[0] < UFTP_READ) || (dc.cbuffer[0] > UFTP_DELETE))
		{
		    ioctl(usb_dev_file, USB_NOT_SUPPORTED_COMMAND);
		    return;
		}
	
		/* Put command to the Queue */
		TempC = (QUEUE_ITEM * )malloc(sizeof(QUEUE_ITEM) + (dc.request.wLength));
	
		if (TempC == NULL)
		{
		    ioctl(usb_dev_file, USB_NOT_SUPPORTED_COMMAND);
		    return;
		}
	
		TempC -> cbuffer = (uint8 *)TempC + sizeof(QUEUE_ITEM);

		memcpy(TempC -> cbuffer, dc.cbuffer, dc.request.wLength);
		memcpy((uint8 *) &(TempC -> request.bmRequestType), (uint8 *) &(dc.request.bmRequestType), sizeof(REQUEST));

		TempC -> NextC = NULL;

		/* Place NewCQ into Command Queue now */
		if (EndQ != NULL)
			EndQ -> NextC = TempC;
				
		EndQ = TempC;
				
		if (BegQ == NULL)
			BegQ = TempC;

		ioctl(usb_dev_file, USB_COMMAND_ACCEPTED);
		return;
	}
}

/********************************************************************/
uint32 
get_string_descriptor(uint8 desc_index,
	uint16 languageID, 
uint16 length)
{
uint16 i = 0;

uint8 * stdesc;
uint32 size;

	if (string_desc == NULL)
	{
	    ioctl(usb_dev_file, USB_NOT_SUPPORTED_COMMAND);
	    return;
	}
	
	if (desc_index != 0) 
	{
		/* Reorder bytes in languageID parameter */
		i = languageID;
		languageID <<=8;
		i >>= 8;
		languageID = i | languageID;
	
		i = 0;
		
		/* Point stdesc to first languageID in the string descriptor index 0 */
		stdesc = (uint8 *) string_desc + 2;
		
		/* Find index of required langugeID */
		while (( (* (uint16 *) stdesc) != languageID) && (i < NUM_LANGUAGES))
		{
			stdesc += 2;
			i++;
		}
	}
	
	if ((desc_index > NUM_STRING_DESC) || (i == NUM_LANGUAGES))
	{
	    ioctl(usb_dev_file, USB_NOT_SUPPORTED_COMMAND);
	    return;
	}
	else
	{
		/* Point stdesc to required descriptor */
		if (desc_index)
		{
			i *= NUM_STRING_DESC;
			i += desc_index;
			stdesc = (uint8 *) &(string_desc[i]);
		}
		else
			stdesc = (uint8 *) &(string_desc[0]);
		
		/* Get size of that descriptor */
		size = *stdesc;
	
		/* Modify length of transfer (if needed) */
		if (size >= length)
			size = length;
		else
			ioctl(usb_dev_file, USB_SET_SEND_ZLP);
	
		/* Send descriptor to Host */
		write(usb_dev_file, stdesc, size);

		return;
	}
}
/********************************************************************/
uint32
fetch_command(uint8 * dcb)
{
QUEUE_ITEM * TempC;
/* sigset_t mask = (1 << SIGIO); */
sigset_t mask;
sigemptyset(&mask);
sigaddset(&mask,1<<SIGIO);

/* sigsuspend() may be used to make client sleep while there is no new command. */
/* We just use busy waiting here */
	while (BegQ == NULL)
/*		sigsuspend(&mask)*/;

	TempC = BegQ;
	BegQ = TempC -> NextC;
	if (BegQ == NULL)
		EndQ = NULL;

	/* Extract the new command from the queue */
	memcpy (dcb, TempC -> cbuffer,  TempC -> request.wLength);
	free(TempC);
	
	return USB_NEW_COMMAND;
}
