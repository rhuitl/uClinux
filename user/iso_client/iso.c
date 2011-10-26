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
 * File:		iso.c
 * Purpose:		ISO Client Demo Application for the USB Device Driver
 */

#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <unistd.h>

#include "descriptors.h"
#include "iso.h"
#include "usb.h"

/********************************************************************/
/* Buffer definition for tests (5 packets x 160 bytes + 20 bytes header) */
typedef struct {
	uint32 packet_length[5];
	uint8 databuf[800];
} iso_test_buffer;

/* Buffer definition for main task (20 packets x 90 bytes + 80 bytes header)*/
typedef struct {
	uint32 packet_length[20];
	uint8 databuf[1800];
} audio_buffer;

iso_test_buffer *buffers;
	
/* These variables are used by client application in test mode
   (when program performs tests).
 */
uint32 start_isotest_inout_stream = FALSE;
uint32 start_isotest_in_stream = FALSE;
uint32 start_isotest_out_stream = FALSE;

/* These variables are used by client application
   during execution the main task.
 */
uint32 start_main_task = FALSE;
uint32 stop_main_task = FALSE;

/* Device files */
int usb_dev_file;
int usb_ep1_file;
int usb_ep2_file;

uint8 * databuf;

uint16 volume = 0x7FFF;

/* Indicates current sample rate */
/* For 8 KHz packet_size == 16, for 44.1 KHz packet_size == 90 */
uint32 packet_size;

/* Global USB Descriptor Data (application specific) */
extern USB_DEVICE_DESC Descriptors;
extern USB_STRING_DESC string_desc;

uint8 command_block[COMMAND_BUFFER_LENGTH];
uint8 cb[COMMAND_BUFFER_LENGTH];
DEVICE_COMMAND dc;

/* Called whenever Host reads string descriptors from device */
uint32 get_string_descriptor(uint8, uint16, uint16);

/* Handles events and retrieves commands from driver */
static void
 accept_event(int);

void main_task(void);
void test_case1_handler(void);
void test_case2_handler(void);
void test_case3_handler(void);

void init_buffer_headers(iso_test_buffer *);
void init_audio_headers(audio_buffer *);
void print_transfer_status(iso_test_buffer *);
void print_buffer_contents(iso_test_buffer *);
void clear_buffer(void);
void buffer_init(iso_test_buffer *);
void process_data (audio_buffer *);
/********************************************************************/
int main (void)
{
unsigned int oflags;
DESC_INFO device_desc;
struct sigaction act;
uint32 i;

	/* Open device files */	
	usb_dev_file = open(USB_EP0_FILE_NAME, O_RDWR);		/* Control endpoint (ep0) */
        if (usb_dev_file < 0) {
    	    printf ("Can't open device file: %s\n", USB_EP0_FILE_NAME);
    	    exit(-1);
	}
	usb_ep1_file = open(USB_EP1_FILE_NAME, O_WRONLY);	/* Isochronous In endpoint (ep1) */
        if (usb_ep1_file < 0) {
    	    printf ("Can't open device file: %s\n", USB_EP1_FILE_NAME);
	    close(usb_dev_file);
    	    exit(-1);
	}
	usb_ep2_file = open(USB_EP2_FILE_NAME, O_RDONLY);	/* Isochronous Out endpoint (ep2) */
        if (usb_ep2_file < 0) {
    	    printf ("Can't open device file: %s\n", USB_EP2_FILE_NAME);
	    close(usb_dev_file);
	    close(usb_ep1_file);
    	    exit(-1);
	}
	
	/* Register Asynchronous notification handler */
	act.sa_handler = &accept_event;
	/* act.sa_mask = 0; */
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGIO, &act, NULL);

	fcntl(usb_dev_file, F_SETOWN, getpid());
	oflags = fcntl(usb_dev_file, F_GETFL);
	fcntl(usb_dev_file, F_SETFL, oflags | FASYNC);


	/* Initialize USB driver */
	device_desc.pDescriptor = (uint8 *) &Descriptors;
	device_desc.DescSize = usb_get_desc_size();

	/* Initialize command buffer */
	dc.cbuffer = cb;

	printf("Initializing USB driver...");
        ioctl(usb_dev_file, USB_INIT, (char *)&device_desc);
	printf("done.\n"); 

	databuf = (uint8*)malloc(32768);
	if (!databuf) printf("Can't allocate memory\n");

	while(TRUE)
	{
		/* Start loopback task, it is the main task of the program */	
		if (start_main_task)
		{
			start_main_task = FALSE;
			main_task();
		}
	
		/* Do data OUT test transfers */
		if (start_isotest_out_stream)
		{
			start_isotest_out_stream = FALSE;
			test_case1_handler();
		}

		/* Do data IN test transfers */
		if (start_isotest_in_stream)
		{
			start_isotest_in_stream = FALSE;
			test_case2_handler();
		}

		/* Do data IN and OUT test transfers */
		if (start_isotest_inout_stream)
		{
			start_isotest_inout_stream = FALSE;
			test_case3_handler();
		}
	}

	free(databuf);
	return (0);
}
/********************************************************************/
void
accept_event(int sig)
{

uint16 start_frame_number;
uint16 final_frame_number;
CONFIG_STATUS current_config;
uint32 event;

	/* Get event number from the driver */
	event = ioctl(usb_dev_file, USB_GET_COMMAND, &dc);
	
	/* If new command has arrived - process it */
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


		/* Set volume */
		if (	(dc.request.bRequest == USB_AUDIO_SET_VOLUME) &&
			(dc.request.wValue == 0) &&
			(dc.request.wIndex == 0) &&
			(dc.request.wLength == 2))
		{
			/* This is an example of data OUT command. */
			/* Host sent new multiplication factor to the Device */

			volume = *(uint16 *)dc.cbuffer;
			/* Swap the bytes in multiplication factor */
			volume = (volume << 8) | (volume >> 8);

			/* Notify Host that the command is accepted */
			ioctl(usb_dev_file, USB_COMMAND_ACCEPTED);
			
			return;
		}	


		/* Start IN transfers test */
		if (	(dc.request.bRequest == START_TEST_IN_TRANSFER) &&
			(dc.request.wValue == 0) &&
			(dc.request.wIndex == 0) &&
			(dc.request.wLength == 2))
		{
			/* This is an example of data IN command. */
			/* Host asks the Device from what number of frame */
			/* device will be ready to start receiving test data. */

			/* Data stream will be started with this delay (required by Host) */
			start_frame_number = 75 + (uint32)ioctl(usb_dev_file, USB_GET_FRAME_NUMBER);
			if (start_frame_number > 2047)
					start_frame_number -= 2048;
	
			/* Determine the number of frame in which test data IN stream stops.
			(25 packets Host will sent to the Device) */
			final_frame_number = start_frame_number + 25;
			if (final_frame_number > 2047)
					final_frame_number -= 2048;

			/* Send number of start frame to Host */
			
write(usb_dev_file, (uint8 *)&start_frame_number, 2);

			/* Tell to Driver from what number of frame data IN stream starts/stops. */
			ioctl(usb_ep1_file, USB_SET_START_FRAME, start_frame_number);
			ioctl(usb_ep1_file, USB_SET_FINAL_FRAME, final_frame_number);

			/* Set this variable to start execution in the main() function. */
			start_isotest_in_stream = TRUE;
		
			return;
		}


		/* Start OUT transfers test */
		if (	(dc.request.bRequest == START_TEST_OUT_TRANSFER) &&
			(dc.request.wValue == 0) &&
			(dc.request.wIndex == 0) &&
			(dc.request.wLength == 2))
		{
			/* This is an example of data IN command. */
			/* Host asks the Device from what number of frame */
			/* device will be ready to start sending test data. */

			/* Data stream will be started with this delay (required by Host) */
			start_frame_number = 70 + (uint32)ioctl(usb_dev_file, USB_GET_FRAME_NUMBER);
			if (start_frame_number > 2047)
					start_frame_number -= 2048;
	
			final_frame_number = start_frame_number + 25;
			if (final_frame_number > 2047)
					final_frame_number -= 2048;

			/* Send number of start frame to Host */
			
write(usb_dev_file, (uint8 *)&start_frame_number, 2);

			/* Tell to Driver from what number of frame data OUT stream stats/stops. */
			ioctl(usb_ep2_file, USB_SET_START_FRAME, start_frame_number);
			ioctl(usb_ep2_file, USB_SET_FINAL_FRAME, final_frame_number);

			/* Set this variable to start execution in the main() function. */
			start_isotest_out_stream = TRUE;
		
			return;
		}


		/* Start IN & OUT transfers test */
		if (	(dc.request.bRequest == START_TEST_INOUT_TRANSFER) &&
			(dc.request.wValue == 0) &&
			(dc.request.wIndex == 0) &&
			(dc.request.wLength == 2))
		{
			/* This is an example of data IN command. */
			/* Host asks the Device from what number of frame */
			/* device will be ready to start sending and receiving test data. */

			/* Data stream will be started with this delay (required by Host) */
			start_frame_number = 70 + (uint32)ioctl(usb_dev_file, USB_GET_FRAME_NUMBER);
			if (start_frame_number > 2047)
					start_frame_number -= 2048;
	
			final_frame_number = start_frame_number + 25;
			if (final_frame_number > 2047)
					final_frame_number -= 2048;

			/* Send number of start frame to Host */
			
write(usb_dev_file, (uint8 *)&start_frame_number, 2);

			/* Tell to Driver from what number of frame data IN/OUT streams start/stop. */
			ioctl(usb_ep1_file, USB_SET_START_FRAME, start_frame_number);
			ioctl(usb_ep2_file, USB_SET_START_FRAME, start_frame_number);
			ioctl(usb_ep1_file, USB_SET_FINAL_FRAME, final_frame_number);
	
		ioctl(usb_ep2_file, USB_SET_FINAL_FRAME, final_frame_number);

			/* Set this variable to start execution in the main() function. */
			start_isotest_inout_stream = TRUE;
		
			return;
		}


		/* Start loopback task */
		if (	(dc.request.bRequest == USB_AUDIO_START) &&
			(dc.request.wValue == 0) &&
			(dc.request.wIndex == 0) &&
			(dc.request.wLength == 2))
		{
			/* 	This is an example of data IN command. */
			/*	Host asks the Device from what number of frame */
			/*	device will be ready to start sending and receiving data. */

			/* Data stream will be started with this delay (required by Host) */
			start_frame_number = 50 + (uint32)ioctl(usb_dev_file, USB_GET_FRAME_NUMBER);
			if (start_frame_number > 2047)
					start_frame_number -= 2048;
	
			/* Send number of start frame to Host */
			
write(usb_dev_file, (uint8 *)&start_frame_number, 2);

			/* Tell to Driver from what number of frame data IN/OUT streams start. */
			ioctl(usb_ep1_file, USB_SET_START_FRAME, start_frame_number);
			ioctl(usb_ep2_file, USB_SET_START_FRAME, start_frame_number);

			/* Set this variable to start execution in the main() function. */
			start_main_task = TRUE;
		
			return;
		}


		/* Stop data replay */
		if (	(dc.request.bRequest == USB_AUDIO_STOP) &&
			(dc.request.wValue == 0) &&
			(dc.request.wIndex == 0) &&
			(dc.request.wLength == 0))
		{
			/* This is an example of NO DATA stage command. */
			/* Host wants to stop loopback task. */

			final_frame_number = (uint32)ioctl(usb_dev_file, USB_GET_FRAME_NUMBER) + 20;
			if (final_frame_number > 2047)
					final_frame_number -= 2048;

			/* Tell to Driver from what number of frame data IN/OUT streams stop. */
			ioctl(usb_ep1_file, USB_SET_FINAL_FRAME, final_frame_number);
	
		ioctl(usb_ep2_file, USB_SET_FINAL_FRAME, final_frame_number);

			/* Set this variable to stop execution of main_task() function */
			stop_main_task = TRUE;
			
			/* Notify Host that the command is accepted */
			ioctl(usb_dev_file, USB_COMMAND_ACCEPTED);

			return;
		}

		
		/* If we are here than received command is not supported */
		ioctl(usb_dev_file, USB_NOT_SUPPORTED_COMMAND);
        	printf ("Unsupported command.\n");
	}

	/* Host has changed configuration of device (set new alt setting number) */
    	if (event & USB_CONFIGURATION_CHG)
	{
		/* Is used during execution of loopback task */

		/* Set up appropriate length of transfer for 8kHz sample rate
		(10 packets x 8 samples x 2 bytes per sample) */
		ioctl(usb_dev_file, USB_GET_CURRENT_CONFIG, &current_config);
		if (current_config.altsetting == 1)
			packet_size = 16;
		
		/* Set up appropriate length of transfer for 44.1kHz sample rate
		(9 packets x 45 samples x 2 bytes per sample + 1 packet x 36 samples x 2 bytes per sample) */
		if (current_config.altsetting == 2)
			packet_size = 90;

		return;
	}

	/* Bus RESET has occured */
    	if (event & USB_DEVICE_RESET)
	{
	    /* Reset signal may be processed here */
	}

	return;
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
/***************************************************************/
void
print_transfer_status(iso_test_buffer* buffer)
{
uint32 i, j;

	printf("\nCompletion results of Isochronous transfer:\n");
	printf("Packet#     Size\n");
	
	for (j = 0; j < 5; j ++)
		for (i = 0; i < 5; i ++)
			printf(" %-12d%-12d\n", j*5+i, buffer[j].packet_length[i]);
}

/********************************************************************/
void
print_buffer_contents(iso_test_buffer* buffer)
{
uint32 i, k, l = 0;

	/* Prints first 10 characters of each received packet of each buffer */
	printf("Contents of data buffer:\n");

	for (i = 0; i < 25; i ++)
	{
		printf("Packet %d:\n", i);
		
			for (l = 0; l < 10; l++)
				printf("%d ", buffer[i/5].databuf[(i%5)*160+l]);

		printf("...\n");
	}
}
/********************************************************************/
void
init_buffer_headers(iso_test_buffer* buffer)
{
uint32 i;
	/* Each data buffer (IN and OUT) has a header. Header contains
	size of each packet that must be sent/received. After transfer completion
	it contains a real size of read/written packet */
	
	/* Initializes packet_length fields of data buffer */
	for (i = 0; i < 5; i ++)
		buffer->packet_length[i] = 0xA0;
}
/********************************************************************/
void
init_audio_headers(audio_buffer* buffer)
{
uint16 i;
	/* Initializes packet_length fields of audio data buffer */
	for (i = 0; i < 20; i ++)
		buffer->packet_length[i] = packet_size;

	/* For 44.1 KHz sample rate we need 9 packets of 90 bytes length
	+ 1 of 72 bytes. Each buffer contains 20 packets. */
	if (packet_size == 90)
	{
		buffer->packet_length[9] = 72;
		buffer->packet_length[19] = 72;
	}
}
/********************************************************************/
void
clear_buffer(void)
{
uint32 i;

	for (i = 0; i < 16384; i += 4)
		*(uint32 *)(&databuf[i]) = 0;
}
/********************************************************************/
void
buffer_init(iso_test_buffer* buffer)
{
uint8 i, j;

	/* Fills test buffer with data.
	The size of packet is 160 bytes during performing the test 
	transfers (alternate setting 3).
	The first packet will have "100"s, second - "101", etc. */

	for (i = 0; i < 25; i ++)
		for (j = 0; j < 160; j ++)
			buffer[i/5].databuf[(i%5)*160+j] = i + 100;
}

/********************************************************************/
/* ISO OUT test *****************************************************/
void
test_case1_handler(void)
{
uint8 i;

	buffers = (iso_test_buffer*) databuf;
	
	/* Clear target data buffer */
	clear_buffer();

	for (i = 0; i < 5; i ++)
	{
		/* Init headers of each buffer */
		init_buffer_headers(&buffers[i]);
		/* Put requests in queue. Read 5 packets into each of 5 buffers */
		read(usb_ep2_file, (uint8*)(&buffers[i]), 5);
	}

	/* Client program asks Driver to read data from 5 frames.
	But in this point data stream is not started yet.
	Thus Driver will start to count 5 frames from the frame in which
	it starts a stream, not from the current frame. */

	/* So, these calls returned control, but no data is read yet, and data stream is not started.
	But it allocated a buffer, where Driver will place data. Driver will start stream in a frame,
	specified in usb_set_start_frame ioctl. After starting a stream, Driver reads data
	from 5 frames into the buffer and then extracts next request from the queue. */

	/* Wait while transfer is in progress */
	ioctl(usb_ep2_file, USB_EP_WAIT, 0);
			
	/* Show results */
	print_buffer_contents(buffers);
	print_transfer_status(buffers);
	
}
/* ISO IN test *****************************************************/
void
test_case2_handler(void)
{
uint8 i;

	buffers = (iso_test_buffer*) databuf;

	/* Initialize source data buffer */
	buffer_init(buffers);

	for (i = 0; i < 5; i ++)
	{
		/* Init headers of each buffer */
		init_buffer_headers(&buffers[i]);
		/* Put requests in queue. Write 5 packets from each of 5 buffers */
		write(usb_ep1_file, (uint8*)(&buffers[i]), 5);
	}

	/* Client program asks Driver to send 5 buffers of 800 bytes (5 packets x 160 bytes per packet).
	But in this point data stream is not started yet. Thus Driver will start sending data
	when Host will send IN-token (from the frame specified in USB_SET_START_FRAME ioctl).*/
			
	/* Wait while transfer is in progress */
	ioctl(usb_ep1_file, USB_EP_WAIT, 0);
	
	
/* The results can be seen in TestSuite (Host side s/w) */
}

/* ISO IN/OUT test **************************************************/
void
test_case3_handler(void)
{
iso_test_buffer * tx_data;
iso_test_buffer * rx_data;
iso_test_buffer * tmp;
uint8 i;
uint8 cnt = 0;

uint8 swtch = 1;

	buffers = (iso_test_buffer*) databuf;

	/* Initialize buffer */
	buffer_init(buffers);

	/* tx_data and rx_data point to 2 buffers. Each of buffers contains 5 packets of data */
	tx_data = (iso_test_buffer*) databuf;
	rx_data = (iso_test_buffer*)((uint8*)tx_data + sizeof(iso_test_buffer)*2);

	for (i=0; i<2; i++)
	{
		/* Init buffer headers */
		init_buffer_headers(&rx_data[i]);
		init_buffer_headers(&tx_data[i]);

		/* Start IN and OUT data stream. Enqueue I/O requests */
		write(usb_ep1_file, (uint8*)(&tx_data[i]), 5);
		read(usb_ep2_file, (uint8*)(&rx_data[i]), 5);
	}
	/* We have 4 requests in queue now (2 read and 2 write) */
	while (cnt<3)
	{
		/* Wait until there is only 1 request left in each queue */
		ioctl(usb_ep1_file, USB_EP_WAIT, 1);
		ioctl(usb_ep2_file, USB_EP_WAIT, 1);
		
		if (swtch)
		{
			/* Change buffers */
			tmp = rx_data;
			rx_data = tx_data;
			tx_data = tmp;
			swtch = 0;
		}
		else
			swtch = 1;

		/* Reinit buffer headers */
		init_buffer_headers(&rx_data[swtch]);
		init_buffer_headers(&tx_data[swtch]);

		/* Add requests (send/receive next buffers) */
		write(usb_ep1_file, (uint8*)(&tx_data[swtch]), 5);
		read(usb_ep2_file, (uint8*)(&rx_data[swtch]), 5);

		cnt++;
	}

	/* Wait while last transfers are in progress */
	ioctl(usb_ep1_file, USB_EP_WAIT, 0);
	ioctl(usb_ep2_file, USB_EP_WAIT, 0);
	
	
/* The results can be seen in TestSuite (Host side s/w) */
}

/* ISO main task **************************************************/
void
main_task(void)
{
audio_buffer * rx_data;
audio_buffer * tx_data;
audio_buffer * tmp;
uint8 swtch = 1;
uint8 i, n;

	/* Initialize buffer with zeros */
	clear_buffer();
	
	/* tx_data and rx_data point to 2 buffers. Each of buffers contains 20 packets of data */
	rx_data = (audio_buffer *) databuf;
	tx_data = (audio_buffer*)((uint8*)rx_data + sizeof(audio_buffer)*2);
	
	for (i=0; i<2; i++)
	{
		/* Init buffer headers */
		init_audio_headers(&rx_data[i]);
		init_audio_headers(&tx_data[i]);

		/* Start IN and OUT data stream. Enqueue I/O requests */
		write(usb_ep1_file, (uint8*)(&tx_data[i]), 20);
		read(usb_ep2_file, (uint8*)(&rx_data[i]), 20);
	}
	
	/* USB_AUDIO_STOP command stops the loopback */
	while (!stop_main_task)
	{
		/* Wait until there is only 1 request left in a queue */
		ioctl(usb_ep2_file, USB_EP_WAIT, 1);
		ioctl(usb_ep1_file, USB_EP_WAIT, 1);
		
		if (swtch)
		{
			/* Change buffers */
			tmp = rx_data;
			rx_data = tx_data;
			tx_data = tmp;
			swtch = 0;
		}
		else
			swtch = 1;

		/* Apply volume value */
		process_data(&tx_data[swtch]);
		
		/* Reinit buffer headers */
		init_audio_headers(&rx_data[swtch]);
		init_audio_headers(&tx_data[swtch]);

		/* Add requests (send/receive next buffers) */
		read(usb_ep2_file, (uint8*)(&rx_data[swtch]), 20);
		write(usb_ep1_file, (uint8*)(&tx_data[swtch]), 20);
	}
	
	stop_main_task = FALSE;

	/* Wait while last transfers are in progress */
	ioctl(usb_ep1_file, USB_EP_WAIT, 0);
	ioctl(usb_ep2_file, USB_EP_WAIT, 0);
}

/*****************************************************************/
void
process_data (audio_buffer * buffer)
{
uint32 i,j;
uint16 k;
long int l;

    if (packet_size == 90) j = 1800;
    else j = 800;
    
    for (i=0; i<j; i+=2)
    {
	/* PCM samples in 16 bit mono are coded in following way:
	     ____________________
	    |___ LSB___|___ MSB___|,

	    so these bytes must be swapped before being multiplied. */
	k = *(uint16*)(&buffer->databuf[i]);
	k = (k << 8) | (k >> 8);
	/* 16 bit samples are signed values - minimum amplitude is (-32768), 0 - zero amplitude,
	    and 32767 - maximum amplitude value. So, multiplication must be signed.
	    ("volume" value can not be grater than 0x7FFF in this demo program)*/
	l = (short int)k*(short int)volume;
	k = ((uint32)l >> 16);
	/* Swap bytes */
	k = (k << 8) | (k >> 8);
	*(uint16*)(&buffer->databuf[i]) = k;
    }
}
/*****************************************************************/
